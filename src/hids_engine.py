#!/usr/bin/env python3
import os
import sys
import json
import yaml
import signal
import socket
import struct
import hashlib
import datetime
import sqlite3
import ctypes as ct
import yara
from bcc import BPF

# ==============================================================================
# 1. CARGA DE CONFIGURACIÓN Y REGLAS YARA
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")

try:
    with open(CONFIG_PATH, "r") as f:
        CONFIG = yaml.safe_load(f)
except Exception as e:
    sys.exit(f"[-] Error al cargar {CONFIG_PATH}: {e}")

# Compilación YARA
YARA_PATH = os.path.join(BASE_DIR, CONFIG["threat_intel"]["yara_rules_path"])
try:
    YARA_RULES = yara.compile(filepath=YARA_PATH)
except Exception as e:
    sys.exit(f"[-] Error al compilar reglas YARA en {YARA_PATH}: {e}")

LOG_FILE_PATH = os.path.join(BASE_DIR, CONFIG["agent"]["log_file"])
SQLITE_PATH = os.path.join(BASE_DIR, CONFIG["threat_intel"]["sqlite_db_path"])

# ==============================================================================
# 2. GESTIÓN DE THREAT INTEL EN MEMORIA (O(1) Y RECARGA EN CALIENTE)
# ==============================================================================
# Diccionario en RAM: { "sha256": "threat_type" }
MALWARE_CACHE = {}

# Set en RAM para deduplicación: almacena paths ya alertados por YARA para evitar bucles
SCANNED_YARA_FILES = set()

def reload_threat_intel(signum=None, frame=None):
    """Recarga las firmas desde SQLite a la memoria RAM de forma atómica."""
    global MALWARE_CACHE, SCANNED_YARA_FILES
    if not os.path.exists(SQLITE_PATH):
        print(f"[!] Base de datos no encontrada en {SQLITE_PATH}. Cache vacía.", flush=True)
        return

    try:
        # Conexión local y efímera en modo lectura con timeout para evitar locks
        conn = sqlite3.connect(f"file:{SQLITE_PATH}?mode=ro", uri=True, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("SELECT sha256_hash, threat_type FROM malware_hashes;")
        
        # Construcción atómica en RAM
        new_cache = {row[0].lower(): (row[1] or "MalwareBazaar-Recent") for row in cursor.fetchall()}
        conn.close()

        MALWARE_CACHE = new_cache
        SCANNED_YARA_FILES.clear()
        print(f"[*] [HOT-RELOAD] Threat Intel actualizado: {len(MALWARE_CACHE)} hashes cargados en memoria.", flush=True)
    except Exception as e:
        print(f"[-] Error al recargar Threat Intel: {e}", file=sys.stderr, flush=True)

# Registro de la señal SIGHUP para recarga sin reiniciar el servicio
signal.signal(signal.SIGHUP, reload_threat_intel)

# ==============================================================================
# 3. SONDAS eBPF EN C
# ==============================================================================
ebpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/socket.h>

enum event_type {
    EVENT_PROCESS = 1,
    EVENT_NET_CONNECT = 2,
    EVENT_FILE_OPEN = 3
};

struct hids_event_t {
    u32 type;
    u32 pid;
    u32 uid;
    char comm[16];
    char target_path[256];
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(hids_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct hids_event_t event = {};
    event.type = EVENT_PROCESS;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.target_path, sizeof(event.target_path), args->filename);
    hids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr_in addr = {};
    struct hids_event_t event = {};
    bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);
    if (addr.sin_family != AF_INET) return 0;

    event.type = EVENT_NET_CONNECT;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.daddr = addr.sin_addr.s_addr;
    event.dport = addr.sin_port;
    hids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct hids_event_t event = {};
    event.type = EVENT_FILE_OPEN;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.target_path, sizeof(event.target_path), args->filename);
    hids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class HidsRawEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("target_path", ct.c_char * 256),
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16)
    ]

# ==============================================================================
# 4. MOTOR DE EVALUACIÓN
# ==============================================================================
def get_file_sha256(filepath):
    sha = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest().lower()
    except Exception:
        return None

def evaluate_mitre_rules(event_dict):
    alerts = []
    suspicious_dirs = tuple(CONFIG["monitored_paths"]["suspicious_directories"])
    critical_files = tuple(CONFIG["monitored_paths"]["critical_system_files"])
    
    # 1. Eventos de Archivo
    if event_dict["event_type"] == "FILE_ACCESS":
        path = event_dict.get("path", "")
        
        # A. Archivos críticos del sistema
        if any(path.startswith(cf) for cf in critical_files):
            trusted_auth_procs = tuple(CONFIG.get("monitored_paths", {}).get("auth_trusted_binaries", []))
            proc_name = event_dict.get("process_name", "")

            # Excluir binarios legítimos de autenticación y servicios del sistema
            if proc_name in trusted_auth_procs:
                return alerts

            alerts.append({
                "rule_id": "SEC-FILE-001",
                "severity": "CRITICAL",
                "description": f"Acceso anómalo a archivo crítico del sistema por '{proc_name}': {path}",
                "mitre_attack": {
                    "tactic": "Credential Access",
                    "technique_id": "T1003.008",
                    "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow"
                }
            })

        # B. Detección en directorios sospechosos (/tmp, /dev/shm, etc.)
        elif path.startswith(suspicious_dirs) and os.path.isfile(path):
            file_hash = get_file_sha256(path)
            
            # Verificación instantánea en memoria O(1)
            threat_match = MALWARE_CACHE.get(file_hash) if file_hash else None
            if threat_match:
                alerts.append({
                    "rule_id": "SEC-SIG-MALWAREBAZAAR",
                    "severity": "CRITICAL",
                    "description": f"Hash malicioso detectado en base de datos local: {threat_match}",
                    "hash": file_hash,
                    "mitre_attack": {
                        "tactic": "Execution",
                        "technique_id": "T1204.002",
                        "technique_name": "User Execution: Malicious File"
                    }
                })

            # Consulta al Motor YARA con deduplicación por archivo
            if path not in SCANNED_YARA_FILES:
                try:
                    matches = YARA_RULES.match(path)
                    if matches:
                        SCANNED_YARA_FILES.add(path)
                        for match in matches:
                            alerts.append({
                                "rule_id": f"SEC-YARA-{match.rule}",
                                "severity": match.meta.get("severity", "HIGH"),
                                "description": match.meta.get("description", "Patrón YARA sospechoso detectado"),
                                "mitre_attack": {
                                    "tactic": match.meta.get("mitre_tactic", "Defense Evasion"),
                                    "technique_id": match.meta.get("mitre_technique", "T1027"),
                                    "technique_name": "Obfuscated Files or Information"
                                }
                            })
                except Exception:
                    pass

    # 2. Eventos de Red
    elif event_dict["event_type"] == "NETWORK_CONNECT":
        proc = event_dict["process_name"]
        port = event_dict["dest_port"]
        allowed_ports = CONFIG["network"]["standard_outbound_ports"]
        suspicious_procs = CONFIG["network"]["suspicious_interpreters"]

        if proc in suspicious_procs and port not in allowed_ports:
            alerts.append({
                "rule_id": "SEC-NET-001",
                "severity": "CRITICAL",
                "description": f"Proceso intérprete '{proc}' inició conexión hacia puerto no estándar {port}",
                "mitre_attack": {
                    "tactic": "Command and Control",
                    "technique_id": "T1059.004",
                    "technique_name": "Command and Scripting Interpreter: Unix Shell"
                }
            })

    # 3. Eventos de Procesos
    elif event_dict["event_type"] == "PROCESS_EXEC":
        if event_dict["uid"] == 0 and event_dict["process_name"] != "cron":
            exec_path = event_dict.get("executable", "")
            if any(s in exec_path for s in ["chmod", "chown", "useradd", "usermod"]):
                alerts.append({
                    "rule_id": "SEC-PROC-001",
                    "severity": "MEDIUM",
                    "description": f"Comando administrativo ejecutado como root: {exec_path}",
                    "mitre_attack": {
                        "tactic": "Privilege Escalation",
                        "technique_id": "T1078.003",
                        "technique_name": "Valid Accounts: Local Accounts"
                    }
                })

    return alerts

# ==============================================================================
# 5. MANEJADOR Y REGISTRO DE EVENTOS (Optimizado sin ruido)
# ==============================================================================
def handle_event(cpu, data, size):
    raw = ct.cast(data, ct.POINTER(HidsRawEvent)).contents
    proc_name = raw.comm.decode('utf-8', errors='replace').strip()

    # 1. Whitelist de procesos del agente y telemetría
    if "promtail" in proc_name.lower() or "ebpf-hids" in proc_name.lower():
        return

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    event_payload = {
        "timestamp": now,
        "agent": CONFIG["agent"]["name"],
        "host_pid": raw.pid,
        "uid": raw.uid,
        "process_name": proc_name
    }

    if raw.type == 1:
        event_payload["event_type"] = "PROCESS_EXEC"
        event_payload["executable"] = raw.target_path.decode('utf-8', errors='replace')
    elif raw.type == 2:
        event_payload["event_type"] = "NETWORK_CONNECT"
        event_payload["dest_ip"] = socket.inet_ntoa(struct.pack("<I", raw.daddr))
        event_payload["dest_port"] = socket.ntohs(raw.dport)
    elif raw.type == 3:
        target = raw.target_path.decode('utf-8', errors='replace')

        # Ignorar archivos de control de posición de Promtail y temporales de edición
        if "promtail" in target or target.endswith(".swp"):
            return

        suspicious_dirs = tuple(CONFIG["monitored_paths"]["suspicious_directories"])
        critical_files = tuple(CONFIG["monitored_paths"]["critical_system_files"])
        if not (target.startswith(suspicious_dirs) or any(target.startswith(cf) for cf in critical_files)):
            return

        event_payload["event_type"] = "FILE_ACCESS"
        event_payload["path"] = target

    # Evaluar reglas MITRE / YARA / Threat Intel
    alerts = evaluate_mitre_rules(event_payload)
    if alerts:
        event_payload["status"] = "THREAT_DETECTED"
        event_payload["alerts"] = alerts
    else:
        # Si no hay amenaza, se descarta el evento para no saturar el log ni Loki
        return

    json_record = json.dumps(event_payload, ensure_ascii=False)

    try:
        with open(LOG_FILE_PATH, "a") as log_file:
            log_file.write(json_record + "\n")
    except Exception as e:
        print(f"[-] Error escribiendo log: {e}", file=sys.stderr)

    if CONFIG["agent"].get("log_to_stdout", False):
        print(json_record, flush=True)

# ==============================================================================
# 6. INICIALIZACIÓN
# ==============================================================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[-] Se requieren privilegios de root para ejecutar el agente.")

    # Carga inicial de firmas en memoria
    reload_threat_intel()

    print(f"[*] Iniciando {CONFIG['agent']['name']} v{CONFIG['agent']['version']}...", flush=True)
    bpf_module = BPF(text=ebpf_source, cflags=["-Wno-duplicate-decl-specifier"])
    bpf_module["hids_events"].open_perf_buffer(handle_event)

    print(f"[*] Base de datos Threat Intel cargada desde: {SQLITE_PATH}")
    print(f"[*] Reglas YARA compiladas desde: {YARA_PATH}")
    print(f"[*] Registro persistente en: {LOG_FILE_PATH}")
    print("[*] Sondas eBPF listas en el Kernel. Esperando actividad...\n", flush=True)

    while True:
        try:
            bpf_module.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[*] Agente cerrado correctamente.")
            break
