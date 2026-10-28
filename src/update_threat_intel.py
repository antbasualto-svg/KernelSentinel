#!/usr/bin/env python3
import os
import sys
import sqlite3
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "threat_intel.db")
FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

def get_db_connection():
    # Asegurar que el directorio data exista
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    cursor = conn.cursor()
    
    # Habilitar WAL para soportar lecturas y escrituras simultaneas
    cursor.execute("PRAGMA journal_mode=WAL;")
    
    # Crear tabla solo si no existe (no borrar registros existentes)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256_hash TEXT PRIMARY KEY,
            threat_type TEXT DEFAULT 'MalwareBazaar-Recent'
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256_hash);")
    conn.commit()
    return conn

def download_and_populate():
    print(f"[*] Descargando feed de MalwareBazaar desde: {FEED_URL} ...")
    req = urllib.request.Request(FEED_URL, headers={'User-Agent': 'eBPF-HIDS-ThreatIntel-Fetcher/1.0'})
    
    # Descargar en memoria primero; si falla la red, no afectamos la base de datos
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Error descargando feed: {e}", file=sys.stderr)
        sys.exit(1)

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Obtener conteo inicial
    cursor.execute("SELECT COUNT(*) FROM malware_hashes;")
    count_before = cursor.fetchone()[0]

    batch = []
    print("[*] Procesando registros y actualizando base de datos...")
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        sha256 = line.lower()
        if len(sha256) == 64:
            batch.append((sha256, "MalwareBazaar-Recent-Sample"))
            
            if len(batch) >= 5000:
                cursor.executemany("INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", batch)
                batch.clear()

    if batch:
        cursor.executemany("INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", batch)

    # Hash de prueba EICAR estandar
    cursor.execute(
        "INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", 
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-Test-File")
    )

    conn.commit()
    
    # Conteo final para ver incrementos reales
    cursor.execute("SELECT COUNT(*) FROM malware_hashes;")
    count_after = cursor.fetchone()[0]
    conn.close()

    nuevos = count_after - count_before
    print(f"[✓] Actualizacion finalizada: {nuevos} firmas nuevas incorporadas (Total acumulado: {count_after} firmas).")

if __name__ == "__main__":
    download_and_populate()
