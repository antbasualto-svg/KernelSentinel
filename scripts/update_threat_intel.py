#!/usr/bin/env python3
import os
import sys
import io
import zipfile
import sqlite3
import urllib.request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "threat_intel.db")
FEED_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

def setup_database():
    print(f"[*] Creando base de datos en: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Crear tabla y eliminar datos antiguos si existen
    cursor.execute("DROP TABLE IF EXISTS malware_hashes;")
    cursor.execute("""
        CREATE TABLE malware_hashes (
            sha256_hash TEXT PRIMARY KEY,
            threat_type TEXT DEFAULT 'MalwareBazaar-Recent'
        );
    """)
    # Indice B-Tree explícito para maximizar velocidad de búsqueda
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256_hash);")
    conn.commit()
    return conn

def download_and_populate(conn):
    print(f"[*] Descargando feed de MalwareBazaar desde: {FEED_URL} ...")
    req = urllib.request.Request(FEED_URL, headers={'User-Agent': 'eBPF-HIDS-ThreatIntel-Fetcher/1.0'})
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        sys.exit(f"[-] Error descargando feed: {e}")

    cursor = conn.cursor()
    inserted_count = 0
    batch = []

    print("[*] Procesando registros y construyendo índices...")
    for line in content.splitlines():
        line = line.strip()
        # Ignorar comentarios y líneas vacías del feed
        if not line or line.startswith("#"):
            continue
        
        # El feed entrega líneas con el hash SHA-256
        sha256 = line.lower()
        if len(sha256) == 64:
            batch.append((sha256, "MalwareBazaar-Recent-Sample"))
            inserted_count += 1
            
            if len(batch) >= 5000:
                cursor.executemany("INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", batch)
                batch.clear()

    if batch:
        cursor.executemany("INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", batch)

    # Insertar siempre el hash de prueba EICAR estándar
    cursor.execute(
        "INSERT OR IGNORE INTO malware_hashes VALUES (?, ?);", 
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-Test-File")
    )

    conn.commit()
    conn.close()
    print(f"[✓] Base de datos completada: {inserted_count + 1} firmas indexadas en '{DB_PATH}'.")

if __name__ == "__main__":
    db_conn = setup_database()
    download_and_populate(db_conn)
