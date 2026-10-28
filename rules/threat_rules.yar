rule Webshell_PHP_Inyection {
    meta:
        description = "Detecta inyeccion de Webshell y ejecucion de comandos remotos en PHP"
        mitre_technique = "T1505.003"
        mitre_tactic = "Persistence"
        severity = "CRITICAL"
    strings:
        $s1="system(_GET" nocase
        $s2 = "eval(base64_decode" nocase
        $s3 = "passthru(" nocase
        $s4 = "shell_exec(" nocase
        $s5="assert(_POST" nocase
    condition:
        any of ($s*)
}

rule Crypto_Miner_Payload {
    meta:
        description = "Detecta cadenas y configuraciones asociadas a mineros de criptomonedas"
        mitre_technique = "T1496"
        mitre_tactic = "Impact"
        severity = "HIGH"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "stratum+ssl://" nocase
        $m3 = "xmrig" nocase
        $m4 = "donate-level=" nocase
    condition:
        any of ($m*)
}

rule Reverse_Shell_Payload {
    meta:
        description = "Detecta scripts con comandos tipicos de reverse shell interactiva"
        mitre_technique = "T1059.004"
        mitre_tactic = "Command and Control"
        severity = "HIGH"
    strings:
        $s1 = "/dev/tcp/" nocase
        $s2 = "nc -e /bin/sh" nocase
        $s3 = "nc -e /bin/bash" nocase
        $s4 = "pty.spawn(\"/bin/bash\")" nocase
        $s5 = "socket.socket(socket.AF_INET" nocase
    condition:
        any of ($s*)
}

rule Linux_Privilege_Escalation_Artifacts {
    meta:
        description = "Detecta cadenas asociadas a scripts automatizados de escalamiento de privilegios"
        mitre_technique = "T1082"
        mitre_tactic = "Privilege Escalation"
        severity = "HIGH"
    strings:
        $p1 = "linpeas.sh" nocase
        $p2 = "PEASS-ng" nocase
        $p3 = "find / -perm -4000 2>/dev/null" nocase
    condition:
        any of ($p*)
}

rule Suspicious_Downloader_Dropper {
    meta:
        description = "Detecta scripts que descargan y ejecutan binarios de forma desatendida"
        mitre_technique = "T1105"
        mitre_tactic = "Ingress Tool Transfer"
        severity = "MEDIUM"
    strings:
        $d1 = "curl -fsSL" nocase
        $d2 = "| bash" nocase
        $d3 = "| sh" nocase
        $d4 = "wget -qO-" nocase
    condition:
        ($d1 or $d4)and($d2 or $d3)
}

rule Linux_Ransomware_Behavior_Artifacts {
    meta:
        description = "Detecta extensiones, notas de rescate y artefactos caracteristicos de ransomware"
        mitre_technique = "T1486"
        mitre_tactic = "Impact"
        severity = "CRITICAL"
    strings:
        $note1 = "your files are encrypted" nocase
        $note2 = "restore-instructions" nocase
        $note3 = "readme_for_decrypt" nocase
        $note4 = ".onion" nocase
        $crypto1 = "openssl enc -aes-256-cbc" nocase
    condition:
        any of ($note*) or ($crypto1)
}

rule Linux_LD_Preload_Userland_Rootkit {
    meta:
        description = "Detecta inyeccion de librerias compartidas y secuestro de llamadas dinamicas"
        mitre_technique = "T1574.006"
        mitre_tactic = "Defense Evasion"
        severity = "HIGH"
    strings:
        $preload1 = "/etc/ld.so.preload" nocase
        $preload2 = "LD_PRELOAD" nocase
        $hook1 = "dlsym(RTLD_NEXT" nocase
        $hook2 = "sys_openat" nocase
        $hook3 = "readdir" nocase
    condition:
        any of ($preload*) and any of($hook*)
}

rule Linux_Credential_Harvester_Script {
    meta:
        description = "Detecta scripts de recoleccion masiva de credenciales y secretos (claves SSH)"
        mitre_technique = "T1552.001"
        mitre_tactic = "Credential Access"
        severity = "HIGH"
    strings:
        $ssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
    condition:
        any of ($ssh, $rsa)
}


