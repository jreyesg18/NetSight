"""
modules/port_scan.py — Escaneo de puertos configurable.

Responsabilidad única: dado un host (dominio o IP), escanear un rango de
puertos TCP en paralelo (usando un pool de hilos) y reportar cuáles
están abiertos, junto con el servicio comúnmente asociado a cada uno
(well-known ports).

================================================================
 AVISO IMPORTANTE — USO RESPONSABLE Y LEGAL
================================================================
Escanear puertos de un host sin autorización puede ser ilegal en
muchas jurisdicciones (p. ej. bajo leyes como la Computer Fraud and
Abuse Act en EE. UU. o equivalentes locales) e incluso cuando no lo
sea, puede interpretarse como actividad hostil por el operador de la
red objetivo (firewalls, IDS/IPS, proveedores de hosting). Esta
función debe usarse ÚNICAMENTE contra:
    - dominios/IPs de tu propiedad, o
    - objetivos para los que tengas autorización explícita y por
      escrito para realizar pruebas de seguridad.
NetSight no implementa ni pretende implementar control de acceso o
verificación de autorización: es responsabilidad de quien use esta
función (y de la UI que la invoque) asegurarse de tener permiso antes
de escanear cualquier host que no sea propio.
================================================================

Input esperado:
    host (str): dominio o IP ya validado (ver utils/validators.py).
    port_start (int): primer puerto del rango a escanear (1-65535).
    port_end (int): último puerto del rango a escanear (1-65535).
    max_threads (int): número máximo de hilos concurrentes (default 100).
    timeout (float): timeout de conexión por puerto en segundos (default 1.0).
    max_ports_per_scan (int): límite duro de puertos por escaneo (default
        5000) para evitar escaneos abusivos o accidentalmente enormes.
        Si el rango solicitado excede este límite, se trunca
        automáticamente y se informa en "warnings".

Función principal:
    scan_ports(host, port_start=1, port_end=1024, max_threads=100,
               timeout=1.0, max_ports_per_scan=5000) -> dict

Output devuelto (dict estandarizado):
    {
        "host": str,
        "port_start": int,
        "port_end": int,             # rango efectivamente escaneado
        "requested_port_end": int,   # rango originalmente pedido (por si se truncó)
        "success": bool,
        "open_ports": [{"port": int, "service": str}, ...],
        "scanned_count": int,
        "duration_seconds": float,
        "max_threads": int,
        "timeout": float,
        "truncated": bool,
        "warnings": [str, ...],
        "errors": [str, ...],
    }

Librerías usadas: socket, concurrent.futures (stdlib). No depende de
otros módulos de modules/.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT_START = 1
DEFAULT_PORT_END = 1024
# Subido de 100 a 300 y el timeout bajado de 1.0s a 0.5s para que un
# escaneo del rango completo (hasta MAX_PORTS_PER_SCAN puertos) tome
# unos segundos en vez de ~50s, sin sacrificar de forma relevante la
# tasa de falsos negativos: 0.5s sigue siendo generoso para un solo
# round-trip de conexión TCP (el RTT típico entre continentes ronda
# 80-250ms). Ambos valores siguen siendo configurables por llamada.
DEFAULT_MAX_THREADS = 300
DEFAULT_TIMEOUT = 0.5
DEFAULT_MAX_PORTS_PER_SCAN = 5000

MIN_PORT = 1
MAX_PORT = 65535

# Mapeo de puertos comunes a su servicio típico, solo para mostrarlo en
# la UI (es una heurística por convención, no una detección real del
# servicio que corre en ese puerto — eso requeriría banner grabbing,
# fuera del alcance de este módulo).
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS (Name Service)",
    138: "NetBIOS (Datagram)",
    139: "NetBIOS (SMB sobre NetBIOS)",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (submission)",
    636: "LDAPS",
    989: "FTPS (datos)",
    990: "FTPS (control)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2181: "ZooKeeper",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3000: "Servidor de desarrollo (Node/Grafana, común)",
    3306: "MySQL / MariaDB",
    3389: "RDP (Escritorio remoto)",
    5000: "Servidor de desarrollo (Flask/UPnP, común)",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    7001: "WebLogic",
    8000: "HTTP alterno / desarrollo",
    8080: "HTTP Proxy / alterno",
    8443: "HTTPS alterno",
    8888: "HTTP alterno",
    9000: "PHP-FPM / SonarQube (común)",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch (transporte)",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB (shard)",
    50000: "SAP",
}


def _service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Desconocido / no estándar")


def _is_port_open(host: str, port: int, timeout: float) -> bool:
    """Intenta un connect() TCP de 3 vías. True si el puerto acepta
    conexiones dentro del timeout; False si se rechaza, filtra o hace
    timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _empty_result(
    host: str, port_start: int, port_end: int, max_threads: int, timeout: float
) -> dict:
    return {
        "host": host,
        "port_start": port_start,
        "port_end": port_end,
        "requested_port_end": port_end,
        "success": False,
        "open_ports": [],
        "scanned_count": 0,
        "duration_seconds": 0.0,
        "max_threads": max_threads,
        "timeout": timeout,
        "truncated": False,
        "warnings": [],
        "errors": [],
    }


def scan_ports(
    host: str,
    port_start: int = DEFAULT_PORT_START,
    port_end: int = DEFAULT_PORT_END,
    max_threads: int = DEFAULT_MAX_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    max_ports_per_scan: int = DEFAULT_MAX_PORTS_PER_SCAN,
) -> dict:
    """
    Escanea el rango [port_start, port_end] de `host` en paralelo con un
    ThreadPoolExecutor. Recuerda: usar solo sobre hosts propios o con
    autorización explícita (ver aviso en el encabezado del módulo).

    Nunca lanza excepciones: cualquier fallo (host inválido, rango de
    puertos inválido, host que no resuelve) queda registrado en
    result["errors"] y la función siempre devuelve el diccionario
    estandarizado. Los rangos que exceden `max_ports_per_scan` se
    truncan automáticamente (no se rechazan) y se informa en
    result["warnings"].
    """
    start_time = time.monotonic()
    result = _empty_result(host, port_start, port_end, max_threads, timeout)

    if not host or not isinstance(host, str):
        result["errors"].append("Host inválido o vacío recibido por port_scan.")
        return result

    try:
        port_start = int(port_start)
        port_end = int(port_end)
    except (TypeError, ValueError):
        result["errors"].append("port_start y port_end deben ser números enteros.")
        return result

    if not (MIN_PORT <= port_start <= MAX_PORT) or not (MIN_PORT <= port_end <= MAX_PORT):
        result["errors"].append(
            f"Los puertos deben estar entre {MIN_PORT} y {MAX_PORT} "
            f"(se recibió port_start={port_start}, port_end={port_end})."
        )
        return result

    if port_start > port_end:
        result["errors"].append(
            f"port_start ({port_start}) no puede ser mayor que port_end ({port_end})."
        )
        return result

    try:
        max_threads = max(1, int(max_threads))
        timeout = float(timeout)
        max_ports_per_scan = max(1, int(max_ports_per_scan))
    except (TypeError, ValueError):
        result["errors"].append("max_threads/timeout/max_ports_per_scan tienen un tipo inválido.")
        return result

    result["max_threads"] = max_threads
    result["timeout"] = timeout

    # --- Límite de seguridad: truncar rangos demasiado grandes ---
    requested_end = port_end
    total_requested = port_end - port_start + 1
    truncated = False
    if total_requested > max_ports_per_scan:
        port_end = port_start + max_ports_per_scan - 1
        truncated = True
        result["warnings"].append(
            f"Se solicitaron {total_requested} puertos ({port_start}-{requested_end}), "
            f"lo cual excede el límite de seguridad de {max_ports_per_scan} puertos por "
            f"escaneo. El rango se truncó a {port_start}-{port_end}. Si necesitas escanear "
            f"más puertos, hazlo en varias llamadas o ajusta max_ports_per_scan de forma "
            f"consciente."
        )

    # Verificar que el host resuelva antes de lanzar cientos de threads
    # que fallarían todos por la misma razón.
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        result["errors"].append(f"No se pudo resolver '{host}': {exc}")
        return result
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"Error inesperado al resolver '{host}': {exc}")
        return result

    ports_to_scan = list(range(port_start, port_end + 1))
    open_ports: list[int] = []
    effective_threads = max(1, min(max_threads, len(ports_to_scan)))

    try:
        with ThreadPoolExecutor(max_workers=effective_threads) as executor:
            future_to_port = {
                executor.submit(_is_port_open, host, port, timeout): port
                for port in ports_to_scan
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as exc:  # noqa: BLE001 - un puerto individual no debe tumbar el escaneo completo
                    result["warnings"].append(
                        f"Error inesperado escaneando el puerto {port}: {exc}"
                    )
    except Exception as exc:  # noqa: BLE001 - protección extra ante fallos del propio executor
        result["errors"].append(f"Error inesperado durante el escaneo de puertos: {exc}")
        return result

    open_ports.sort()

    result.update(
        {
            "success": True,
            "port_end": port_end,
            "requested_port_end": requested_end,
            "truncated": truncated,
            "open_ports": [{"port": p, "service": _service_name(p)} for p in open_ports],
            "scanned_count": len(ports_to_scan),
            "duration_seconds": round(time.monotonic() - start_time, 2),
        }
    )
    return result


if __name__ == "__main__":
    import json
    import sys

    host_arg = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    start_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_arg = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    output = scan_ports(host_arg, start_arg, end_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
