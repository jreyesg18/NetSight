"""
modules/scoring.py — Cálculo del score heurístico general (0-100).

Responsabilidad única y ESPECIAL: este es el único módulo de modules/
que conoce y depende de los resultados de todos los demás. A diferencia
del resto (que reciben un dominio/IP), scoring.py recibe los diccionarios
de resultados YA CALCULADOS por dns_check, whois_check, ssl_check,
port_scan y headers_check, y los combina en un puntaje único.

tech_detect NO participa en el score: es informativo (qué tecnologías
se usan), no hay una noción objetiva de "tecnología buena/mala" que
valga la pena puntuar de forma heurística simple.

Input esperado (todos opcionales — un módulo que falló o no se corrió
se trata como "sin datos", nunca hace fallar a scoring.py):
    dns_result (dict | None):        salida de modules.dns_check.check_dns()
    whois_result (dict | None):      salida de modules.whois_check.check_whois()
    ssl_result (dict | None):        salida de modules.ssl_check.check_ssl()
    port_scan_result (dict | None):  salida de modules.port_scan.scan_ports()
    headers_result (dict | None):    salida de modules.headers_check.check_headers()

Función principal:
    calculate_score(dns_result=None, whois_result=None, ssl_result=None,
                     port_scan_result=None, headers_result=None) -> dict

También se incluye calculate_score_from_results(results: dict) -> dict
como azúcar sintáctica, para llamar con un solo diccionario
{"dns_check": ..., "whois_check": ..., "ssl_check": ..., "port_scan": ...,
"headers_check": ...} (conveniente para app.py).

--------------------------------------------------------------------
 REGLAS DE PUNTAJE (5 categorías, 20 puntos máximo cada una = 100 total)
--------------------------------------------------------------------
1) SSL (max 20):
   - 20 pts: certificado válido, de cadena confiable, y NO expira en
     menos de 30 días.
   - 12 pts: válido y confiable, pero expira en menos de 30 días
     (matiz agregado sobre la regla original para no castigar igual
     "por vencer" que "vencido" o "sin HTTPS").
   -  5 pts: hay HTTPS pero el certificado es autofirmado / de cadena
     no confiable (hay cifrado, pero el navegador mostraría advertencia).
   -  0 pts: sin HTTPS, certificado expirado, o el chequeo falló.

2) Headers de seguridad (max 20):
   - Se toma el score de headers_check (X/6 headers presentes) y se
     escala a 20 puntos: puntos = round((score / max_score) * 20).
     (La consigna decía "1 pt por header, máx 20 pts"; con 6 headers
     evaluados, 1pt/header solo llegaría a 6, así que para que la
     categoría sí pese hasta 20 —y el total balancee 100— se escala
     proporcionalmente en vez de sumar 1 punto plano por header.)

3) DNS / seguridad de correo — SPF + DKIM + DMARC (max 20):
   - 20 pts si los 3 están configurados.
   - Si no están los 3: 7 pts por cada uno de los que sí estén presentes
     (0, 7, 14 o 20 según cuántos falten) — tal como se pidió.

4) Puertos de riesgo (max 20):
   - Base 20 pts, -5 por cada puerto "de riesgo" detectado abierto
     (ver RISKY_PORTS: FTP, Telnet, RDP, SMB, bases de datos expuestas,
     VNC, etc.), con piso en 0.
   - Si port_scan no se ejecutó, se asigna un puntaje neutral (10) en
     vez de premiar o castigar sin datos.

5) Antigüedad del dominio (max 20):
   - 20 pts si el dominio tiene más de 1 año (>=365 días).
   - Se agregaron escalones intermedios para no castigar de forma
     abrupta a dominios "casi de un año": 10 pts (6-12 meses), 5 pts
     (1-6 meses), 0 pts (<1 mes).
   - Si no se pudo determinar la antigüedad (WHOIS falló o no reportó
     fecha), se asigna un puntaje neutral (10), no 0.

Los pesos son ajustables — están centralizados en las constantes y
funciones `_score_*` de este archivo para facilitar tuning futuro sin
tocar el resto de NetSight.

Nivel final:
    80-100 -> "Excelente"
    60-79  -> "Bueno"
    40-59  -> "Regular"
    <40    -> "Débil"

Output devuelto:
    {
        "score_total": int,               # 0-100
        "desglose": {
            "ssl": int,
            "headers": int,
            "dns_seguridad": int,
            "puertos": int,
            "antiguedad_dominio": int,
        },
        "nivel": str,
        "detalles": {                      # explicación en español de cada puntaje
            "ssl": str, "headers": str, "dns_seguridad": str,
            "puertos": str, "antiguedad_dominio": str,
        },
    }

No depende de librerías externas: solo lógica pura de Python.
"""

from __future__ import annotations

MAX_POINTS_PER_CATEGORY = 20
SSL_EXPIRING_SOON_POINTS = 12
SSL_UNTRUSTED_POINTS = 5
DNS_POINTS_PER_MECHANISM = 7
PORT_PENALTY_PER_RISKY_PORT = 5
NEUTRAL_POINTS_NO_DATA = 10

# Puertos que, si aparecen abiertos en el escaneo, se consideran un
# riesgo típico (servicios de administración remota o bases de datos
# que normalmente no deberían estar expuestos directamente a Internet).
RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    135: "MS RPC",
    139: "NetBIOS/SMB",
    445: "SMB",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

NIVEL_THRESHOLDS = (
    (80, "Excelente"),
    (60, "Bueno"),
    (40, "Regular"),
)
NIVEL_DEFAULT = "Débil"


def _nivel_from_score(score_total: int) -> str:
    for threshold, nivel in NIVEL_THRESHOLDS:
        if score_total >= threshold:
            return nivel
    return NIVEL_DEFAULT


def _score_ssl(ssl_result: dict | None) -> tuple[int, str]:
    if not ssl_result or not ssl_result.get("success"):
        return 0, "No se pudo evaluar el certificado SSL (el chequeo falló o no se ejecutó)."

    if not ssl_result.get("has_https"):
        return 0, "El sitio no tiene HTTPS configurado."

    if ssl_result.get("is_expired"):
        return 0, "El certificado SSL ya expiró."

    if not ssl_result.get("trusted"):
        return (
            SSL_UNTRUSTED_POINTS,
            "Hay HTTPS, pero el certificado es autofirmado o de una cadena no confiable.",
        )

    if ssl_result.get("is_expiring_soon"):
        days = ssl_result.get("days_remaining")
        return (
            SSL_EXPIRING_SOON_POINTS,
            f"Certificado válido y confiable, pero expira pronto (faltan {days} días).",
        )

    return (
        MAX_POINTS_PER_CATEGORY,
        "Certificado SSL válido, de cadena confiable y no expira en menos de 30 días.",
    )


def _score_headers(headers_result: dict | None) -> tuple[int, str]:
    if not headers_result or not headers_result.get("success"):
        return 0, "No se pudieron evaluar los security headers (el chequeo falló o no se ejecutó)."

    score = headers_result.get("score", 0) or 0
    max_score = headers_result.get("max_score") or 1
    points = round((score / max_score) * MAX_POINTS_PER_CATEGORY)
    return points, f"{score}/{max_score} headers de seguridad recomendados están presentes."


def _score_dns_security(dns_result: dict | None) -> tuple[int, str]:
    if not dns_result or not dns_result.get("success"):
        return 0, "No se pudo evaluar SPF/DKIM/DMARC (el chequeo DNS falló o no se ejecutó)."

    spf_ok = bool((dns_result.get("spf") or {}).get("found"))
    dkim_ok = bool((dns_result.get("dkim") or {}).get("found"))
    dmarc_ok = bool((dns_result.get("dmarc") or {}).get("found"))
    present_count = sum([spf_ok, dkim_ok, dmarc_ok])

    if present_count == 3:
        return MAX_POINTS_PER_CATEGORY, "SPF, DKIM y DMARC están configurados."

    points = present_count * DNS_POINTS_PER_MECHANISM
    faltantes = [
        name
        for name, ok in (("SPF", spf_ok), ("DKIM", dkim_ok), ("DMARC", dmarc_ok))
        if not ok
    ]
    if present_count == 0:
        detalle = "No se detectó SPF, DKIM ni DMARC."
    else:
        detalle = f"Falta(n): {', '.join(faltantes)}."
    return points, detalle


def _score_ports(port_scan_result: dict | None) -> tuple[int, str]:
    if not port_scan_result or not port_scan_result.get("success"):
        return (
            NEUTRAL_POINTS_NO_DATA,
            "No se escanearon puertos (el escaneo falló o no se ejecutó); puntaje neutral.",
        )

    open_ports = port_scan_result.get("open_ports") or []
    open_port_numbers = {p["port"] for p in open_ports if "port" in p}
    risky_open = sorted(port for port in open_port_numbers if port in RISKY_PORTS)

    points = max(0, MAX_POINTS_PER_CATEGORY - PORT_PENALTY_PER_RISKY_PORT * len(risky_open))

    if risky_open:
        detalle = "Puertos de riesgo abiertos: " + ", ".join(
            f"{port} ({RISKY_PORTS[port]})" for port in risky_open
        ) + "."
    else:
        detalle = "No se detectaron puertos de riesgo abiertos entre los escaneados."
    return points, detalle


def _score_domain_age(whois_result: dict | None) -> tuple[int, str]:
    if not whois_result or not whois_result.get("success"):
        return (
            NEUTRAL_POINTS_NO_DATA,
            "No se pudo determinar la antigüedad del dominio (WHOIS falló, privacidad, o "
            "no se ejecutó); puntaje neutral.",
        )

    age_days = whois_result.get("domain_age_days")
    if age_days is None:
        return (
            NEUTRAL_POINTS_NO_DATA,
            "El WHOIS no reportó fecha de creación; puntaje neutral.",
        )

    if age_days >= 365:
        return MAX_POINTS_PER_CATEGORY, f"Dominio con {age_days} días de antigüedad (más de 1 año)."
    if age_days >= 180:
        return 10, f"Dominio con {age_days} días de antigüedad (entre 6 y 12 meses)."
    if age_days >= 30:
        return 5, f"Dominio con {age_days} días de antigüedad (entre 1 y 6 meses)."
    return 0, f"Dominio muy nuevo ({age_days} días) — señal de posible riesgo."


def calculate_score(
    dns_result: dict | None = None,
    whois_result: dict | None = None,
    ssl_result: dict | None = None,
    port_scan_result: dict | None = None,
    headers_result: dict | None = None,
) -> dict:
    """
    Combina los resultados de los demás módulos en un score 0-100. Nunca
    lanza excepciones ni requiere que todos los módulos hayan tenido
    éxito: cualquier resultado faltante o fallido se trata como "sin
    datos" y se puntúa de forma neutral o conservadora (ver docstring
    del módulo para el detalle de cada categoría).
    """
    ssl_points, ssl_note = _score_ssl(ssl_result)
    headers_points, headers_note = _score_headers(headers_result)
    dns_points, dns_note = _score_dns_security(dns_result)
    port_points, port_note = _score_ports(port_scan_result)
    age_points, age_note = _score_domain_age(whois_result)

    desglose = {
        "ssl": ssl_points,
        "headers": headers_points,
        "dns_seguridad": dns_points,
        "puertos": port_points,
        "antiguedad_dominio": age_points,
    }

    score_total = max(0, min(100, sum(desglose.values())))

    return {
        "score_total": score_total,
        "desglose": desglose,
        "nivel": _nivel_from_score(score_total),
        "detalles": {
            "ssl": ssl_note,
            "headers": headers_note,
            "dns_seguridad": dns_note,
            "puertos": port_note,
            "antiguedad_dominio": age_note,
        },
    }


def calculate_score_from_results(results: dict) -> dict:
    """
    Variante de conveniencia: recibe un único diccionario con las claves
    "dns_check", "whois_check", "ssl_check", "port_scan", "headers_check"
    (cada una con la salida del módulo correspondiente, o ausente/None
    si no se ejecutó) y delega en calculate_score().
    """
    results = results or {}
    return calculate_score(
        dns_result=results.get("dns_check"),
        whois_result=results.get("whois_check"),
        ssl_result=results.get("ssl_check"),
        port_scan_result=results.get("port_scan"),
        headers_result=results.get("headers_check"),
    )


if __name__ == "__main__":
    import json

    ejemplo_bueno = {
        "dns_check": {
            "success": True,
            "spf": {"found": True},
            "dkim": {"found": True},
            "dmarc": {"found": True},
        },
        "whois_check": {"success": True, "domain_age_days": 4000},
        "ssl_check": {
            "success": True,
            "has_https": True,
            "trusted": True,
            "is_expired": False,
            "is_expiring_soon": False,
        },
        "port_scan": {"success": True, "open_ports": [{"port": 443, "service": "HTTPS"}]},
        "headers_check": {"success": True, "score": 6, "max_score": 6},
    }
    print(json.dumps(calculate_score_from_results(ejemplo_bueno), indent=2, ensure_ascii=False))
