"""
utils/export.py — Generación del payload de exportación en JSON.

Responsabilidad única: convertir el diccionario combinado de resultados
de todos los módulos de NetSight (el mismo que app.py ya arma para
pasarle a modules/scoring.py, extendido con las claves de ssl_grade y
dns_propagation) en un string JSON formateado, listo para ofrecer como
descarga desde app.py. Este archivo no hace ninguna llamada de red ni
recalcula nada — solo serializa lo que ya se calculó en otro lado.

Función principal:
    build_export_payload(all_results: dict) -> str

Input esperado:
    all_results (dict): diccionario combinado armado por app.py, por
    ejemplo:
        {
            "domain": "ejemplo.com",
            "dns": {...},              # salida de modules.dns_check
            "dns_propagation": {...},  # salida de modules.dns_propagation
            "whois": {...},            # salida de modules.whois_check
            "ssl": {...},              # salida de modules.ssl_check
            "ssl_grade": {...},        # salida de modules.ssl_grade
            "ports": {...},            # salida de modules.port_scan
            "headers": {...},          # salida de modules.headers_check
            "tech": {...},             # salida de modules.tech_detect
            "score": {...},            # salida de modules.scoring
        }
    Este módulo es agnóstico a los nombres exactos de esas claves
    internas: no las lee ni las valida, solo envuelve el dict completo
    tal cual bajo la clave "results" del payload final. Eso significa
    que también funciona si en el futuro se agregan o quitan módulos,
    sin necesidad de tocar utils/export.py.

Output: un string JSON (indent=2, ensure_ascii=False) con esta forma:
    {
        "netsight_version": "1.0",
        "generated_at": "2026-07-05T14:32:10.123456",
        "domain": "ejemplo.com",
        "results": { ...all_results... }
    }

Nota sobre ensure_ascii=False: sin esto, json.dumps escaparía cualquier
tilde/ñ como secuencias \\uXXXX (p. ej. "México" -> "M\\u00e9xico"),
que son válidas pero ilegibles para un humano abriendo el .json a mano.
Con ensure_ascii=False, el archivo queda en UTF-8 legible directamente.

Librerías usadas: json, datetime (stdlib). No depende de módulos de
modules/ ni de utils/validators.py — solo sabe serializar un dict.
"""

from __future__ import annotations

import json
from datetime import datetime

NETSIGHT_VERSION = "1.0"


def build_export_payload(all_results: dict) -> str:
    """
    Arma el payload de exportación (metadata + resultados) y lo
    devuelve como string JSON formateado.

    El dominio analizado se toma de all_results["domain"] si está
    presente; si no, se intenta inferir de all_results["dns"]["domain"]
    como respaldo, y si tampoco existe, se usa "desconocido" para no
    lanzar una excepción por una clave faltante.
    """
    all_results = all_results or {}

    domain = all_results.get("domain")
    if not domain:
        dns_data = all_results.get("dns") or {}
        domain = dns_data.get("domain") or "desconocido"

    payload = {
        "netsight_version": NETSIGHT_VERSION,
        "generated_at": datetime.now().isoformat(),
        "domain": domain,
        "results": all_results,
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Prueba manual con datos 100% sintéticos de los módulos de
    # NetSight (DNS, WHOIS, SSL + SSL Grade, Puertos, Headers,
    # Tecnologías, Propagación DNS y Score). No requiere red: solo
    # verifica que build_export_payload() arme un JSON válido,
    # re-parseable con json.loads(), y que los acentos/ñ queden
    # legibles (no escapados como \\uXXXX).
    # Ejecutar con: python utils/export.py
    # ------------------------------------------------------------------
    sample_results = {
        "domain": "ejemplo-ñandú.com",
        "dns": {
            "domain": "ejemplo-ñandú.com",
            "success": True,
            "a_records": ["93.184.216.34"],
            "spf": {"found": True, "value": "v=spf1 include:_spf.ejemplo.com ~all"},
            "dkim": {"found": False, "selector_probado": None},
            "dmarc": {"found": True, "value": "v=DMARC1; p=reject"},
            "errors": [],
        },
        "dns_propagation": {
            "domain": "ejemplo-ñandú.com",
            "record_type": "A",
            "success": True,
            "is_consistent": True,
            "resolvers": {
                "Google": {"ip": "8.8.8.8", "responded": True, "values": ["93.184.216.34"], "response_time_ms": 12.3, "error": None},
            },
            "errors": [],
        },
        "whois": {
            "domain": "ejemplo-ñandú.com",
            "success": True,
            "registrar": "Registrador de Prueba, S.A. de C.V.",
            "country": "MX",
            "domain_age_days": 4000,
            "errors": [],
        },
        "ssl": {
            "domain": "ejemplo-ñandú.com",
            "success": True,
            "trusted": True,
            "is_expired": False,
            "issuer": "R3, Let's Encrypt, US",
            "errors": [],
        },
        "ssl_grade": {
            "grade": "A+",
            "numeric_score": 100,
            "penalties_applied": [],
        },
        "ports": {
            "host": "ejemplo-ñandú.com",
            "success": True,
            "open_ports": [{"port": 443, "service": "HTTPS"}],
            "errors": [],
        },
        "headers": {
            "domain": "ejemplo-ñandú.com",
            "success": True,
            "score": 6,
            "max_score": 6,
            "errors": [],
        },
        "tech": {
            "domain": "ejemplo-ñandú.com",
            "success": True,
            "detected_technologies": [{"name": "Nginx", "category": "Web Server", "evidence": []}],
            "errors": [],
        },
        "score": {
            "score_total": 95,
            "desglose": {
                "ssl": 20, "headers": 20, "dns_seguridad": 20,
                "puertos": 20, "antiguedad_dominio": 15,
            },
            "nivel": "Excelente",
        },
    }

    json_str = build_export_payload(sample_results)

    print("=== Payload generado (primeros 600 caracteres) ===")
    print(json_str[:600])
    print("...\n")

    # 1) Debe ser JSON válido y re-parseable.
    parsed = json.loads(json_str)
    assert parsed["netsight_version"] == NETSIGHT_VERSION
    assert parsed["domain"] == "ejemplo-ñandú.com"
    assert "generated_at" in parsed and isinstance(parsed["generated_at"], str)
    assert parsed["results"]["ssl_grade"]["grade"] == "A+"
    assert parsed["results"]["dns_propagation"]["is_consistent"] is True
    assert parsed["results"]["score"]["score_total"] == 95

    # 2) Los acentos/ñ deben verse literales en el string, no escapados.
    assert "ñandú" in json_str
    assert "\\u00f1" not in json_str
    assert "M\\u00e9xico" not in json_str  # no aplica aquí, pero confirma el patrón de escape que NO queremos

    # 3) Probar también con dominio ausente (debe caer al respaldo de dns.domain)
    sin_domain_top_level = dict(sample_results)
    del sin_domain_top_level["domain"]
    json_str_2 = build_export_payload(sin_domain_top_level)
    parsed_2 = json.loads(json_str_2)
    assert parsed_2["domain"] == "ejemplo-ñandú.com"  # rescatado desde results.dns.domain

    # 4) Probar con dict totalmente vacío (no debe lanzar excepción)
    json_str_3 = build_export_payload({})
    parsed_3 = json.loads(json_str_3)
    assert parsed_3["domain"] == "desconocido"
    assert parsed_3["results"] == {}

    print("TODAS LAS PRUEBAS PASARON (JSON válido, acentos legibles, fallbacks de dominio OK)")
