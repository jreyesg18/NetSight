"""
modules/headers_check.py — Verificación de security headers HTTP.

Responsabilidad única: dado un dominio, hacer una petición HTTP(S) (con
requests) e inspeccionar la presencia y el valor de los encabezados de
seguridad más relevantes, devolviendo también una breve explicación en
español de qué protege cada uno y un score parcial de cuántos están
presentes.

Input esperado:
    domain (str): dominio ya validado (ver utils/validators.py). No se
                  vuelve a validar el formato en este módulo.

Función principal:
    check_headers(domain, timeout=10, verify_ssl=True, port=None) -> dict

Comportamiento de la petición:
    Se intenta primero por HTTPS; si falla (SSL, conexión rechazada,
    timeout, etc.) se hace fallback a HTTP. Si ambos fallan, el
    resultado se marca success=False con el detalle en "errors".

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "success": bool,
        "final_url": str | None,       # URL final tras redirects
        "scheme_used": "https" | "http" | None,
        "status_code": int | None,
        "headers": {
            "Content-Security-Policy": {
                "present": bool,
                "value": str | None,
                "description": str,    # qué protege este header
            },
            ... (uno por cada header evaluado)
        },
        "score": int,                  # headers recomendados presentes
        "max_score": int,              # total de headers evaluados
        "score_percentage": float,     # score/max_score * 100
        "raw_headers": {str: str, ...},# todos los headers de la respuesta
        "warnings": [str, ...],        # avisos no fatales (p. ej. fallback a http)
        "errors": [str, ...],
    }

Librerías usadas: requests. No depende de otros módulos de modules/.
"""

from __future__ import annotations

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "NetSight/1.0 (+heuristic security scanner; contacta al operador del sitio)"

# Headers de seguridad evaluados, con una breve explicación en español
# de qué riesgo mitigan.
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "Define qué orígenes pueden cargar scripts, estilos, imágenes u otros "
        "recursos en la página. Es la principal defensa contra ataques de "
        "Cross-Site Scripting (XSS) y de inyección de contenido."
    ),
    "X-Frame-Options": (
        "Controla si el sitio puede mostrarse dentro de un <iframe> de otra "
        "página. Previene ataques de clickjacking, donde un sitio malicioso "
        "superpone tu página para engañar al usuario a hacer clic en algo distinto."
    ),
    "X-Content-Type-Options": (
        "Con el valor 'nosniff', impide que el navegador intente adivinar el "
        "tipo de contenido de un archivo distinto al declarado, evitando "
        "ataques de MIME sniffing (p. ej. ejecutar un archivo como script "
        "cuando en realidad era una imagen)."
    ),
    "Strict-Transport-Security": (
        "(HSTS) Obliga al navegador a comunicarse siempre por HTTPS con este "
        "dominio durante un tiempo determinado, incluso si el usuario escribe "
        "http://. Previene ataques de downgrade y de intermediario (MITM)."
    ),
    "Referrer-Policy": (
        "Controla cuánta información de la URL de origen se envía en el "
        "header Referer al navegar hacia otros sitios, reduciendo la fuga de "
        "datos potencialmente sensibles (rutas internas, tokens en la URL, etc.)."
    ),
    "Permissions-Policy": (
        "Permite habilitar o deshabilitar explícitamente el acceso a APIs y "
        "funciones sensibles del navegador (cámara, micrófono, geolocalización, "
        "etc.) para este origen y para contenido embebido, reduciendo la "
        "superficie de abuso de esas APIs."
    ),
}


def _empty_headers_status() -> dict:
    return {
        name: {"present": False, "value": None, "description": description}
        for name, description in SECURITY_HEADERS.items()
    }


def _empty_result(domain: str) -> dict:
    return {
        "domain": domain,
        "success": False,
        "final_url": None,
        "scheme_used": None,
        "status_code": None,
        "headers": _empty_headers_status(),
        "score": 0,
        "max_score": len(SECURITY_HEADERS),
        "score_percentage": 0.0,
        "raw_headers": {},
        "warnings": [],
        "errors": [],
    }


def _build_url(domain: str, scheme: str, port: int | None) -> str:
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        return f"{scheme}://{domain}:{port}"
    return f"{scheme}://{domain}"


def check_headers(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    port: int | None = None,
) -> dict:
    """
    Hace un GET a `domain` (HTTPS primero, con fallback a HTTP) y evalúa
    la presencia de los security headers definidos en SECURITY_HEADERS.

    Nunca lanza excepciones: cualquier fallo de red/HTTP queda
    registrado en result["errors"] (o en "warnings" si no impidió
    obtener una respuesta, p. ej. cuando HTTPS falló pero HTTP funcionó).
    """
    result = _empty_result(domain)

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio inválido o vacío recibido por headers_check.")
        return result

    headers_to_send = {"User-Agent": DEFAULT_USER_AGENT}

    response = None
    scheme_used = None
    attempt_notes: list[str] = []

    for scheme in ("https", "http"):
        url = _build_url(domain, scheme, port)
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers=headers_to_send,
                allow_redirects=True,
                verify=verify_ssl,
            )
            scheme_used = scheme
            break
        except requests.exceptions.SSLError as exc:
            attempt_notes.append(f"Falló {scheme.upper()} por un error de certificado SSL: {exc}")
        except requests.exceptions.ConnectionError as exc:
            attempt_notes.append(f"No se pudo conectar por {scheme.upper()}: {exc}")
        except requests.exceptions.Timeout:
            attempt_notes.append(f"Timeout al conectar por {scheme.upper()} a '{domain}'.")
        except requests.exceptions.RequestException as exc:
            attempt_notes.append(f"Error inesperado al hacer la petición por {scheme.upper()}: {exc}")

    if response is None:
        result["errors"].extend(attempt_notes)
        result["errors"].append(
            f"No se pudo obtener respuesta de '{domain}' ni por HTTPS ni por HTTP."
        )
        return result

    # Si HTTPS falló pero HTTP funcionó, dejamos constancia como advertencia
    # (no es un error fatal: sí obtuvimos headers, pero vale la pena saber
    # que el sitio no respondió por HTTPS).
    if scheme_used == "http" and attempt_notes:
        result["warnings"].extend(attempt_notes)
        result["warnings"].append(
            "Se obtuvo respuesta por HTTP tras fallar HTTPS: este sitio podría no "
            "tener HTTPS configurado correctamente (ver también modules/ssl_check.py)."
        )

    result["final_url"] = response.url
    result["scheme_used"] = scheme_used
    result["status_code"] = response.status_code
    result["raw_headers"] = dict(response.headers)

    score = 0
    headers_status = {}
    for header_name, description in SECURITY_HEADERS.items():
        # response.headers es case-insensitive (CaseInsensitiveDict de requests)
        value = response.headers.get(header_name)
        present = value is not None
        headers_status[header_name] = {
            "present": present,
            "value": value,
            "description": description,
        }
        if present:
            score += 1

    result["headers"] = headers_status
    result["score"] = score
    result["max_score"] = len(SECURITY_HEADERS)
    result["score_percentage"] = round((score / len(SECURITY_HEADERS)) * 100, 1)
    result["success"] = True

    return result


if __name__ == "__main__":
    import json
    import sys

    domain_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = check_headers(domain_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
