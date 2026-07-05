"""
modules/tech_detect.py — Detección heurística de tecnologías (propia).

Responsabilidad única: dado un dominio, inferir tecnologías usadas (CMS,
servidores web, CDN, frameworks JS/backend, analytics, e-commerce, etc.)
mediante heurísticas 100% propias basadas en tres señales:
    1. Headers de la respuesta HTTP (p. ej. "Server", "X-Powered-By").
    2. Cookies establecidas por el servidor (Set-Cookie).
    3. Patrones simples de texto en el HTML servido (sin parseo de DOM,
       solo búsqueda de substrings — no se ejecuta JavaScript ni se
       parsea el HTML con un parser real).

IMPORTANTE: NO usa Wappalyzer ni ninguna librería de terceros con
licencias restrictivas (p. ej. GPL) para hacer esta detección. Las
reglas viven enteramente en el diccionario TECH_SIGNATURES de este
archivo, con licencia MIT/propia del proyecto.

Input esperado:
    domain (str): dominio ya validado (ver utils/validators.py).

Función principal:
    detect_technologies(domain, timeout=10, verify_ssl=True, port=None) -> dict

Estructura de TECH_SIGNATURES (fácil de extender — solo agregar una
nueva entrada al dict, no hace falta tocar el motor de detección):
    TECH_SIGNATURES = {
        "NombreTecnologia": {
            "category": "CMS" | "Web Server" | "CDN" | "JS Framework" |
                         "Backend Framework" | "Analytics" | "E-commerce" | ...,
            "headers": [("Nombre-Header", "substring_a_buscar_en_el_valor"), ...],
                # Si substring_a_buscar es "", solo se exige que el header
                # exista (con cualquier valor). Si no, se busca el
                # substring dentro del valor del header (case-insensitive).
            "html_patterns": ["substring_en_el_html", ...],
            "cookies": ["substring_en_el_nombre_de_cookie", ...],
        },
        ...
    }

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "success": bool,
        "final_url": str | None,
        "scheme_used": "https" | "http" | None,
        "status_code": int | None,
        "detected_technologies": [
            {
                "name": str,
                "category": str,
                "evidence": [
                    {"method": "header", "header": str, "matched_value": str, "signature": str},
                    {"method": "cookie", "cookie_name": str, "signature": str},
                    {"method": "html_pattern", "signature": str},
                    ...
                ],
            },
            ...
        ],
        "warnings": [str, ...],
        "errors": [str, ...],
    }

LIMITACIÓN: esto es detección heurística basada en firmas conocidas, no
un análisis exhaustivo del stack tecnológico real. Puede haber falsos
negativos (tecnología presente pero sin ninguna de las firmas
configuradas) y, en menor medida, falsos positivos (un string
coincidente por casualidad). El campo "evidence" existe justamente para
que el usuario pueda verificar por sí mismo por qué se detectó cada
tecnología.

Librerías usadas: requests, re (stdlib). No depende de otros módulos de
modules/.
"""

from __future__ import annotations

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "NetSight/1.0 (+heuristic tech detector; contacta al operador del sitio)"
MAX_HTML_CHARS = 300_000  # límite de seguridad: no escanear HTML arbitrariamente grande

# ---------------------------------------------------------------------
# Diccionario de firmas propias. Agregar una tecnología nueva = agregar
# una entrada aquí, no requiere tocar el motor de detección.
# ---------------------------------------------------------------------
TECH_SIGNATURES: dict[str, dict] = {
    "WordPress": {
        "category": "CMS",
        "headers": [("Link", "wp-json"), ("X-Powered-By", "WordPress")],
        "html_patterns": ["wp-content", "wp-includes", "wp-json", "wp-emoji-release"],
        "cookies": ["wordpress_", "wp-settings"],
    },
    "WooCommerce": {
        "category": "E-commerce",
        "headers": [],
        "html_patterns": ["woocommerce", "wc-ajax", "wc_add_to_cart_params", "woocommerce-page"],
        "cookies": ["woocommerce_cart_hash", "woocommerce_items_in_cart"],
    },
    "Nginx": {
        "category": "Web Server",
        "headers": [("Server", "nginx")],
        "html_patterns": [],
        "cookies": [],
    },
    "Apache": {
        "category": "Web Server",
        "headers": [("Server", "apache")],
        "html_patterns": [],
        "cookies": [],
    },
    "Cloudflare": {
        "category": "CDN",
        "headers": [("Server", "cloudflare"), ("CF-RAY", ""), ("CF-Cache-Status", "")],
        "html_patterns": [],
        "cookies": ["__cfduid", "cf_clearance"],
    },
    "React": {
        "category": "JS Framework",
        "headers": [],
        "html_patterns": [
            "data-reactroot",
            "data-reactid",
            "react-dom.production.min.js",
            "react-dom.development.js",
            "_reactListening",
        ],
        "cookies": [],
    },
    "Next.js": {
        "category": "JS Framework",
        "headers": [("X-Powered-By", "Next.js")],
        "html_patterns": ["__NEXT_DATA__", "/_next/static/", "__next"],
        "cookies": [],
    },
    "PHP": {
        "category": "Backend Framework",
        "headers": [("X-Powered-By", "PHP"), ("Server", "PHP")],
        "html_patterns": [],
        "cookies": ["PHPSESSID"],
    },
    "Express": {
        "category": "Backend Framework",
        "headers": [("X-Powered-By", "Express")],
        "html_patterns": [],
        "cookies": ["connect.sid"],
    },
    "Django": {
        "category": "Backend Framework",
        "headers": [],
        "html_patterns": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "cookies": ["csrftoken", "sessionid", "django"],
    },
    "Google Analytics": {
        "category": "Analytics",
        "headers": [],
        "html_patterns": [
            "google-analytics.com/analytics.js",
            "googletagmanager.com/gtag/js",
            "gtag('config'",
            "ga('create'",
        ],
        "cookies": ["_ga", "_gid"],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "headers": [],
        "html_patterns": ["googletagmanager.com/gtm.js", "GTM-"],
        "cookies": [],
    },
}


# --- Motor de detección genérico (no conoce tecnologías específicas) ---


def _match_headers(headers, header_sigs: list[tuple[str, str]]) -> list[dict]:
    """headers: CaseInsensitiveDict de requests (o dict equivalente)."""
    evidence = []
    for header_name, substring in header_sigs:
        value = headers.get(header_name)
        if value is None:
            continue
        if substring == "" or substring.lower() in value.lower():
            evidence.append(
                {
                    "method": "header",
                    "header": header_name,
                    "matched_value": value,
                    "signature": substring or "(presencia del header)",
                }
            )
    return evidence


def _match_cookies(cookie_names: list[str], cookie_sigs: list[str]) -> list[dict]:
    evidence = []
    lowered_names = [(name, name.lower()) for name in cookie_names]
    for sig in cookie_sigs:
        sig_lower = sig.lower()
        for original_name, lowered in lowered_names:
            if sig_lower in lowered:
                evidence.append(
                    {"method": "cookie", "cookie_name": original_name, "signature": sig}
                )
                break
    return evidence


def _match_html(html_lower: str, patterns: list[str]) -> list[dict]:
    evidence = []
    for pattern in patterns:
        if pattern.lower() in html_lower:
            evidence.append({"method": "html_pattern", "signature": pattern})
    return evidence


def _detect_all(headers, cookie_names: list[str], html_lower: str) -> list[dict]:
    detected = []
    for name, signature in TECH_SIGNATURES.items():
        evidence = []
        evidence.extend(_match_headers(headers, signature.get("headers", [])))
        evidence.extend(_match_cookies(cookie_names, signature.get("cookies", [])))
        evidence.extend(_match_html(html_lower, signature.get("html_patterns", [])))
        if evidence:
            detected.append(
                {
                    "name": name,
                    "category": signature.get("category", "Desconocida"),
                    "evidence": evidence,
                }
            )
    return detected


# --- Obtención de la página (independiente de otros módulos) -----------


def _empty_result(domain: str) -> dict:
    return {
        "domain": domain,
        "success": False,
        "final_url": None,
        "scheme_used": None,
        "status_code": None,
        "detected_technologies": [],
        "warnings": [],
        "errors": [],
    }


def _build_url(domain: str, scheme: str, port: int | None) -> str:
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        return f"{scheme}://{domain}:{port}"
    return f"{scheme}://{domain}"


def detect_technologies(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    port: int | None = None,
) -> dict:
    """
    Descarga la página principal de `domain` (HTTPS primero, fallback a
    HTTP) y detecta tecnologías conocidas usando TECH_SIGNATURES.

    Nunca lanza excepciones: cualquier fallo de red queda en
    result["errors"]; fallback https->http exitoso queda en "warnings".
    """
    result = _empty_result(domain)

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio inválido o vacío recibido por tech_detect.")
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

    if scheme_used == "http" and attempt_notes:
        result["warnings"].extend(attempt_notes)
        result["warnings"].append(
            "Se obtuvo respuesta por HTTP tras fallar HTTPS; la detección de "
            "tecnologías se basó en esa respuesta."
        )

    result["final_url"] = response.url
    result["scheme_used"] = scheme_used
    result["status_code"] = response.status_code

    html_text = response.text or ""
    if len(html_text) > MAX_HTML_CHARS:
        result["warnings"].append(
            f"El HTML de la página supera los {MAX_HTML_CHARS} caracteres; "
            f"solo se analizaron los primeros {MAX_HTML_CHARS} para la detección de patrones."
        )
        html_text = html_text[:MAX_HTML_CHARS]

    cookie_names = list(response.cookies.keys())

    try:
        detected = _detect_all(response.headers, cookie_names, html_text.lower())
    except Exception as exc:  # noqa: BLE001 - el motor de firmas no debe tumbar la app
        result["errors"].append(f"Error inesperado durante la detección de tecnologías: {exc}")
        return result

    result["detected_technologies"] = detected
    result["success"] = True

    return result


if __name__ == "__main__":
    import json
    import sys

    domain_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = detect_technologies(domain_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
