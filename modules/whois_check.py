"""
modules/whois_check.py — Consulta WHOIS del dominio.

Responsabilidad única: dado un dominio, obtener información de registro:
antigüedad del dominio, registrador (registrar), país, fecha de creación
y fecha de expiración, y calcular métricas derivadas (antigüedad en
días/años, días restantes para expirar).

Input esperado:
    domain (str): nombre de dominio ya validado (ver utils/validators.py).
                  Este módulo no vuelve a validar el formato, asume que ya
                  pasó por utils.validators.validate_target. No aplica a
                  IPs (WHOIS de IP no es el caso de uso de este módulo).

Función principal:
    check_whois(domain, timeout=10) -> dict

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "success": bool,
        "registrar": str | None,
        "country": str | None,
        "creation_date": str | None,        # ISO 8601, p. ej. "2005-03-15T00:00:00"
        "expiration_date": str | None,       # ISO 8601
        "domain_age_days": int | None,
        "domain_age_years": float | None,
        "days_to_expire": int | None,
        "is_expired": bool | None,
        "status": [str, ...],
        "privacy_protected": bool,
        "raw_error": str | None,       # texto crudo completo del error WHOIS (debug), si aplica
        "errors": [str, ...],
    }

LIMITACIÓN — WHOIS "privado" (GDPR / privacidad del registrador):
    Desde el RGPD (2018), la mayoría de registradores ocultan los datos
    del registrante (nombre, org, email, dirección) y los sustituyen por
    placeholders como "REDACTED FOR PRIVACY" o "Data Protected". Esto NO
    rompe la consulta WHOIS: el registrador, el estado del dominio y casi
    siempre las fechas de creación/expiración se siguen publicando. Este
    módulo:
        - sigue devolviendo success=True y las fechas/registrador cuando
          están disponibles;
        - marca "privacy_protected": True si detecta marcadores de texto
          conocidos de redacción/privacidad en los campos del WHOIS
          (heurística de texto — no existe un campo estándar "is_private"
          en el protocolo WHOIS, así que esto puede tener falsos
          negativos con proveedores de privacidad no listados).

Librerías usadas: python-whois (import "whois"). No depende de otros
módulos de modules/.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

import whois
from whois.exceptions import PywhoisError

DEFAULT_TIMEOUT = 10

# Marcadores de texto que delatan que el WHOIS está protegido por un
# servicio de privacidad o por redacción GDPR. Es una heurística: no hay
# un campo estándar en WHOIS que indique "esto es privado".
PRIVACY_MARKERS = [
    "redacted for privacy",
    "data protected",
    "not disclosed",
    "gdpr masked",
    "gdpr redacted",
    "whoisguard",
    "privacy protect",
    "perfect privacy",
    "domains by proxy",
    "contact privacy",
    "private registration",
    "identity protection service",
    "redacted for gdpr",
    "on behalf of",
    "withheld for privacy",
]


def _empty_result(domain: str) -> dict:
    """Estructura base del diccionario de resultados, todo vacío."""
    return {
        "domain": domain,
        "success": False,
        "registrar": None,
        "country": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "domain_age_years": None,
        "days_to_expire": None,
        "is_expired": None,
        "status": [],
        "privacy_protected": False,
        "raw_error": None,
        "errors": [],
    }


def _first_relevant_line(text: str) -> str:
    """
    Extrae la primera línea no vacía de un texto de error WHOIS crudo.

    Muchos servidores WHOIS (p. ej. el de Verisign para .com/.net)
    devuelven, cuando el dominio no existe, una primera línea del tipo
    'No match for "DOMINIO.COM"' seguida de varios párrafos de términos
    legales/de uso. python-whois a veces propaga ese texto completo como
    mensaje de la excepción. Esta función se queda solo con la primera
    línea útil para mostrar un error corto y legible; el texto completo
    se conserva aparte en result["raw_error"] por si hace falta para debug.
    """
    if not text:
        return "El servidor WHOIS no devolvió información para este dominio."
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            return line
    # Salvaguarda por si el texto no tiene saltos de línea "normales".
    return text.strip()[:200]


def _first(value):
    """
    python-whois a veces devuelve una lista cuando el WHOIS trae varios
    valores para el mismo campo (registros duplicados del servidor).
    Tomamos el primer valor no vacío; si es un valor simple, se devuelve
    tal cual.
    """
    if isinstance(value, (list, tuple)):
        for item in value:
            if item:
                return item
        return None
    return value


def _to_naive_utc(value) -> datetime | None:
    """
    Normaliza una fecha proveniente de python-whois (puede venir como
    datetime con o sin timezone, o como lista de datetimes) a un
    datetime "naive" en UTC, para poder restar fechas de forma
    consistente sin importar si el registrador publicó timezone o no.
    Si no se puede interpretar como fecha, devuelve None.
    """
    dt = _first(value)
    if dt is None or not isinstance(dt, datetime):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _normalize_status(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _looks_privacy_protected(entry) -> bool:
    """
    Heurística: junta varios campos de texto del WHOIS (registrar, org,
    nombre del registrante, emails, país, etc.) más el texto crudo de la
    respuesta (si está disponible) y busca marcadores conocidos de
    privacidad/redacción GDPR.
    """
    haystack_parts = []

    for key in ("registrar", "org", "name", "emails", "state", "address", "city", "country"):
        val = entry.get(key)
        if isinstance(val, (list, tuple)):
            haystack_parts.extend(str(v) for v in val)
        elif val:
            haystack_parts.append(str(val))

    # El texto crudo se guarda como atributo de instancia (no como key
    # del dict), así que se accede con getattr, no con entry.get("text").
    raw_text = getattr(entry, "text", "") or ""
    haystack_parts.append(raw_text)

    haystack = " ".join(haystack_parts).lower()
    return any(marker in haystack for marker in PRIVACY_MARKERS)


def check_whois(domain: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Consulta WHOIS para `domain` y calcula antigüedad / días para
    expirar. Nunca lanza excepciones: cualquier fallo (dominio sin
    WHOIS, timeout, TLD no soportado, respuesta vacía) queda registrado
    en result["errors"] y la función siempre devuelve el diccionario
    estandarizado con success=False en esos casos.
    """
    result = _empty_result(domain)

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio inválido o vacío recibido por whois_check.")
        return result

    try:
        entry = whois.whois(domain, timeout=timeout, ignore_socket_errors=False)
    except PywhoisError as exc:
        full_text = str(exc)
        short_message = _first_relevant_line(full_text)
        result["errors"].append(f"WHOIS no encontró datos para '{domain}': {short_message}")
        # El texto completo (que puede incluir varios párrafos de términos
        # legales del servidor WHOIS) se guarda aparte, no en "errors".
        result["raw_error"] = full_text
        return result
    except socket.timeout:
        result["errors"].append(f"Timeout al consultar WHOIS para '{domain}'.")
        return result
    except socket.gaierror as exc:
        result["errors"].append(
            f"No se pudo resolver el servidor WHOIS para '{domain}': {exc}"
        )
        return result
    except OSError as exc:
        # Cubre errores de socket genéricos (conexión rechazada, red
        # inalcanzable, etc.) que no son PywhoisError.
        result["errors"].append(f"Error de red al consultar WHOIS para '{domain}': {exc}")
        return result
    except Exception as exc:  # noqa: BLE001 - no queremos que un fallo aquí tumbe la app
        result["errors"].append(
            f"Error inesperado al consultar WHOIS para '{domain}': {exc}"
        )
        return result

    if entry is None or not any(entry.values()):
        result["errors"].append(
            f"WHOIS devolvió una respuesta vacía o sin datos útiles para '{domain}'."
        )
        return result

    registrar = _first(entry.get("registrar"))
    country = _first(entry.get("country"))
    status = _normalize_status(entry.get("status"))

    creation_dt = _to_naive_utc(entry.get("creation_date"))
    expiration_dt = _to_naive_utc(entry.get("expiration_date"))

    now = datetime.utcnow()

    domain_age_days = None
    domain_age_years = None
    if creation_dt:
        domain_age_days = (now - creation_dt).days
        domain_age_years = round(domain_age_days / 365.25, 2)

    days_to_expire = None
    is_expired = None
    if expiration_dt:
        days_to_expire = (expiration_dt - now).days
        is_expired = days_to_expire < 0

    result.update(
        {
            "success": True,
            "registrar": registrar,
            "country": country,
            "creation_date": creation_dt.isoformat() if creation_dt else None,
            "expiration_date": expiration_dt.isoformat() if expiration_dt else None,
            "domain_age_days": domain_age_days,
            "domain_age_years": domain_age_years,
            "days_to_expire": days_to_expire,
            "is_expired": is_expired,
            "status": status,
            "privacy_protected": _looks_privacy_protected(entry),
        }
    )

    return result


if __name__ == "__main__":
    import json
    import sys

    domain_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = check_whois(domain_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
