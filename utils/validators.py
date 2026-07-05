"""
utils/validators.py — Validación de formato de dominio/IP.

Responsabilidad única: validar que el input del usuario (antes de que
app.py invoque cualquier módulo de modules/) sea un dominio o una
dirección IP (IPv4) con formato correcto. No realiza resolución de red
ni llamadas externas — es validación puramente sintáctica/local.

Funciones:
    - normalize_domain(value: str) -> str
    - is_valid_domain(value: str) -> bool
    - is_valid_ip(value: str) -> bool
    - validate_target(value: str) -> tuple[bool, str, str]
        Devuelve (es_valido, valor_normalizado, mensaje_error).

Librerías usadas: re, ipaddress (stdlib). Este módulo no depende de
modules/ ni de servicios externos.
"""

import re
import ipaddress

# Dominio: etiquetas alfanuméricas (con guiones internos, no al inicio/fin)
# separadas por puntos, terminando en un TLD de al menos 2 letras.
_DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def normalize_domain(value: str) -> str:
    """
    Normaliza un input crudo de usuario para que pueda evaluarse como
    dominio:
        - quita espacios en los extremos
        - pasa a minúsculas
        - quita el esquema "http://" o "https://"
        - quita cualquier path/query/fragment (todo lo que venga tras "/")
        - quita el prefijo "www."
        - quita un puerto explícito (":8080") si viene pegado al host

    No lanza excepciones: si `value` no es utilizable devuelve "".
    """
    if not isinstance(value, str):
        return ""

    normalized = value.strip().lower()
    if not normalized:
        return ""

    # Quitar esquema http:// o https://
    normalized = re.sub(r"^https?://", "", normalized)

    # Quitar cualquier path/query/fragment tras el primer "/"
    normalized = normalized.split("/", 1)[0]

    # Quitar prefijo www.
    if normalized.startswith("www."):
        normalized = normalized[len("www."):]

    # Quitar puerto explícito (p. ej. "example.com:8080"), pero sin tocar
    # direcciones IPv6 entre corchetes (fuera de alcance aquí).
    if normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]

    return normalized.strip(".")


def is_valid_domain(value: str) -> bool:
    """
    Valida que `value` tenga formato de dominio válido. Se asume que
    `value` ya viene normalizado (ver normalize_domain).
    """
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_REGEX.match(value))


def is_valid_ip(value: str) -> bool:
    """
    Valida que `value` sea una dirección IPv4 válida (p. ej. "192.168.1.1").
    """
    if not value:
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def validate_target(value: str) -> tuple[bool, str, str]:
    """
    Punto de entrada único para validar el input del usuario antes de
    escanear nada.

    Recibe el string crudo tal como lo escribió el usuario (puede incluir
    "http://", "https://", "www.", espacios, etc.) e intenta interpretarlo
    como IPv4 o como dominio.

    Devuelve una tupla:
        (es_valido: bool, valor_normalizado: str, mensaje_error: str)

    Si es_valido es True, mensaje_error es "" y valor_normalizado contiene
    el dominio/IP listo para usarse en los módulos de análisis.
    Si es_valido es False, valor_normalizado es el input original tal
    cual lo escribió el usuario (sin normalizar) — no tiene sentido
    mostrarle al usuario un intento parcial/confuso de normalización de
    algo que de entrada no es válido, y mensaje_error explica el motivo
    citando ese mismo input original.
    """
    if value is None or not isinstance(value, str) or not value.strip():
        return False, "", "El input no puede estar vacío."

    raw = value.strip()

    # Caso 1: el usuario ya escribió una IP tal cual (sin esquema ni www).
    if is_valid_ip(raw):
        return True, raw, ""

    # Caso 2: normalizar y volver a intentar como IP (por si traía
    # esquema/espacios, aunque no sea lo habitual para IPs).
    normalized = normalize_domain(raw)

    if not normalized:
        return False, raw, f"'{raw}' no puede interpretarse como dominio ni como IP."

    if is_valid_ip(normalized):
        return True, normalized, ""

    # Caso 3: validar como dominio.
    if is_valid_domain(normalized):
        return True, normalized, ""

    # Inválido: devolvemos el input ORIGINAL (no el resultado parcial de
    # normalize_domain, que para basura como "ht!tp://raro..com" puede
    # quedar cortado de forma confusa, p. ej. "ht!tp"). Si no es válido,
    # no tiene caso mostrar un intento de normalización a medias.
    return (
        False,
        raw,
        f"'{raw}' no es un dominio ni una dirección IPv4 válida.",
    )


if __name__ == "__main__":
    # Pruebas manuales rápidas. Ejecutar con: python utils/validators.py
    test_cases = [
        "example.com",
        "http://example.com",
        "https://www.example.com",
        "www.example.com",
        "  example.com  ",
        "EXAMPLE.COM",
        "https://example.com/path/to/page?x=1",
        "sub.example.co.uk",
        "example.com:8080",
        "192.168.1.1",
        "http://192.168.1.1/",
        "8.8.8.8",
        "999.999.999.999",       # IPv4 inválida
        "-example.com",          # dominio inválido (empieza con guion)
        "example-.com",          # dominio inválido (etiqueta termina en guion)
        "example",               # sin TLD
        "",                      # vacío
        "   ",                   # solo espacios
        None,                    # tipo inválido
        "ht!tp://raro..com",     # basura
    ]

    print(f"{'input':35} -> {'valido':6} {'normalizado':25} error")
    print("-" * 100)
    for case in test_cases:
        es_valido, normalizado, error = validate_target(case)
        print(f"{str(case)!r:35} -> {str(es_valido):6} {normalizado!r:25} {error}")
