"""
modules/ssl_check.py — Verificación de certificado SSL/TLS.

Responsabilidad única: dado un dominio (o IP), conectarse por HTTPS
(puerto 443 por defecto) y extraer información del certificado: emisor,
a quién fue emitido (subject/CN), fechas de validez, días restantes para
expirar, algoritmo de firma, cipher suite negociado y versión de TLS.

Input esperado:
    domain (str): nombre de dominio o IP ya validado (ver
                  utils/validators.py). Este módulo no vuelve a validar
                  el formato del input.

Función principal:
    check_ssl(domain, port=443, timeout=5.0, warn_days=30) -> dict

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "port": int,
        "success": bool,               # True si se logró obtener y parsear un certificado
        "has_https": bool,             # True si el handshake TLS se completó (aunque no sea confiable)
        "trusted": bool | None,        # True si la cadena de confianza validó correctamente
        "self_signed_or_untrusted": bool,
        "verify_error": str | None,    # motivo por el que no fue "trusted" (si aplica)
        "issuer": str | None,          # representación legible, p.ej. "R3, Let's Encrypt, US"
        "issuer_raw": {str: str, ...}, # atributos crudos del issuer (CN, O, C, ...)
        "subject_cn": str | None,
        "subject_raw": {str: str, ...},
        "signature_algorithm": str | None,
        "not_before": str | None,      # ISO 8601 UTC
        "not_after": str | None,       # ISO 8601 UTC
        "days_remaining": int | None,
        "is_expired": bool | None,
        "is_expiring_soon": bool | None,   # True si faltan menos de `warn_days` días
        "cipher_suite": {"name": str, "tls_version": str, "secret_bits": int} | None,
        "errors": [str, ...],
    }

LIMITACIÓN — parsing del certificado sin librerías de terceros:
    El módulo `ssl` de la librería estándar NO expone el algoritmo de
    firma del certificado (ni permite leer el certificado en absoluto
    cuando la verificación fue deshabilitada — `getpeercert()` devuelve
    un dict vacío en ese caso). Para evitar depender de `cryptography` o
    `pyOpenSSL`, este módulo incluye un parser ASN.1/DER mínimo y propio
    (funciones `_read_tlv`, `_iter_children`, `_decode_oid`, etc.) que
    interpreta directamente los bytes DER del certificado (obtenidos con
    `getpeercert(binary_form=True)`, que sí funciona sin verificar) para
    extraer issuer, subject, fechas de validez y el algoritmo de firma.
    No es un parser X.509 completo: solo entiende los campos que
    NetSight necesita, usando los OIDs más comunes en certificados TLS
    reales (RSA/ECDSA/Ed25519 con SHA-1/256/384/512).

MANEJO DE CASOS DE ERROR:
    - Sin HTTPS configurado (puerto cerrado, conexión rechazada, timeout,
      o algo responde en el puerto pero no habla TLS): se reporta en
      "errors", success=False, has_https=False.
    - Certificado autofirmado / cadena no confiable / hostname no
      coincide: NO se descarta la conexión. Se reintenta sin verificar
      para poder igual extraer y mostrar los datos del certificado,
      marcando trusted=False y self_signed_or_untrusted=True, con el
      motivo en "verify_error".

Librerías usadas: ssl, socket, datetime (stdlib). No depende de otros
módulos de modules/.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0
DEFAULT_WARN_DAYS = 30

# --- OIDs conocidos -----------------------------------------------------

# Algoritmos de firma más comunes en certificados TLS reales.
SIGNATURE_ALGORITHM_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

# Atributos de Name (issuer/subject) más comunes.
NAME_ATTRIBUTE_OIDS = {
    "2.5.4.3": "commonName",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "1.2.840.113549.1.9.1": "emailAddress",
}

_NAME_DISPLAY_ORDER = [
    "commonName",
    "organizationName",
    "organizationalUnitName",
    "localityName",
    "stateOrProvinceName",
    "countryName",
]


# --- Parser ASN.1 / DER mínimo -------------------------------------------


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Lee un campo de longitud DER a partir de `offset`.
    Devuelve (longitud, offset_despues_de_la_longitud)."""
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Longitud ASN.1 indefinida no soportada en DER.")
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Lee un TLV (Tag-Length-Value) en `offset`.
    Devuelve (tag, value_start, value_end)."""
    tag = data[offset]
    length, value_start = _read_length(data, offset + 1)
    return tag, value_start, value_start + length


def _iter_children(data: bytes, start: int, end: int):
    """Itera los TLVs hijos directos dentro del rango [start, end)."""
    offset = start
    while offset < end:
        tag, value_start, value_end = _read_tlv(data, offset)
        yield tag, value_start, value_end
        offset = value_end


def _decode_oid(oid_bytes: bytes) -> str:
    """Decodifica un OBJECT IDENTIFIER DER a su notación 'x.y.z...'."""
    if not oid_bytes:
        return ""
    first = oid_bytes[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in oid_bytes[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _parse_asn1_time(data: bytes, tag: int, start: int, end: int) -> datetime:
    """Convierte un UTCTime (tag 0x17) o GeneralizedTime (tag 0x18) DER
    a un datetime timezone-aware en UTC."""
    raw = data[start:end].decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSS
        yy = int(raw[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        month, day, hour, minute, second = (
            int(raw[2:4]),
            int(raw[4:6]),
            int(raw[6:8]),
            int(raw[8:10]),
            int(raw[10:12]) if len(raw) >= 12 else 0,
        )
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSS
        year = int(raw[0:4])
        month, day, hour, minute, second = (
            int(raw[4:6]),
            int(raw[6:8]),
            int(raw[8:10]),
            int(raw[10:12]),
            int(raw[12:14]) if len(raw) >= 14 else 0,
        )
    else:
        raise ValueError(f"Tipo de tiempo ASN.1 desconocido (tag={tag:#x}).")
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _parse_name(data: bytes, start: int, end: int) -> dict:
    """Parsea una estructura Name (RDNSequence) y devuelve un dict
    {atributo_legible: valor}."""
    attrs: dict = {}
    for _rdn_tag, rdn_start, rdn_end in _iter_children(data, start, end):
        for _atv_tag, atv_start, atv_end in _iter_children(data, rdn_start, rdn_end):
            children = list(_iter_children(data, atv_start, atv_end))
            if len(children) < 2:
                continue
            (_, oid_start, oid_end), (_, val_start, val_end) = children[0], children[1]
            oid_str = _decode_oid(data[oid_start:oid_end])
            name = NAME_ATTRIBUTE_OIDS.get(oid_str, oid_str)
            raw_value = data[val_start:val_end]
            try:
                value = raw_value.decode("utf-8")
            except UnicodeDecodeError:
                value = raw_value.decode("latin-1", errors="replace")
            if name in attrs:
                if isinstance(attrs[name], list):
                    attrs[name].append(value)
                else:
                    attrs[name] = [attrs[name], value]
            else:
                attrs[name] = value
    return attrs


def _format_name(attrs: dict) -> str | None:
    """Convierte el dict de atributos de un Name en un string legible,
    p. ej. 'R3, Let's Encrypt, US'."""
    parts = []
    for key in _NAME_DISPLAY_ORDER:
        value = attrs.get(key)
        if not value:
            continue
        if isinstance(value, list):
            value = ", ".join(value)
        parts.append(value)
    return ", ".join(parts) if parts else None


def _parse_certificate_der(der: bytes) -> dict:
    """
    Parsea manualmente un certificado X.509 en DER para extraer issuer,
    subject, validez y algoritmo de firma. Ver limitación documentada en
    el encabezado del módulo.
    """
    _cert_tag, cert_start, cert_end = _read_tlv(der, 0)
    cert_children = list(_iter_children(der, cert_start, cert_end))
    if len(cert_children) < 3:
        raise ValueError("Estructura de certificado X.509 inesperada (DER incompleto).")

    tbs_tag, tbs_start, tbs_end = cert_children[0]
    _sig_alg_tag, sig_alg_start, sig_alg_end = cert_children[1]

    # signatureAlgorithm a nivel de Certificate (fuera del TBSCertificate)
    sig_alg_children = list(_iter_children(der, sig_alg_start, sig_alg_end))
    sig_oid_tag, sig_oid_start, sig_oid_end = sig_alg_children[0]
    sig_oid = _decode_oid(der[sig_oid_start:sig_oid_end])
    signature_algorithm = SIGNATURE_ALGORITHM_OIDS.get(sig_oid, sig_oid)

    # Recorrer TBSCertificate: [version]?, serialNumber, signature, issuer, validity, subject, ...
    tbs_children = list(_iter_children(der, tbs_start, tbs_end))
    idx = 0
    if tbs_children[idx][0] == 0xA0:  # version [0] EXPLICIT (contexto, constructed)
        idx += 1
    idx += 1  # serialNumber (INTEGER)
    idx += 1  # signature AlgorithmIdentifier (duplicado del de arriba)

    issuer_tag, issuer_start, issuer_end = tbs_children[idx]
    issuer_attrs = _parse_name(der, issuer_start, issuer_end)
    idx += 1

    validity_tag, validity_start, validity_end = tbs_children[idx]
    validity_children = list(_iter_children(der, validity_start, validity_end))
    not_before = _parse_asn1_time(der, *validity_children[0])
    not_after = _parse_asn1_time(der, *validity_children[1])
    idx += 1

    subject_tag, subject_start, subject_end = tbs_children[idx]
    subject_attrs = _parse_name(der, subject_start, subject_end)

    return {
        "issuer_raw": issuer_attrs,
        "issuer": _format_name(issuer_attrs),
        "subject_raw": subject_attrs,
        "subject_cn": subject_attrs.get("commonName"),
        "not_before": not_before,
        "not_after": not_after,
        "signature_algorithm": signature_algorithm,
    }


# --- Lógica de expiración (aislada para poder probarla sin red) ---------


def _expiry_status(not_after: datetime, warn_days: int, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    days_remaining = (not_after - now).days
    return {
        "days_remaining": days_remaining,
        "is_expired": days_remaining < 0,
        "is_expiring_soon": 0 <= days_remaining < warn_days,
    }


# --- Conexión TLS ---------------------------------------------------------


def _empty_result(domain: str, port: int) -> dict:
    return {
        "domain": domain,
        "port": port,
        "success": False,
        "has_https": False,
        "trusted": None,
        "self_signed_or_untrusted": False,
        "verify_error": None,
        "issuer": None,
        "issuer_raw": {},
        "subject_cn": None,
        "subject_raw": {},
        "signature_algorithm": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "is_expired": None,
        "is_expiring_soon": None,
        "cipher_suite": None,
        "errors": [],
    }


def _connect_and_get_cert(
    domain: str, port: int, timeout: float, context: ssl.SSLContext
) -> tuple[bytes | None, dict | None]:
    """
    Abre una conexión TLS a (domain, port) usando `context` y devuelve
    (der_bytes, cipher_info). Puede lanzar excepciones de socket/ssl:
    el llamador decide cómo manejarlas.
    """
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()  # (nombre, version_protocolo, bits_secretos) | None
            cipher_info = None
            if cipher:
                cipher_info = {
                    "name": cipher[0],
                    "tls_version": cipher[1],
                    "secret_bits": cipher[2],
                }
            return der, cipher_info


def check_ssl(
    domain: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    warn_days: int = DEFAULT_WARN_DAYS,
) -> dict:
    """
    Se conecta por TLS a `domain:port`, obtiene el certificado y calcula
    su estado. Nunca lanza excepciones: cualquier fallo (sin HTTPS,
    timeout, cadena no confiable, certificado corrupto, etc.) queda
    registrado en result["errors"] y la función siempre devuelve el
    diccionario estandarizado.
    """
    result = _empty_result(domain, port)

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio/IP inválido o vacío recibido por ssl_check.")
        return result

    der = None
    cipher_info = None
    verify_error = None
    trusted = None

    # --- Intento 1: conexión verificando la cadena de confianza y el hostname ---
    try:
        verifying_context = ssl.create_default_context()
        der, cipher_info = _connect_and_get_cert(domain, port, timeout, verifying_context)
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        verify_error = str(exc)
    except socket.timeout:
        result["errors"].append(f"Timeout al conectar a {domain}:{port}.")
        return result
    except ConnectionRefusedError:
        result["errors"].append(
            f"Conexión rechazada en {domain}:{port} (parece que HTTPS no está habilitado ahí)."
        )
        return result
    except socket.gaierror as exc:
        result["errors"].append(f"No se pudo resolver '{domain}': {exc}")
        return result
    except ssl.SSLError as exc:
        result["errors"].append(
            f"Error SSL al conectar a {domain}:{port} "
            f"(el puerto respondió pero no parece hablar TLS correctamente): {exc}"
        )
        return result
    except OSError as exc:
        result["errors"].append(f"Error de red al conectar a {domain}:{port}: {exc}")
        return result

    # --- Intento 2 (solo si el 1 falló por verificación): reintentar sin validar ---
    if der is None and verify_error is not None:
        try:
            lenient_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            lenient_context.check_hostname = False
            lenient_context.verify_mode = ssl.CERT_NONE
            der, cipher_info = _connect_and_get_cert(domain, port, timeout, lenient_context)
            trusted = False
        except Exception as exc:  # noqa: BLE001 - último recurso, ya sabemos que hay un problema de verificación
            result["errors"].append(
                f"No se pudo obtener el certificado de {domain}:{port} "
                f"ni siquiera sin verificar la cadena: {exc}"
            )
            result["verify_error"] = verify_error
            return result

    if der is None:
        result["errors"].append(f"No se obtuvo certificado de {domain}:{port}.")
        return result

    result["has_https"] = True
    result["trusted"] = trusted
    result["self_signed_or_untrusted"] = trusted is False
    result["verify_error"] = verify_error
    result["cipher_suite"] = cipher_info

    try:
        parsed = _parse_certificate_der(der)
    except Exception as exc:  # noqa: BLE001 - el parser DER es propio; cualquier cert raro no debe tumbar la app
        result["errors"].append(f"No se pudo parsear el certificado de {domain}:{port}: {exc}")
        return result

    expiry = _expiry_status(parsed["not_after"], warn_days)

    result.update(
        {
            "success": True,
            "issuer": parsed["issuer"],
            "issuer_raw": parsed["issuer_raw"],
            "subject_cn": parsed["subject_cn"],
            "subject_raw": parsed["subject_raw"],
            "signature_algorithm": parsed["signature_algorithm"],
            "not_before": parsed["not_before"].isoformat(),
            "not_after": parsed["not_after"].isoformat(),
            "days_remaining": expiry["days_remaining"],
            "is_expired": expiry["is_expired"],
            "is_expiring_soon": expiry["is_expiring_soon"],
        }
    )

    return result


if __name__ == "__main__":
    import json
    import sys

    domain_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = check_ssl(domain_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
