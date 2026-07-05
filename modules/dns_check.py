"""
modules/dns_check.py — Resolución DNS y verificación de registros de correo.

Responsabilidad única: dado un dominio, resolver sus registros DNS
principales (A, AAAA, MX, NS, TXT, CNAME) y verificar la presencia y
validez básica de los registros SPF, DKIM y DMARC.

Input esperado:
    domain (str): nombre de dominio ya validado (ver utils/validators.py).
                  Este módulo no vuelve a validar el formato del dominio,
                  asume que ya pasó por utils.validators.validate_target.

Función principal:
    check_dns(domain, timeout=5.0, dkim_selectors=None) -> dict

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "success": bool,               # True si se pudo resolver algo del dominio
        "a_records": [str, ...],
        "aaaa_records": [str, ...],
        "mx_records": [{"preference": int, "exchange": str}, ...],
        "ns_records": [str, ...],
        "cname_records": [str, ...],
        "txt_records": [str, ...],
        "spf": {"found": bool, "value": str | None},
        "dkim": {
            "found": bool,
            "selector_probado": str | None,
            "selectores_intentados": [str, ...],
            "value": str | None,
        },
        "dmarc": {"found": bool, "value": str | None},
        "errors": [str, ...],
    }

LIMITACIÓN IMPORTANTE — detección de DKIM:
    DKIM no se anuncia en un registro fijo del dominio raíz: vive en
    "<selector>._domainkey.<dominio>", y el "selector" lo define quien
    configuró el correo (Google Workspace, Microsoft 365, un ESP, etc.).
    No hay forma de "descubrir" el selector solo con DNS — hay que
    adivinarlo. Este módulo prueba una lista de selectores comunes
    (ver DEFAULT_DKIM_SELECTORS) y reporta el primero que responde con
    un TXT válido. Esto significa que:
        - Un "found: False" NO prueba que el dominio no tenga DKIM
          configurado; solo que ninguno de los selectores probados
          respondió.
        - Un "found: True" sí es una confirmación positiva real.
    Si se conoce el selector exacto, puede pasarse explícitamente vía el
    parámetro `dkim_selectors`.

Librerías usadas: dnspython. No depende de otros módulos de modules/.
"""

from __future__ import annotations

import dns.resolver
import dns.exception


DEFAULT_TIMEOUT = 5.0

# Selectores DKIM más comunes en proveedores de correo populares.
# Esto es una heurística: no cubre todos los casos posibles (ver
# limitación documentada arriba).
DEFAULT_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "dkim",
    "mail",
    "smtp",
    "s1",
    "s2",
    "email",
]


def _empty_result(domain: str) -> dict:
    """Estructura base del diccionario de resultados, todo vacío."""
    return {
        "domain": domain,
        "success": False,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "cname_records": [],
        "txt_records": [],
        "spf": {"found": False, "value": None},
        "dkim": {
            "found": False,
            "selector_probado": None,
            "selectores_intentados": [],
            "value": None,
        },
        "dmarc": {"found": False, "value": None},
        "errors": [],
    }


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _txt_to_text(rdata) -> str:
    """
    Convierte un rdata TXT en un string plano. Un registro TXT puede
    estar compuesto de varios "character-strings"; se concatenan para
    obtener el valor completo (p. ej. registros SPF/DKIM largos que
    algunos proveedores dividen en varios trozos).
    """
    if hasattr(rdata, "strings"):
        parts = []
        for chunk in rdata.strings:
            if isinstance(chunk, bytes):
                parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(str(chunk))
        return "".join(parts)
    return rdata.to_text().strip('"')


def _resolve(
    resolver: dns.resolver.Resolver, name: str, record_type: str
) -> tuple[list[str], str | None]:
    """
    Resuelve `name` para el tipo `record_type` usando `resolver`.

    Devuelve (valores, error):
        - valores: lista de strings con el contenido de cada registro
          (ya "aplanado" a texto). Lista vacía si no hay registros de
          ese tipo (esto NO se considera un error).
        - error: mensaje descriptivo si ocurrió un problema real de
          resolución (dominio inexistente, timeout, sin servidores de
          nombres, error inesperado). None si todo salió bien (incluso
          si no había registros de ese tipo).
    """
    try:
        answer = resolver.resolve(name, record_type)
        if record_type == "TXT":
            values = [_txt_to_text(r) for r in answer]
        else:
            values = [r.to_text().rstrip(".") for r in answer]
        return values, None
    except dns.resolver.NXDOMAIN:
        return [], f"NXDOMAIN: '{name}' no existe."
    except dns.resolver.NoAnswer:
        # El dominio existe pero no tiene registros de este tipo.
        # No es un error: simplemente no hay nada que reportar.
        return [], None
    except dns.resolver.NoNameservers:
        return [], f"No hay servidores de nombres disponibles para {record_type} en '{name}'."
    except dns.exception.Timeout:
        return [], f"Timeout al resolver {record_type} para '{name}'."
    except Exception as exc:  # noqa: BLE001 - queremos capturar cualquier fallo de red/parseo
        return [], f"Error inesperado al resolver {record_type} para '{name}': {exc}"


def _finalize_errors(errors: list[str], domain: str) -> list[str]:
    """
    Post-procesa la lista de errores antes de devolverla:

    1) Cuando el dominio base no existe, dnspython lanza NXDOMAIN para
       cada uno de los 6 tipos de registro consultados (A, AAAA, MX, NS,
       CNAME, TXT), lo que sin este paso deja el mismo mensaje repetido
       hasta 6 veces en "errors". Aquí se colapsa a un único mensaje
       claro: "El dominio '<domain>' no existe (NXDOMAIN).".
    2) Como red de seguridad general, también se eliminan duplicados
       exactos de cualquier otro mensaje (p. ej. si dos tipos de registro
       distintos fallan con el mismo texto de error), preservando el
       orden de aparición.
    """
    nx_message = f"NXDOMAIN: '{domain}' no existe."
    deduped: list[str] = []
    seen: set[str] = set()
    nx_added = False

    for err in errors:
        if err == nx_message:
            if not nx_added:
                deduped.append(f"El dominio '{domain}' no existe (NXDOMAIN).")
                nx_added = True
            continue
        if err in seen:
            continue
        seen.add(err)
        deduped.append(err)

    return deduped


def _parse_mx(raw_mx_values: list[str]) -> list[dict]:
    """
    Convierte líneas de texto de MX (p. ej. "10 mail.example.com") en
    diccionarios {"preference": int, "exchange": str}, ordenados por
    preferencia ascendente (menor = mayor prioridad).
    """
    parsed = []
    for value in raw_mx_values:
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            parsed.append({"preference": int(parts[0]), "exchange": parts[1].rstrip(".")})
        else:
            # Formato inesperado: lo dejamos igual para no perder información.
            parsed.append({"preference": None, "exchange": value})
    parsed.sort(key=lambda item: (item["preference"] is None, item["preference"]))
    return parsed


def check_dns(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    dkim_selectors: list[str] | None = None,
) -> dict:
    """
    Resuelve los registros DNS principales de `domain` y evalúa la
    configuración de SPF, DKIM y DMARC.

    Nunca lanza excepciones: cualquier fallo de resolución queda
    registrado dentro de result["errors"] y la función siempre devuelve
    el diccionario estandarizado.

    Args:
        domain: dominio ya validado (sin esquema, sin "www.").
        timeout: segundos de espera por consulta DNS.
        dkim_selectors: lista opcional de selectores DKIM a probar. Si
            no se pasa, se usa DEFAULT_DKIM_SELECTORS.

    Returns:
        dict con la estructura documentada en el encabezado del módulo.
    """
    result = _empty_result(domain)

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio inválido o vacío recibido por dns_check.")
        return result

    resolver = _make_resolver(timeout)
    any_success = False

    # --- A ---
    values, err = _resolve(resolver, domain, "A")
    result["a_records"] = values
    if values:
        any_success = True
    if err:
        result["errors"].append(err)

    # --- AAAA ---
    values, err = _resolve(resolver, domain, "AAAA")
    result["aaaa_records"] = values
    if values:
        any_success = True
    if err:
        result["errors"].append(err)

    # --- MX ---
    values, err = _resolve(resolver, domain, "MX")
    result["mx_records"] = _parse_mx(values)
    if values:
        any_success = True
    if err:
        result["errors"].append(err)

    # --- NS ---
    values, err = _resolve(resolver, domain, "NS")
    result["ns_records"] = values
    if values:
        any_success = True
    if err:
        result["errors"].append(err)

    # --- CNAME ---
    values, err = _resolve(resolver, domain, "CNAME")
    result["cname_records"] = values
    if values:
        any_success = True
    if err:
        result["errors"].append(err)

    # --- TXT (crudo + detección de SPF) ---
    txt_values, err = _resolve(resolver, domain, "TXT")
    result["txt_records"] = txt_values
    if txt_values:
        any_success = True
    if err:
        result["errors"].append(err)

    spf_value = next(
        (t for t in txt_values if t.strip().lower().startswith("v=spf1")), None
    )
    result["spf"]["found"] = spf_value is not None
    result["spf"]["value"] = spf_value

    # --- DMARC (_dmarc.<dominio>) ---
    dmarc_name = f"_dmarc.{domain}"
    dmarc_values, err = _resolve(resolver, dmarc_name, "TXT")
    if err and not err.startswith("NXDOMAIN"):
        # NXDOMAIN aquí solo significa "no hay DMARC configurado", no es
        # un error real que valga la pena reportar como falla de red.
        result["errors"].append(err)
    dmarc_value = next(
        (t for t in dmarc_values if t.strip().lower().startswith("v=dmarc1")), None
    )
    result["dmarc"]["found"] = dmarc_value is not None
    result["dmarc"]["value"] = dmarc_value

    # --- DKIM (heurístico: probar selectores comunes) ---
    selectors = dkim_selectors if dkim_selectors else DEFAULT_DKIM_SELECTORS
    result["dkim"]["selectores_intentados"] = list(selectors)

    for selector in selectors:
        dkim_name = f"{selector}._domainkey.{domain}"
        dkim_values, dkim_err = _resolve(resolver, dkim_name, "TXT")
        # Los NXDOMAIN/NoAnswer por selector son esperados y se ignoran
        # silenciosamente: solo probamos "a ver si este selector existe".
        if dkim_values:
            result["dkim"]["found"] = True
            result["dkim"]["selector_probado"] = selector
            result["dkim"]["value"] = dkim_values[0]
            break
        if dkim_err and not dkim_err.startswith("NXDOMAIN"):
            # Timeout / sin nameservers sí es relevante reportarlo, pero
            # no detiene la búsqueda de otros selectores.
            result["errors"].append(f"DKIM selector '{selector}': {dkim_err}")

    # Deduplicar errores repetidos (típicamente NXDOMAIN del dominio base,
    # que dnspython reporta una vez por cada tipo de registro consultado).
    result["errors"] = _finalize_errors(result["errors"], domain)

    # `success` refleja si el dominio pudo resolverse de alguna forma.
    # Si obtuvimos al menos un registro (A/AAAA/MX/NS/CNAME/TXT) lo
    # consideramos exitoso. Si no obtuvimos ninguno, solo es exitoso
    # cuando tampoco hubo errores de resolución (dominio válido pero
    # sin registros configurados); si hubo NXDOMAIN/timeout/etc. en el
    # dominio base, se marca como no exitoso.
    result["success"] = any_success or not result["errors"]

    return result


if __name__ == "__main__":
    import json
    import sys

    domain_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = check_dns(domain_arg)
    print(json.dumps(output, indent=2, ensure_ascii=False))
