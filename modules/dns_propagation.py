"""
modules/dns_propagation.py — Verificación de propagación DNS.

Responsabilidad única: dado un dominio, consultar el mismo registro DNS
contra varios resolvers públicos independientes (Google, Cloudflare,
Quad9, OpenDNS) y comparar si todos devuelven la misma respuesta. Esto
sirve para detectar propagación DNS incompleta o inconsistente (p. ej.
justo después de cambiar de proveedor de hosting o de nameservers).

Input esperado:
    domain (str): dominio ya validado (ver utils/validators.py). Este
                  módulo no vuelve a validar el formato del dominio.

Función principal:
    check_dns_propagation(domain, record_type="A", timeout=5.0) -> dict

Tipos de registro soportados: A, AAAA, MX, NS, TXT.

Output devuelto (dict estandarizado):
    {
        "domain": str,
        "record_type": str,
        "success": bool,        # True si al menos un resolver respondió
        "is_consistent": bool,  # True si todos los resolvers que respondieron
                                 # coinciden en los mismos valores
        "resolvers": {
            "Google": {
                "ip": "8.8.8.8",
                "responded": bool,
                "values": [str, ...],
                "response_time_ms": float | None,
                "error": str | None,
            },
            "Cloudflare": {...},
            "Quad9": {...},
            "OpenDNS": {...},
        },
        "errors": [str, ...],
    }

Notas de diseño:
    - Cada resolver se consulta con su propia instancia de
      dns.resolver.Resolver(configure=False), apuntando exclusivamente a
      ese nameserver — así la respuesta de un resolver nunca se mezcla
      con la de otro.
    - NXDOMAIN y "sin registros de este tipo" (NoAnswer) se consideran
      respuestas VÁLIDAS del resolver (responded=True, values=[]): el
      resolver sí contestó, solo que no hay nada que reportar. Un
      timeout, un resolver inalcanzable o cualquier otro error de red sí
      se registra como responded=False con el detalle en "error", pero
      NUNCA interrumpe la consulta a los demás resolvers.
    - La comparación de consistencia ignora el orden de los valores
      (p. ej. varios registros A en orden distinto por round-robin DNS
      no cuentan como inconsistencia), pero si algún resolver está de
      más/de menos en el conjunto de valores, sí se marca inconsistente.
    - IMPORTANTE — ambigüedad de is_consistent=False: que los resolvers
      no coincidan NO significa necesariamente que algo esté mal. Puede
      deberse a propagación DNS incompleta (p. ej. si el dominio cambió
      de nameservers/IP hace poco y aún no todos los resolvers tienen la
      respuesta actualizada), pero también puede ser el comportamiento
      normal y esperado de sitios con balanceo de carga geográfico o CDN
      (Google, Cloudflare, AWS y sitios grandes en general suelen
      devolver IPs distintas según desde dónde se consulte, por diseño).
      Este módulo no tiene forma de distinguir automáticamente un caso
      del otro sin contexto adicional (p. ej. saber si el dominio usa
      una CDN, o si el usuario acaba de migrar de proveedor), así que
      is_consistent=False debe leerse como "hay que revisar con más
      contexto", no como "hay un problema".
    - Si menos de 2 resolvers respondieron, no hay suficientes puntos de
      vista independientes para afirmar que la propagación es
      consistente, así que is_consistent se marca False con una nota en
      "errors" explicando el motivo (no es lo mismo que "inconsistente
      porque los valores difieren").

LIMITACIÓN DE ESTE ENTORNO DE DESARROLLO:
    Las pruebas manuales al final de este archivo (bajo
    `if __name__ == "__main__":`) se ejecutaron en un sandbox sin acceso
    real a Internet (sin salida UDP/TCP a redes externas), así que no
    pudieron validarse resultados reales de propagación contra
    google.com u otro dominio. Esas pruebas solo confirman que el código
    compila, importa y se ejecuta sin errores de sintaxis/tipos,
    devolviendo la estructura esperada con success=False y los errores
    de red correspondientes. La validación funcional con datos DNS
    reales debe hacerla el usuario en su propio entorno con acceso a
    Internet.

Librerías usadas: dnspython, time (stdlib). No depende de otros módulos
de modules/ (en particular, no reutiliza dns_check.py a propósito, para
mantener cada módulo independiente).
"""

from __future__ import annotations

import time

import dns.exception
import dns.resolver

DEFAULT_TIMEOUT = 5.0

# Resolvers DNS públicos a consultar. Fácil de extender: solo agregar
# una entrada más "Nombre": "IP".
PUBLIC_RESOLVERS: dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

SUPPORTED_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def _txt_to_text(rdata) -> str:
    """Aplana un rdata TXT (posiblemente multi-string) a un solo string."""
    if hasattr(rdata, "strings"):
        parts = []
        for chunk in rdata.strings:
            parts.append(chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk))
        return "".join(parts)
    return rdata.to_text().strip('"')


def _rdata_to_text(rdata, record_type: str) -> str:
    """Convierte un rdata a texto plano según el tipo de registro."""
    if record_type == "TXT":
        return _txt_to_text(rdata)
    if record_type == "MX":
        # "10 mail.example.com" (sin el punto final)
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    return rdata.to_text().rstrip(".")


def _empty_resolver_result(ip: str) -> dict:
    return {
        "ip": ip,
        "responded": False,
        "values": [],
        "response_time_ms": None,
        "error": None,
    }


def _query_resolver(name: str, ip: str, domain: str, record_type: str, timeout: float) -> dict:
    """
    Consulta `domain` (tipo `record_type`) usando exclusivamente el
    nameserver `ip`. Nunca lanza excepciones: cualquier fallo queda
    reflejado en el dict devuelto con responded=False.
    """
    result = _empty_resolver_result(ip)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    start = time.perf_counter()
    try:
        answer = resolver.resolve(domain, record_type)
        elapsed_ms = (time.perf_counter() - start) * 1000
        values = [_rdata_to_text(rdata, record_type) for rdata in answer]
        result["responded"] = True
        result["values"] = values
        result["response_time_ms"] = round(elapsed_ms, 2)
        return result
    except dns.resolver.NXDOMAIN:
        # El resolver SÍ contestó: el dominio no existe según su vista.
        elapsed_ms = (time.perf_counter() - start) * 1000
        result["responded"] = True
        result["values"] = []
        result["response_time_ms"] = round(elapsed_ms, 2)
        return result
    except dns.resolver.NoAnswer:
        # El resolver SÍ contestó: el dominio existe pero sin registros
        # de este tipo.
        elapsed_ms = (time.perf_counter() - start) * 1000
        result["responded"] = True
        result["values"] = []
        result["response_time_ms"] = round(elapsed_ms, 2)
        return result
    except dns.resolver.NoNameservers as exc:
        result["error"] = f"El resolver {name} ({ip}) rechazó o no pudo resolver la consulta: {exc}"
        return result
    except dns.exception.Timeout:
        result["error"] = f"Timeout esperando respuesta de {name} ({ip})."
        return result
    except Exception as exc:  # noqa: BLE001 - un resolver caído no debe tumbar a los demás
        result["error"] = f"Error inesperado consultando a {name} ({ip}): {exc}"
        return result


def _values_match(values_a: list[str], values_b: list[str]) -> bool:
    """Compara dos listas de valores DNS ignorando el orden (p. ej. A
    records en distinto orden por round-robin no cuentan como
    inconsistencia)."""
    return frozenset(values_a) == frozenset(values_b)


def check_dns_propagation(
    domain: str,
    record_type: str = "A",
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Consulta `record_type` de `domain` contra cada resolver en
    PUBLIC_RESOLVERS por separado y evalúa si todos coinciden
    (propagación DNS consistente).

    Nunca lanza excepciones: cualquier fallo de un resolver individual
    queda registrado en resolvers[nombre]["error"] sin detener la
    consulta a los demás; la función siempre devuelve el diccionario
    estandarizado.
    """
    record_type = (record_type or "A").upper()

    result = {
        "domain": domain,
        "record_type": record_type,
        "success": False,
        "is_consistent": False,
        "resolvers": {name: _empty_resolver_result(ip) for name, ip in PUBLIC_RESOLVERS.items()},
        "errors": [],
    }

    if not domain or not isinstance(domain, str):
        result["errors"].append("Dominio inválido o vacío recibido por dns_propagation.")
        return result

    if record_type not in SUPPORTED_RECORD_TYPES:
        result["errors"].append(
            f"Tipo de registro '{record_type}' no soportado. "
            f"Usa uno de: {', '.join(SUPPORTED_RECORD_TYPES)}."
        )
        return result

    for name, ip in PUBLIC_RESOLVERS.items():
        resolver_result = _query_resolver(name, ip, domain, record_type, timeout)
        result["resolvers"][name] = resolver_result
        if not resolver_result["responded"] and resolver_result["error"]:
            result["errors"].append(resolver_result["error"])

    responded = {
        name: r for name, r in result["resolvers"].items() if r["responded"]
    }

    result["success"] = len(responded) > 0

    if len(responded) == 0:
        result["is_consistent"] = False
        result["errors"].append(
            "Ningún resolver respondió; no se pudo evaluar la propagación DNS "
            "(posiblemente no hay salida de red a resolvers DNS públicos desde este entorno)."
        )
    elif len(responded) == 1:
        only_name = next(iter(responded))
        result["is_consistent"] = False
        result["errors"].append(
            f"Solo '{only_name}' respondió; se necesitan al menos 2 resolvers "
            f"para confirmar consistencia de propagación."
        )
    else:
        names = list(responded.keys())
        reference_values = responded[names[0]]["values"]
        result["is_consistent"] = all(
            _values_match(reference_values, responded[name]["values"]) for name in names[1:]
        )
        if not result["is_consistent"]:
            result["errors"].append(
                "Los resolvers devolvieron valores distintos. Esto puede indicar "
                "propagación DNS incompleta (recién cambiaste el DNS) o ser un "
                "comportamiento normal de sitios con balanceo de carga "
                "geográfico/CDN (común en sitios grandes como Google, Cloudflare, "
                "AWS). No se puede determinar automáticamente cuál es el caso "
                "sin contexto adicional."
            )

    return result


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Pruebas manuales. Ejecutar con: python modules/dns_propagation.py
    #
    # IMPORTANTE: este archivo se probó dentro de un sandbox de
    # desarrollo SIN acceso real a Internet (no hay salida UDP/TCP hacia
    # redes externas — se confirmó que ni siquiera se puede alcanzar
    # 8.8.8.8:53). Por lo tanto, estas pruebas solo verifican que:
    #   1) el módulo importa y compila sin errores de sintaxis/tipos,
    #   2) check_dns_propagation() nunca lanza excepciones aunque todos
    #      los resolvers fallen por falta de red,
    #   3) la estructura del diccionario devuelto es la esperada.
    # NO validan que la lógica de comparación de consistencia sea
    # correcta contra datos DNS reales — para eso, correr este mismo
    # script en un entorno con acceso a Internet (por ejemplo, tu
    # máquina local) y revisar los resultados contra un dominio conocido
    # como "google.com".
    # ------------------------------------------------------------------
    import json

    print("=== Prueba 1: registro A de google.com ===")
    r1 = check_dns_propagation("google.com", record_type="A")
    print(json.dumps(r1, indent=2, ensure_ascii=False))
    assert set(r1["resolvers"].keys()) == set(PUBLIC_RESOLVERS.keys())
    assert isinstance(r1["success"], bool)
    assert isinstance(r1["is_consistent"], bool)

    print("\n=== Prueba 2: registro MX de google.com ===")
    r2 = check_dns_propagation("google.com", record_type="MX", timeout=2.0)
    print(json.dumps(r2, indent=2, ensure_ascii=False))

    print("\n=== Prueba 3: tipo de registro no soportado ===")
    r3 = check_dns_propagation("google.com", record_type="SRV")
    print(json.dumps(r3, indent=2, ensure_ascii=False))
    assert r3["success"] is False
    assert "no soportado" in r3["errors"][0]

    print("\n=== Prueba 4: dominio vacío ===")
    r4 = check_dns_propagation("")
    print(json.dumps(r4, indent=2, ensure_ascii=False))
    assert r4["success"] is False

    print("\nPruebas de compilación/estructura completadas sin excepciones.")
    print(
        "Recordatorio: valida los resultados de propagación reales en un "
        "entorno con acceso a Internet."
    )
