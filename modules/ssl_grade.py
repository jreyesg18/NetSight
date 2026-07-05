"""
modules/ssl_grade.py — Calificación heurística propia (A+ a F) del SSL/TLS.

Responsabilidad única: dado el diccionario YA CALCULADO por
modules/ssl_check.py (check_ssl()), traducirlo a una nota tipo
"SSL Labs" (A+, A, B, C, D, F) con reglas 100% propias, documentadas y
ajustables — sin llamar a ningún servicio externo (no SSL Labs API, no
terceros). No hace ninguna conexión de red ni parsing de certificados:
solo lee campos que ssl_check.py ya extrajo.

------------------------------------------------------------------
DECISIÓN DE DISEÑO: ¿por qué un archivo separado y no una función más
al final de modules/ssl_check.py?
------------------------------------------------------------------
Se optó por un módulo nuevo (ssl_grade.py) en vez de extender
ssl_check.py, por tres razones:

1. Responsabilidad distinta: ssl_check.py hace I/O real (abre sockets
   TLS, negocia handshake, parsea bytes DER de un certificado X.509).
   ssl_grade.py es una función pura de calificación (sin red, sin
   parsing binario) que solo interpreta un dict ya calculado. Mezclar
   ambas cosas en un mismo archivo dificultaría probar cada una por
   separado y violaría "cada módulo hace una sola cosa".
2. Las reglas de calificación son subjetivas y van a cambiar con el
   tiempo (pesos, umbrales, nuevos criterios). Tenerlas aisladas en su
   propio archivo hace mucho más fácil ajustarlas sin arriesgar tocar
   la lógica de conexión/parsing de ssl_check.py, que ya está probada.
3. Es trivialmente testeable sin red: calculate_ssl_grade() es una
   función pura (dict in -> dict out), así que las pruebas son 100%
   sintéticas y deterministas, sin mocks de sockets/DNS. Vive mejor
   como su propio módulo con sus propias pruebas.

Nota de arquitectura: igual que modules/scoring.py, este módulo SÍ
depende de la forma del dict que produce otro módulo (ssl_check.py),
pero no lo importa ni lo ejecuta — solo asume su "contrato" de claves.
Es un acoplamiento de datos, no de código, y es análogo al rol que
scoring.py ya cumple para el resto de los módulos.

Input esperado:
    ssl_result (dict): la salida de modules.ssl_check.check_ssl(), con
    (al menos) estas claves relevantes para la calificación:
        - success (bool), has_https (bool)
        - trusted (bool | None), is_expired (bool | None)
        - days_remaining (int | None)
        - signature_algorithm (str | None)
        - cipher_suite ({"name": str, "tls_version": str, "secret_bits": int} | None)

Función principal:
    calculate_ssl_grade(ssl_result: dict) -> dict

Output devuelto:
    {
        "grade": str,               # "A+", "A", "B", "C", "D" o "F"
        "numeric_score": int,       # 0-100, ya con todas las penalizaciones aplicadas
        "penalties_applied": [
            {"reason": str, "points": int},   # points siempre <= 0
            ...
        ],
    }

------------------------------------------------------------------
REGLAS DE CALIFICACIÓN (ajustables — todas centralizadas en este archivo)
------------------------------------------------------------------
Se parte de 100 puntos y se restan penalizaciones:

  1) Confianza de la cadena y expiración (topes duros):
     - Si el certificado NO es de cadena confiable (autofirmado o no
       verificado): penalización fuerte (-100) y se fuerza un tope
       máximo de nota "F", sin importar el resto de las reglas.
     - Si el certificado ya expiró: mismo tratamiento (-100, tope "F").
     - Ambas condiciones son acumulables (pueden darse las dos a la vez).

  2) Versión de TLS negociada (de ssl_result["cipher_suite"]["tls_version"]):
     - TLSv1.3            -> sin penalización
     - TLSv1.2            -> -10
     - TLSv1.1 / TLSv1.0  -> -40 (protocolos obsoletos/inseguros)
     - Desconocida/ausente -> sin penalización (no se castiga por falta
       de dato; se dice explícitamente en penalties_applied con 0 puntos).

  3) Días restantes para expirar (solo si no está ya expirado):
     - > 30 días   -> sin penalización
     - 8-30 días   -> -5
     - <= 7 días   -> -15

  4) Algoritmo de firma del certificado:
     - ECDSA o RSA con SHA-256/384/512, o Ed25519/Ed448 -> sin penalización
     - Cualquier variante con SHA-1                      -> -30
     - Cualquier variante con MD5 (aún más débil)         -> -30
     - Desconocido/no reconocido -> sin penalización explícita (se
       documenta la incertidumbre en penalties_applied con 0 puntos).

  5) Cipher suite (ssl_result["cipher_suite"]["name"]):
     - Contiene "GCM", "CHACHA20" o "POLY1305" (AEAD moderno) -> sin penalización
     - Cualquier otro caso -> -15
     - Sin dato -> sin penalización explícita (0 puntos, documentado).

El puntaje final se recorta a [0, 100] y, si aplica algún tope duro
(regla 1), se recorta además a un máximo de 49 para garantizar que la
nota resultante sea "F" de forma consistente entre numeric_score y grade.

------------------------------------------------------------------
CONVERSIÓN A LETRA
------------------------------------------------------------------
    >= 90        -> "A+"
    80 - 89      -> "A"
    70 - 79      -> "B"
    60 - 69      -> "C"
    50 - 59      -> "D"
    < 50         -> "F"

Caso especial: si ssl_result indica que ni siquiera se pudo obtener un
certificado (success=False o has_https=False), no hay nada que
calificar — se devuelve directamente grade="F", numeric_score=0, con
una única entrada en penalties_applied explicando que no hubo
certificado que evaluar. Esto es distinto de "certificado inválido":
aquí ni siquiera hubo HTTPS.

Librerías usadas: ninguna externa (función pura de Python). No depende
de otros módulos de modules/ (no importa ssl_check.py; solo documenta
el contrato de claves que espera recibir).
"""

from __future__ import annotations

# --- Constantes de penalización (ajustables) ---

PENALTY_UNTRUSTED = -100
PENALTY_EXPIRED = -100
PENALTY_TLS_1_2 = -10
PENALTY_TLS_OLD = -40
PENALTY_EXPIRING_SOON = -5
PENALTY_EXPIRING_CRITICAL = -15
PENALTY_WEAK_SIGNATURE = -30
PENALTY_NON_AEAD_CIPHER = -15

HARD_CAP_MAX_SCORE = 49  # si hay tope duro (untrusted/expired), el score no puede superar esto

# Versiones de TLS consideradas obsoletas/inseguras.
OBSOLETE_TLS_VERSIONS = {"TLSV1", "TLSV1.0", "TLSV1.1"}

# Subcadenas que delatan un cipher suite con modo AEAD moderno.
AEAD_CIPHER_MARKERS = ("GCM", "CHACHA20", "POLY1305")

# Subcadenas de algoritmo de firma consideradas seguras hoy en día.
STRONG_SIGNATURE_MARKERS = ("SHA256", "SHA384", "SHA512", "ED25519", "ED448")
WEAK_SIGNATURE_MARKERS = ("SHA1",)
BROKEN_SIGNATURE_MARKERS = ("MD5",)


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def calculate_ssl_grade(ssl_result: dict) -> dict:
    """
    Calcula una nota A+ a F a partir del dict ya calculado por
    modules.ssl_check.check_ssl(). Función pura: no hace I/O, no lanza
    excepciones (un ssl_result incompleto/con campos faltantes se trata
    de forma conservadora, sin penalizar por falta de datos salvo en los
    dos topes duros explícitos).
    """
    ssl_result = ssl_result or {}
    penalties: list[dict] = []

    if not ssl_result.get("success") or not ssl_result.get("has_https"):
        return {
            "grade": "F",
            "numeric_score": 0,
            "penalties_applied": [
                {
                    "reason": (
                        "No se obtuvo un certificado SSL/TLS que evaluar "
                        "(sin HTTPS o el chequeo de ssl_check falló)."
                    ),
                    "points": 0,
                }
            ],
        }

    score = 100
    hard_cap = False

    # --- 1) Confianza de la cadena y expiración (topes duros) ---
    if not ssl_result.get("trusted"):
        score += PENALTY_UNTRUSTED
        hard_cap = True
        penalties.append(
            {
                "reason": (
                    "El certificado no es de una cadena de confianza válida "
                    "(autofirmado o no verificado) — nota máxima forzada a 'F'."
                ),
                "points": PENALTY_UNTRUSTED,
            }
        )

    if ssl_result.get("is_expired"):
        score += PENALTY_EXPIRED
        hard_cap = True
        penalties.append(
            {
                "reason": "El certificado ya expiró — nota máxima forzada a 'F'.",
                "points": PENALTY_EXPIRED,
            }
        )

    # --- 2) Versión de TLS ---
    cipher = ssl_result.get("cipher_suite") or {}
    tls_version_raw = cipher.get("tls_version") or ""
    tls_version = tls_version_raw.upper()

    if not tls_version:
        penalties.append(
            {
                "reason": "No se pudo determinar la versión de TLS negociada (sin penalización por falta de datos).",
                "points": 0,
            }
        )
    elif tls_version == "TLSV1.3":
        pass  # sin penalización
    elif tls_version == "TLSV1.2":
        score += PENALTY_TLS_1_2
        penalties.append(
            {
                "reason": "Usa TLS 1.2 en vez de TLS 1.3 (aceptable, pero no la versión más moderna).",
                "points": PENALTY_TLS_1_2,
            }
        )
    elif tls_version in OBSOLETE_TLS_VERSIONS:
        score += PENALTY_TLS_OLD
        penalties.append(
            {
                "reason": f"Usa una versión de TLS obsoleta/insegura ({tls_version_raw}).",
                "points": PENALTY_TLS_OLD,
            }
        )
    else:
        penalties.append(
            {
                "reason": f"Versión de TLS no reconocida explícitamente ({tls_version_raw}); sin penalización por incertidumbre.",
                "points": 0,
            }
        )

    # --- 3) Días restantes para expirar (solo si no está ya expirado) ---
    days_remaining = ssl_result.get("days_remaining")
    if not ssl_result.get("is_expired") and days_remaining is not None:
        if days_remaining > 30:
            pass
        elif 8 <= days_remaining <= 30:
            score += PENALTY_EXPIRING_SOON
            penalties.append(
                {
                    "reason": f"El certificado expira pronto (faltan {days_remaining} días).",
                    "points": PENALTY_EXPIRING_SOON,
                }
            )
        else:  # 0-7 días
            score += PENALTY_EXPIRING_CRITICAL
            penalties.append(
                {
                    "reason": f"El certificado expira muy pronto (faltan {days_remaining} días).",
                    "points": PENALTY_EXPIRING_CRITICAL,
                }
            )

    # --- 4) Algoritmo de firma ---
    signature_algorithm = ssl_result.get("signature_algorithm") or ""
    sig_upper = signature_algorithm.upper()

    if not sig_upper:
        penalties.append(
            {
                "reason": "No se pudo determinar el algoritmo de firma (sin penalización por falta de datos).",
                "points": 0,
            }
        )
    elif any(marker in sig_upper for marker in WEAK_SIGNATURE_MARKERS):
        score += PENALTY_WEAK_SIGNATURE
        penalties.append(
            {
                "reason": f"El algoritmo de firma usa SHA-1, criptográficamente débil ({signature_algorithm}).",
                "points": PENALTY_WEAK_SIGNATURE,
            }
        )
    elif any(marker in sig_upper for marker in BROKEN_SIGNATURE_MARKERS):
        score += PENALTY_WEAK_SIGNATURE
        penalties.append(
            {
                "reason": f"El algoritmo de firma usa MD5, criptográficamente roto ({signature_algorithm}).",
                "points": PENALTY_WEAK_SIGNATURE,
            }
        )
    elif any(marker in sig_upper for marker in STRONG_SIGNATURE_MARKERS):
        pass  # sin penalización (ECDSA/RSA con SHA-256/384/512, o Ed25519/Ed448)
    else:
        penalties.append(
            {
                "reason": f"Algoritmo de firma no reconocido explícitamente ({signature_algorithm}); sin penalización por incertidumbre.",
                "points": 0,
            }
        )

    # --- 5) Cipher suite (modo AEAD moderno) ---
    cipher_name = (cipher.get("name") or "").upper()
    if not cipher_name:
        penalties.append(
            {
                "reason": "No se pudo determinar el cipher suite negociado (sin penalización por falta de datos).",
                "points": 0,
            }
        )
    elif any(marker in cipher_name for marker in AEAD_CIPHER_MARKERS):
        pass  # sin penalización
    else:
        score += PENALTY_NON_AEAD_CIPHER
        penalties.append(
            {
                "reason": f"El cipher suite negociado ({cipher.get('name')}) no usa un modo AEAD moderno (GCM/ChaCha20-Poly1305).",
                "points": PENALTY_NON_AEAD_CIPHER,
            }
        )

    # --- Recorte final ---
    score = max(0, min(100, score))
    if hard_cap:
        score = min(score, HARD_CAP_MAX_SCORE)

    return {
        "grade": _score_to_grade(score),
        "numeric_score": score,
        "penalties_applied": penalties,
    }


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Pruebas sintéticas. calculate_ssl_grade() es una función pura (sin
    # red, sin parsing de certificados), así que estas pruebas no
    # dependen en absoluto de que el sandbox tenga o no acceso a
    # Internet: son 100% deterministas con dicts de ejemplo.
    # Ejecutar con: python modules/ssl_grade.py
    # ------------------------------------------------------------------
    import json

    def run_case(title, ssl_result, expected_grade):
        result = calculate_ssl_grade(ssl_result)
        print(f"=== {title} ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        assert result["grade"] == expected_grade, (
            f"Esperaba '{expected_grade}' pero dio '{result['grade']}' " f"(score={result['numeric_score']})"
        )
        print(f"OK: grade == '{expected_grade}'\n")
        return result

    # --- Caso 1: certificado ideal -> A+ ---
    ideal = {
        "success": True,
        "has_https": True,
        "trusted": True,
        "is_expired": False,
        "days_remaining": 200,
        "signature_algorithm": "ecdsa-with-SHA256",
        "cipher_suite": {"name": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3", "secret_bits": 256},
    }
    run_case("Caso 1: certificado ideal", ideal, "A+")

    # --- Caso 2: TLS 1.2 + cerca de expirar -> debería bajar a B o C ---
    tls12_expiring = {
        "success": True,
        "has_https": True,
        "trusted": True,
        "is_expired": False,
        "days_remaining": 5,  # <=7 dias -> -15
        "signature_algorithm": "sha256WithRSAEncryption",
        "cipher_suite": {"name": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "TLSv1.2", "secret_bits": 128},
    }
    r2 = run_case("Caso 2: TLS 1.2 + expira en 5 días", tls12_expiring, "B")
    # 100 - 10 (tls1.2) - 15 (expira <=7 dias) = 75 -> "B" (70-79)
    assert r2["numeric_score"] == 75

    # --- Caso 3: SHA-1 -> baja fuerte ---
    sha1_cert = {
        "success": True,
        "has_https": True,
        "trusted": True,
        "is_expired": False,
        "days_remaining": 200,
        "signature_algorithm": "sha1WithRSAEncryption",
        "cipher_suite": {"name": "ECDHE-RSA-AES256-GCM-SHA384", "tls_version": "TLSv1.3", "secret_bits": 256},
    }
    r3 = run_case("Caso 3: firma SHA-1", sha1_cert, "B")
    # 100 - 30 (sha1) = 70 -> "B" (borde de rango 70-79), sigue siendo una baja fuerte y notoria
    assert r3["numeric_score"] == 70

    # --- Caso 4: self-signed -> F forzado sin importar el resto ---
    self_signed = {
        "success": True,
        "has_https": True,
        "trusted": False,
        "self_signed_or_untrusted": True,
        "is_expired": False,
        "days_remaining": 300,
        "signature_algorithm": "ecdsa-with-SHA256",
        "cipher_suite": {"name": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3", "secret_bits": 256},
    }
    r4 = run_case("Caso 4: certificado autofirmado", self_signed, "F")
    assert r4["numeric_score"] <= HARD_CAP_MAX_SCORE

    # --- Caso 5 (extra): certificado expirado -> F forzado ---
    expired = {
        "success": True,
        "has_https": True,
        "trusted": True,
        "is_expired": True,
        "days_remaining": -30,
        "signature_algorithm": "sha256WithRSAEncryption",
        "cipher_suite": {"name": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3", "secret_bits": 256},
    }
    run_case("Caso 5 (extra): certificado expirado", expired, "F")

    # --- Caso 6 (extra): sin HTTPS -> F, score 0 ---
    sin_https = {"success": False, "has_https": False}
    r6 = run_case("Caso 6 (extra): sin HTTPS/chequeo fallido", sin_https, "F")
    assert r6["numeric_score"] == 0

    # --- Caso 7 (extra): TLS 1.0 obsoleto + cipher no-AEAD ---
    tls_viejo = {
        "success": True,
        "has_https": True,
        "trusted": True,
        "is_expired": False,
        "days_remaining": 200,
        "signature_algorithm": "sha256WithRSAEncryption",
        "cipher_suite": {"name": "AES256-SHA", "tls_version": "TLSv1", "secret_bits": 256},
    }
    r7 = run_case("Caso 7 (extra): TLS 1.0 + cipher no-AEAD", tls_viejo, "F")
    # 100 - 40 (tls viejo) - 15 (cipher no AEAD) = 45 -> "F" (< 50)
    assert r7["numeric_score"] == 45

    print("TODAS LAS PRUEBAS PASARON")
