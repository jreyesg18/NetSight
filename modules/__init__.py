"""
modules — Paquete que agrupa los módulos de análisis heurístico de NetSight.

Cada módulo en este paquete es independiente: recibe un dominio/IP como
input y devuelve un diccionario de resultados estandarizado. Ningún módulo
(excepto scoring.py) debe importar o depender de otro módulo de este paquete.

Módulos:
    - dns_check:        Resolución DNS + registros SPF/DKIM/DMARC.
    - dns_propagation:  Consulta el mismo registro contra varios resolvers
                        DNS públicos (Google, Cloudflare, Quad9, OpenDNS)
                        y compara si todos coinciden (propagación DNS).
    - whois_check:      Antigüedad del dominio, registrador, fecha de expiración.
    - ssl_check:        Certificado SSL/TLS, días para expirar, cipher suite.
    - ssl_grade:        Calificación heurística propia (A+ a F) a partir del
                        dict de ssl_check, sin depender de SSL Labs ni de
                        ningún servicio externo.
    - port_scan:        Escaneo configurable de puertos con threading.
    - headers_check:    Security headers HTTP (CSP, X-Frame-Options, etc.).
    - tech_detect:      Heurísticas propias de detección de tecnologías
                        (headers, cookies, patrones en HTML).
    - scoring:          Único módulo que conoce a los demás; combina sus
                        resultados en un puntaje heurístico 0-100.
"""
