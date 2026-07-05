# NetSight

NetSight es una aplicación web (Streamlit) de análisis heurístico de dominios y sitios web, en el mismo espíritu que herramientas tipo "web-check", pero construida desde cero con librerías nativas/estándar de Python — sin depender de Wappalyzer ni de ninguna librería de terceros con licencia restrictiva (GPL o similar).

Dado un dominio o una IP, NetSight resuelve su configuración DNS, revisa su antigüedad vía WHOIS, valida su certificado SSL/TLS y lo califica con una nota propia estilo SSL Labs, escanea un rango de puertos, audita los security headers HTTP, detecta tecnologías con firmas propias, y combina todo en un score heurístico de 0 a 100 — todo mostrado en una sola página con gráficos y exportable a JSON.

## Características principales

- **Resolución DNS (`modules/dns_check.py`)**: registros A, AAAA, MX, NS, CNAME y TXT, más detección de SPF, DKIM (contra una lista de selectores comunes, documentando la limitación de no poder "descubrir" el selector real) y DMARC.
- **Propagación DNS (`modules/dns_propagation.py`)**: consulta el mismo registro contra 4 resolvers públicos independientes (Google, Cloudflare, Quad9, OpenDNS) y evalúa si todos coinciden, dejando claro que una discrepancia puede ser propagación incompleta o simplemente balanceo de carga/CDN.
- **WHOIS (`modules/whois_check.py`)**: registrador, país, antigüedad del dominio (días/años), días para expirar, y detección heurística de privacidad (GDPR/proxy de registro).
- **Certificado SSL/TLS (`modules/ssl_check.py`)**: emisor, a quién fue emitido, algoritmo de firma, fechas de validez, cipher suite negociado, y manejo explícito de certificados autofirmados/no confiables o dominios sin HTTPS, sin depender de ninguna librería externa para parsear el certificado (parser ASN.1/DER propio).
- **Nota SSL propia A+ a F (`modules/ssl_grade.py`)**: calificación estilo SSL Labs calculada 100% localmente a partir de los datos de `ssl_check.py` (versión de TLS, algoritmo de firma, cipher suite, expiración), con el detalle de cada penalización aplicada.
- **Escaneo de puertos (`modules/port_scan.py`)**: escaneo concurrente (hilos) de un rango configurable, con límite de seguridad de puertos por escaneo y mapeo a servicios comunes (SSH, HTTPS, MySQL, RDP, etc.).
- **Security headers (`modules/headers_check.py`)**: presencia y valor de Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy y Permissions-Policy, cada uno con una explicación de qué protege.
- **Detección de tecnologías (`modules/tech_detect.py`)**: heurísticas propias (headers, cookies, patrones en HTML) para WordPress, WooCommerce, Nginx, Apache, Cloudflare, React, Next.js, PHP, Express, Django, Google Analytics y Google Tag Manager, con evidencia transparente de qué disparó cada detección.
- **Score heurístico combinado (`modules/scoring.py`)**: pondera SSL, security headers, SPF/DKIM/DMARC, puertos de riesgo abiertos y antigüedad del dominio en un puntaje 0-100 con nivel (Excelente/Bueno/Regular/Débil).
- **Exportación a JSON (`utils/export.py`)**: descarga de todos los resultados combinados en un único archivo `.json`, con metadata de versión y fecha de análisis.
- **Validación de input (`utils/validators.py`)**: normalización y validación de dominios/IPs antes de ejecutar cualquier análisis.

## Sin dependencias restrictivas

Todo el análisis corre con librerías nativas de Python (`ssl`, `socket`, `re`, `ipaddress`, `concurrent.futures`, `json`, `datetime`) o librerías de bajo nivel con licencias permisivas (`dnspython`, `python-whois`, `requests`). NetSight **no usa Wappalyzer ni ninguna librería GPL**: la detección de tecnologías, el parseo de certificados y la calificación SSL son heurísticas e implementaciones propias, escritas específicamente para este proyecto.

## Stack técnico

| Función | Librería |
|---|---|
| Interfaz web, estado de sesión, gráfico gauge del score | `streamlit`, `plotly` |
| Resolución DNS y propagación entre resolvers | `dnspython` (`dns.resolver`, `dns.exception`) |
| Consultas WHOIS | `python-whois` |
| Conexión TLS, extracción y parseo de certificados, cálculo de nota SSL | `ssl`, `socket` (nativas de Python) |
| Escaneo de puertos concurrente | `socket`, `concurrent.futures.ThreadPoolExecutor` (nativas) |
| Peticiones HTTP/HTTPS (headers y detección de tecnologías) | `requests` |
| Validación de dominios/IPs | `re`, `ipaddress` (nativas) |
| Exportación de resultados | `json`, `datetime` (nativas) |

## Instalación

Requiere Python 3.9 o superior.

1. Clona o descarga este repositorio y entra a la carpeta del proyecto:

   ```bash
   cd netsight
   ```

2. (Recomendado) crea un entorno virtual:

   ```bash
   python -m venv venv
   source venv/bin/activate   # En Windows: venv\Scripts\activate
   ```

3. Instala las dependencias:

   ```bash
   pip install -r requirements.txt
   ```

## Uso

Desde la carpeta `netsight/`:

```bash
streamlit run app.py
```

Esto abre la aplicación en el navegador (por defecto en `http://localhost:8501`). Desde ahí:

1. Ingresa un dominio o IP (acepta `ejemplo.com`, `https://www.ejemplo.com`, `8.8.8.8`, etc. — se normaliza automáticamente).
2. Ajusta el rango de puertos a escanear si lo necesitas (y, opcionalmente, hilos/timeout en "Opciones avanzadas").
3. Presiona **🚀 Analizar**.
4. Revisa el score general arriba y cada sección de resultados (DNS, Propagación DNS, WHOIS, SSL, Puertos, Headers, Tecnologías) en los expanders de la página.
5. Descarga el reporte completo con el botón **📥 Descargar reporte en JSON**.

## Estructura del proyecto

```
netsight/
├── app.py                      # Entry point de Streamlit (solo UI, sin lógica de negocio)
├── modules/
│   ├── __init__.py
│   ├── dns_check.py            # Resolución DNS + SPF/DKIM/DMARC
│   ├── dns_propagation.py      # Consistencia entre resolvers DNS públicos
│   ├── whois_check.py          # Antigüedad, registrador, expiración, privacidad
│   ├── ssl_check.py            # Certificado, días para expirar, cipher, parser DER propio
│   ├── ssl_grade.py            # Nota SSL propia (A+ a F) a partir de ssl_check
│   ├── port_scan.py            # Escaneo de puertos configurable con threading
│   ├── headers_check.py        # Security headers (CSP, X-Frame-Options, etc.)
│   ├── tech_detect.py          # Heurísticas propias (headers/cookies/patrones HTML)
│   └── scoring.py              # Calcula el score heurístico general 0-100
├── utils/
│   ├── __init__.py
│   ├── validators.py           # Validar formato de dominio/IP antes de escanear
│   └── export.py                # Serializar resultados combinados a JSON descargable
├── requirements.txt
└── README.md
```

### Reglas de diseño

- Cada módulo en `modules/` hace una sola cosa y no depende de los demás módulos directamente. Todos reciben un dominio/IP (o, en el caso de `ssl_grade.py` y `scoring.py`, el diccionario ya calculado por otro módulo) y devuelven un diccionario de resultados estandarizado.
- `app.py` no contiene lógica de negocio: solo llama a los módulos en orden y muestra los resultados con Streamlit.
- `scoring.py` es el único módulo que conoce a los demás — recibe los resultados de todos y calcula un puntaje combinado.
- El input (dominio/IP) siempre se valida con `utils/validators.py` antes de ejecutar cualquier análisis.

## Aviso legal

**Esta herramienta debe usarse únicamente sobre dominios/IPs de tu propiedad o con autorización explícita del propietario.** El escaneo de puertos y otras técnicas de reconocimiento realizadas sin autorización pueden constituir un delito en algunas jurisdicciones (por ejemplo, bajo leyes como la Computer Fraud and Abuse Act en EE. UU. o equivalentes locales), incluso cuando la intención sea inofensiva. NetSight no implementa ningún control de acceso o verificación de autorización: esa responsabilidad es exclusivamente de quien lo utiliza.

## Licencia

MIT

## Autor

Javier Reyes
