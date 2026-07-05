"""
app.py — Entry point de Streamlit para NetSight.

Responsabilidad única: interfaz de usuario. Este archivo NO contiene
lógica de negocio ni de análisis. Su trabajo es:
    1. Recibir el input del usuario (dominio o IP) vía widgets de Streamlit.
    2. Validar el input usando utils.validators.
    3. Invocar los módulos de modules/ (dns_check, dns_propagation,
       whois_check, ssl_check, ssl_grade, port_scan, headers_check,
       tech_detect) para obtener resultados.
    4. Pasar los resultados combinados a modules/scoring.py para obtener
       el puntaje heurístico final.
    5. Renderizar todo (tablas, gráficos con Plotly, tarjetas de estado)
       en la interfaz de Streamlit.
    6. Ofrecer los resultados combinados para descarga en JSON vía
       utils/export.py (solo serialización, ninguna lógica de análisis).

No implementar aquí: parsing de DNS, WHOIS, SSL, escaneo de puertos,
detección de tecnologías, cálculo de score/nota SSL, ni el armado del
JSON de exportación — todo eso vive en modules/ y utils/. Este archivo
solo ORQUESTA (llama a los módulos en orden) y MUESTRA los diccionarios
de resultados que ya vienen calculados.
"""

from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from modules import (
    dns_check,
    dns_propagation,
    headers_check,
    port_scan,
    scoring,
    ssl_check,
    ssl_grade,
    tech_detect,
    whois_check,
)
from utils import export, validators

# ---------------------------------------------------------------------
# Configuración de página (debe ser la primera llamada de Streamlit)
# ---------------------------------------------------------------------
st.set_page_config(
    page_title="NetSight",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Límites de escaneo de puertos definidos en modules/port_scan.py — la UI
# los reutiliza tal cual, no redefine ninguna regla propia.
PORT_MIN = port_scan.MIN_PORT
PORT_MAX = port_scan.MAX_PORT
MAX_PORTS_PER_SCAN = port_scan.DEFAULT_MAX_PORTS_PER_SCAN


def _nivel_visual(nivel: str) -> tuple[str, str]:
    """Emoji + color hex asociados a cada nivel de score (verde/amarillo/rojo)."""
    mapping = {
        "Excelente": ("🟢", "#2ECC71"),
        "Bueno": ("🟢", "#8BC34A"),
        "Regular": ("🟡", "#F1C40F"),
        "Débil": ("🔴", "#E74C3C"),
    }
    return mapping.get(nivel, ("⚪", "#95A5A6"))


def _render_gauge(score_total: int, color: str) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score_total,
            number={"suffix": " / 100"},
            title={"text": "Score heurístico NetSight"},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 40], "color": "#FADBD8"},
                    {"range": [40, 60], "color": "#FCF3CF"},
                    {"range": [60, 80], "color": "#D5F5E3"},
                    {"range": [80, 100], "color": "#A9DFBF"},
                ],
                "threshold": {
                    "line": {"color": "#333333", "width": 3},
                    "thickness": 0.8,
                    "value": score_total,
                },
            },
        )
    )
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=50, b=10))
    return fig


def _render_errors_and_warnings(result: dict) -> None:
    for err in result.get("errors", []) or []:
        st.error(err)
    for warn in result.get("warnings", []) or []:
        st.warning(warn)


# ---------------------------------------------------------------------
# Encabezado
# ---------------------------------------------------------------------
st.title("🔍 NetSight")
st.caption(
    "Análisis heurístico de dominios y sitios web — DNS, WHOIS, SSL, puertos, "
    "headers de seguridad y tecnologías. 100% librerías nativas de Python."
)

# ---------------------------------------------------------------------
# Formulario de entrada
# ---------------------------------------------------------------------
input_col, button_col = st.columns([4, 1])

with input_col:
    target_input = st.text_input(
        "Dominio o IP a analizar",
        placeholder="ejemplo.com, https://www.ejemplo.com, 8.8.8.8...",
        label_visibility="visible",
    )

with button_col:
    st.write("")  # espaciador para alinear el botón con el input
    st.write("")
    analizar_clicked = st.button("🚀 Analizar", type="primary", width="stretch")

port_start, port_end = st.slider(
    "Rango de puertos a escanear",
    min_value=PORT_MIN,
    max_value=PORT_MAX,
    value=(1, 1024),
)
st.caption(
    f"Límite de seguridad: máximo {MAX_PORTS_PER_SCAN} puertos por escaneo. "
    f"Rangos más grandes se truncan automáticamente."
)

with st.expander("⚙️ Opciones avanzadas"):
    adv_col1, adv_col2 = st.columns(2)
    with adv_col1:
        max_threads = st.number_input(
            "Hilos concurrentes para el escaneo de puertos",
            min_value=1,
            max_value=500,
            value=port_scan.DEFAULT_MAX_THREADS,
            step=10,
        )
    with adv_col2:
        port_timeout = st.number_input(
            "Timeout por puerto (segundos)",
            min_value=0.1,
            max_value=10.0,
            value=port_scan.DEFAULT_TIMEOUT,
            step=0.1,
        )

st.divider()

# ---------------------------------------------------------------------
# Estado persistente entre reruns de Streamlit
# ---------------------------------------------------------------------
if "netsight_results" not in st.session_state:
    st.session_state.netsight_results = None
if "netsight_target" not in st.session_state:
    st.session_state.netsight_target = None

# ---------------------------------------------------------------------
# Ejecutar el análisis al presionar el botón
# ---------------------------------------------------------------------
if analizar_clicked:
    es_valido, valor_normalizado, mensaje_error = validators.validate_target(target_input)

    if not es_valido:
        st.error(f"Input inválido: {mensaje_error}")
    else:
        target = valor_normalizado

        with st.spinner(f"Resolviendo DNS de {target}..."):
            dns_result = dns_check.check_dns(target)

        with st.spinner(f"Verificando propagación DNS de {target} en resolvers públicos..."):
            propagation_result = dns_propagation.check_dns_propagation(target)

        with st.spinner(f"Consultando WHOIS de {target}..."):
            whois_result = whois_check.check_whois(target)

        with st.spinner(f"Verificando certificado SSL de {target}..."):
            ssl_result = ssl_check.check_ssl(target)

        # Cálculo puro (sin red): no necesita spinner propio, es instantáneo.
        ssl_grade_result = ssl_grade.calculate_ssl_grade(ssl_result)

        with st.spinner(
            f"Escaneando puertos {port_start}-{port_end} de {target} "
            f"(esto puede tardar unos segundos)..."
        ):
            port_result = port_scan.scan_ports(
                target,
                port_start=port_start,
                port_end=port_end,
                max_threads=int(max_threads),
                timeout=float(port_timeout),
            )

        with st.spinner(f"Revisando security headers de {target}..."):
            headers_result = headers_check.check_headers(target)

        with st.spinner(f"Detectando tecnologías usadas por {target}..."):
            tech_result = tech_detect.detect_technologies(target)

        with st.spinner("Calculando score heurístico..."):
            score_result = scoring.calculate_score(
                dns_result=dns_result,
                whois_result=whois_result,
                ssl_result=ssl_result,
                port_scan_result=port_result,
                headers_result=headers_result,
            )

        st.session_state.netsight_target = target
        st.session_state.netsight_results = {
            "domain": target,
            "dns": dns_result,
            "dns_propagation": propagation_result,
            "whois": whois_result,
            "ssl": ssl_result,
            "ssl_grade": ssl_grade_result,
            "ports": port_result,
            "headers": headers_result,
            "tech": tech_result,
            "score": score_result,
        }
        st.success(f"Análisis de '{target}' completado.")

# ---------------------------------------------------------------------
# Mostrar resultados (si ya hay un análisis en session_state)
# ---------------------------------------------------------------------
results = st.session_state.netsight_results

if results is None:
    st.info("Ingresa un dominio o IP arriba y presiona **Analizar** para comenzar.")
else:
    target = st.session_state.netsight_target
    dns_result = results["dns"]
    propagation_result = results["dns_propagation"]
    whois_result = results["whois"]
    ssl_result = results["ssl"]
    ssl_grade_result = results["ssl_grade"]
    port_result = results["ports"]
    headers_result = results["headers"]
    tech_result = results["tech"]
    score_result = results["score"]

    st.header(f"Resultados para `{target}`")

    # --- Score prominente arriba, con gauge + métricas clave ---
    emoji, color = _nivel_visual(score_result["nivel"])
    gauge_col, metrics_col = st.columns([1, 2])

    with gauge_col:
        st.plotly_chart(_render_gauge(score_result["score_total"], color), width="stretch")
        st.markdown(f"### {emoji} Nivel: **{score_result['nivel']}**")

    with metrics_col:
        m1, m2, m3 = st.columns(3)
        m1.metric(
            "SSL",
            f"{score_result['desglose']['ssl']}/20",
            help=score_result["detalles"]["ssl"],
        )
        m2.metric(
            "Security Headers",
            f"{score_result['desglose']['headers']}/20",
            help=score_result["detalles"]["headers"],
        )
        m3.metric(
            "SPF/DKIM/DMARC",
            f"{score_result['desglose']['dns_seguridad']}/20",
            help=score_result["detalles"]["dns_seguridad"],
        )

        m4, m5, m6 = st.columns(3)
        m4.metric(
            "Puertos",
            f"{score_result['desglose']['puertos']}/20",
            help=score_result["detalles"]["puertos"],
        )
        m5.metric(
            "Antigüedad dominio",
            f"{score_result['desglose']['antiguedad_dominio']}/20",
            help=score_result["detalles"]["antiguedad_dominio"],
        )
        open_ports_count = len(port_result.get("open_ports", []) or [])
        m6.metric("Puertos abiertos", open_ports_count)

    st.divider()

    # -------------------------------------------------------------
    # Resultados detallados: una sola página larga con un expander por
    # sección (en vez de pestañas), separados por st.divider(). SSL y
    # Headers arrancan abiertos por defecto por ser las secciones más
    # accionables; el resto arranca colapsado para no saturar la vista.
    # -------------------------------------------------------------
    st.subheader("Resultados detallados")

    # --- DNS ---
    with st.expander("🌐 DNS", expanded=False):
        _render_errors_and_warnings(dns_result)
        if dns_result.get("success"):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.subheader("Registros")
                st.markdown("**A**")
                st.write(dns_result.get("a_records") or "—")
                st.markdown("**AAAA**")
                st.write(dns_result.get("aaaa_records") or "—")
                st.markdown("**NS**")
                st.write(dns_result.get("ns_records") or "—")
                st.markdown("**CNAME**")
                st.write(dns_result.get("cname_records") or "—")
            with col2:
                st.subheader("MX")
                mx_records = dns_result.get("mx_records") or []
                if mx_records:
                    st.table(mx_records)
                else:
                    st.write("—")
                st.subheader("TXT")
                st.write(dns_result.get("txt_records") or "—")
            with col3:
                st.subheader("Seguridad de correo")
                spf = dns_result.get("spf", {})
                dkim = dns_result.get("dkim", {})
                dmarc = dns_result.get("dmarc", {})
                st.write("✅ SPF" if spf.get("found") else "❌ SPF")
                if spf.get("value"):
                    st.caption(spf["value"])
                st.write("✅ DKIM" if dkim.get("found") else "❌ DKIM (heurístico, ver nota abajo)")
                if dkim.get("selector_probado"):
                    st.caption(f"Selector: {dkim['selector_probado']}")
                st.write("✅ DMARC" if dmarc.get("found") else "❌ DMARC")
                if dmarc.get("value"):
                    st.caption(dmarc["value"])
                st.caption(
                    "DKIM se prueba contra una lista de selectores comunes: "
                    "'❌' no garantiza que DKIM esté ausente, solo que ninguno "
                    "de los selectores probados respondió."
                )

    st.divider()

    # --- Propagación DNS ---
    with st.expander("🌍 Propagación DNS", expanded=False):
        _render_errors_and_warnings(propagation_result)
        if propagation_result.get("success"):
            if propagation_result.get("is_consistent"):
                st.success(
                    f"✅ Todos los resolvers que respondieron coinciden "
                    f"(registro {propagation_result.get('record_type')})."
                )
            else:
                st.warning(
                    "⚠️ Los resolvers no coinciden o no hubo suficientes para confirmarlo "
                    "(ver detalle abajo; esto no siempre es un problema — puede ser CDN/balanceo)."
                )
            rows = []
            for name, info in propagation_result.get("resolvers", {}).items():
                rows.append(
                    {
                        "Resolver": name,
                        "IP": info.get("ip"),
                        "Respondió": "✅" if info.get("responded") else "❌",
                        "Valores": ", ".join(info.get("values") or []) or "—",
                        "Tiempo (ms)": info.get("response_time_ms"),
                        "Error": info.get("error") or "",
                    }
                )
            st.table(rows)

    st.divider()

    # --- WHOIS ---
    with st.expander("📋 WHOIS", expanded=False):
        _render_errors_and_warnings(whois_result)
        if whois_result.get("success"):
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Registrador", whois_result.get("registrar") or "Desconocido")
                st.metric("País", whois_result.get("country") or "Desconocido")
                age_days = whois_result.get("domain_age_days")
                age_years = whois_result.get("domain_age_years")
                st.metric(
                    "Antigüedad",
                    f"{age_years} años" if age_years is not None else "Desconocida",
                    help=f"{age_days} días" if age_days is not None else None,
                )
            with col2:
                st.write("**Fecha de creación:**", whois_result.get("creation_date") or "—")
                st.write("**Fecha de expiración:**", whois_result.get("expiration_date") or "—")
                days_to_expire = whois_result.get("days_to_expire")
                if days_to_expire is not None:
                    if whois_result.get("is_expired"):
                        st.error(f"El dominio ya expiró (hace {abs(days_to_expire)} días).")
                    else:
                        st.write(f"**Días para expirar:** {days_to_expire}")
                if whois_result.get("privacy_protected"):
                    st.info("🔒 WHOIS protegido por privacidad (GDPR / proxy de registro).")
                if whois_result.get("status"):
                    st.write("**Estado:**", ", ".join(whois_result["status"]))

    st.divider()

    # --- SSL --- (abierto por defecto: suele traer los hallazgos más accionables)
    with st.expander("🔒 SSL", expanded=True):
        _render_errors_and_warnings(ssl_result)

        # Nota SSL propia (A+ a F), calculada por modules/ssl_grade.py a
        # partir de este mismo ssl_result — no consulta ningún servicio
        # externo tipo SSL Labs.
        grade_col, score_col = st.columns([1, 3])
        with grade_col:
            st.metric("Nota SSL (NetSight)", ssl_grade_result["grade"])
        with score_col:
            st.caption(f"Puntaje interno: {ssl_grade_result['numeric_score']}/100")
            if ssl_grade_result["penalties_applied"]:
                for penalty in ssl_grade_result["penalties_applied"]:
                    st.write(f"- {penalty['reason']} ({penalty['points']} pts)")
            else:
                st.write("Sin penalizaciones aplicadas.")

        if ssl_result.get("success"):
            if ssl_result.get("trusted"):
                st.success("✅ Certificado válido y de cadena confiable.")
            elif ssl_result.get("self_signed_or_untrusted"):
                st.warning(
                    f"⚠️ Certificado autofirmado o no confiable. "
                    f"({ssl_result.get('verify_error')})"
                )

            col1, col2 = st.columns(2)
            with col1:
                st.write("**Emitido a (CN):**", ssl_result.get("subject_cn") or "—")
                st.write("**Emisor:**", ssl_result.get("issuer") or "—")
                st.write("**Algoritmo de firma:**", ssl_result.get("signature_algorithm") or "—")
            with col2:
                st.write("**Válido desde:**", ssl_result.get("not_before") or "—")
                st.write("**Válido hasta:**", ssl_result.get("not_after") or "—")
                days_remaining = ssl_result.get("days_remaining")
                if ssl_result.get("is_expired"):
                    st.error(f"El certificado ya expiró (hace {abs(days_remaining)} días).")
                elif ssl_result.get("is_expiring_soon"):
                    st.warning(f"⚠️ El certificado expira en {days_remaining} días.")
                elif days_remaining is not None:
                    st.write(f"**Días restantes:** {days_remaining}")

            cipher = ssl_result.get("cipher_suite")
            if cipher:
                st.caption(
                    f"Cipher: {cipher.get('name')} · TLS: {cipher.get('tls_version')} · "
                    f"{cipher.get('secret_bits')} bits"
                )

    st.divider()

    # --- Puertos ---
    with st.expander("🔌 Puertos", expanded=False):
        _render_errors_and_warnings(port_result)
        if port_result.get("success"):
            st.write(
                f"Puertos escaneados: **{port_result.get('port_start')}-{port_result.get('port_end')}** "
                f"({port_result.get('scanned_count')} puertos, {port_result.get('duration_seconds')}s)"
            )
            if port_result.get("truncated"):
                st.info(
                    f"El rango solicitado se truncó por el límite de seguridad "
                    f"(pedido hasta el puerto {port_result.get('requested_port_end')})."
                )
            open_ports = port_result.get("open_ports") or []
            if open_ports:
                st.table(open_ports)
            else:
                st.write("No se encontraron puertos abiertos en el rango escaneado.")

    st.divider()

    # --- Headers --- (abierto por defecto: suele traer hallazgos accionables)
    # Nota: usamos st.container(border=True) en vez de st.expander por header
    # porque Streamlit no permite anidar expanders dentro de otro expander.
    with st.expander("🛡️ Headers", expanded=True):
        _render_errors_and_warnings(headers_result)
        if headers_result.get("success"):
            st.progress(
                headers_result["score"] / headers_result["max_score"],
                text=f"{headers_result['score']}/{headers_result['max_score']} headers presentes "
                f"({headers_result['score_percentage']}%)",
            )
            for name, info in headers_result.get("headers", {}).items():
                icon = "✅" if info["present"] else "❌"
                with st.container(border=True):
                    st.markdown(f"**{icon} {name}**")
                    st.write("**Valor:**", info["value"] or "No presente")
                    st.caption(info["description"])

    st.divider()

    # --- Tecnologías ---
    # Nota: usamos st.container(border=True) en vez de st.expander por
    # tecnología porque Streamlit no permite anidar expanders.
    with st.expander("🧩 Tecnologías", expanded=False):
        _render_errors_and_warnings(tech_result)
        if tech_result.get("success"):
            detected = tech_result.get("detected_technologies") or []
            if not detected:
                st.write("No se detectaron tecnologías conocidas con las firmas actuales.")
            else:
                for tech in detected:
                    with st.container(border=True):
                        st.markdown(f"**🧩 {tech['name']}** _{tech['category']}_")
                        for ev in tech["evidence"]:
                            if ev["method"] == "header":
                                st.write(
                                    f"- Header `{ev['header']}` contiene `{ev['signature']}` "
                                    f"(valor: `{ev['matched_value']}`)"
                                )
                            elif ev["method"] == "cookie":
                                st.write(f"- Cookie `{ev['cookie_name']}` coincide con `{ev['signature']}`")
                            elif ev["method"] == "html_pattern":
                                st.write(f"- Patrón `{ev['signature']}` encontrado en el HTML")

    st.divider()

    # -------------------------------------------------------------
    # Exportar resultados: arma el JSON combinado (utils/export.py se
    # encarga de serializar, esta sección solo lo ofrece para descarga).
    # -------------------------------------------------------------
    export_json = export.build_export_payload(results)
    safe_target = "".join(c if c.isalnum() or c in ".-" else "_" for c in target)
    export_filename = f"netsight_{safe_target}_{datetime.now().strftime('%Y%m%d')}.json"

    st.download_button(
        label="📥 Descargar reporte en JSON",
        data=export_json,
        file_name=export_filename,
        mime="application/json",
        width="stretch",
    )

# ---------------------------------------------------------------------
# Disclaimer legal (siempre visible al final)
# ---------------------------------------------------------------------
st.divider()
st.warning(
    "⚠️ **Aviso legal:** Esta herramienta debe usarse únicamente sobre dominios/IPs "
    "de tu propiedad o con autorización explícita del propietario. El escaneo de "
    "puertos y otras técnicas de reconocimiento sin autorización pueden ser ilegales "
    "en tu jurisdicción."
)
