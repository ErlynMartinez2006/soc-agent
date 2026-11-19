"""Interfaz gráfica (Streamlit) del agente SOC.

Ejecutar:  streamlit run app.py
"""
import pandas as pd
import streamlit as st

from soc_agent import AgenteSOC, Percepcion
from soc_agent import config as cfg
from soc_agent.escenarios import casos_de_prueba
from soc_agent.modelos import TIPOS_ACTIVO, TIPOS_ALERTA
from soc_agent.simulacion import analisis_sensibilidad, comparar_politicas, generar_eventos

st.set_page_config(page_title="Agente SOC", page_icon="🛡️", layout="wide")

COLORES = {
    "IGNORAR": "🟢", "BLOQUEAR_IP": "🟠", "REVOCAR_CREDENCIALES": "🟠",
    "AISLAR_HOST": "🔴", "ESCALAR_ANALISTA": "🔵",
}
DESCRIPCION = {
    "IGNORAR": "Se descarta la alerta: la amenaza es poco probable.",
    "BLOQUEAR_IP": "Se bloquea la IP de origen en el firewall.",
    "REVOCAR_CREDENCIALES": "Se revocan las sesiones del host afectado.",
    "AISLAR_HOST": "Se aísla el equipo de la red.",
    "ESCALAR_ANALISTA": "Se abre un ticket para un analista humano.",
}


# ------------------------------------------------------------------ utilidades
def evaluar(agente: AgenteSOC, percepcion: Percepcion):
    """Devuelve (diagnóstico, p, tabla de estados proyectados con U) sin ejecutar la acción."""
    diagnostico = agente.actualizar_estado_interno(percepcion)
    estados = agente.generar_estados_proyectados(diagnostico, percepcion)
    filas = []
    for e in estados:
        filas.append({
            "Acción": e.nombre_accion,
            "P (éxito)": round(e.probabilidad_exito, 3),
            "B (rapidez)": round(e.beneficio_operativo, 1),
            "R (riesgo)": round(e.riesgo_impacto, 3),
            "C (costo)": round(e.costo_intervencion, 2),
            "U(s,a)": agente.calcular_utilidad(e),
        })
    tabla = pd.DataFrame(filas).sort_values("U(s,a)", ascending=False).reset_index(drop=True)
    return diagnostico, agente._p_amenaza, tabla


def mostrar_decision(agente: AgenteSOC, percepcion: Percepcion, titulo_extra: str = ""):
    """Muestra la decisión del agente para una percepción (sin modificar su estado)."""
    try:
        diagnostico, p, tabla = evaluar(agente, percepcion)
    except ValueError as exc:
        st.error(f"🛑 Dato inválido: {exc}")
        st.warning("**Modo seguro:** con datos corruptos el agente no decide; "
                   f"escala al analista ({COLORES['ESCALAR_ANALISTA']} `ESCALAR_ANALISTA`).")
        return
    mejor = tabla.iloc[0]["Acción"]
    c1, c2, c3 = st.columns([1, 1.5, 1])
    c1.metric("Probabilidad de amenaza real", f"{p:.1%}")
    c2.metric("Diagnóstico", diagnostico.replace("_", " ").capitalize())
    c3.metric("Utilidad de la mejor acción", f"{tabla.iloc[0]['U(s,a)']:.1f}")
    st.success(f"{COLORES[mejor]} **Decisión: `{mejor}`** {titulo_extra}— {DESCRIPCION[mejor]}")
    st.caption("Utilidad U(s,a) de cada acción factible (mayor es mejor):")
    st.bar_chart(tabla.set_index("Acción")["U(s,a)"])
    st.dataframe(tabla, hide_index=True)


def percepcion_desde_widgets(prefijo: str, valores: dict | None = None) -> Percepcion:
    """Construye una percepción a partir de los controles (o de valores precargados)."""
    v = valores or {}
    tipo_alerta = st.selectbox("Tipo de alerta (SIEM)", TIPOS_ALERTA, key=f"{prefijo}_tipo",
                               index=TIPOS_ALERTA.index(v.get("tipo_alerta", "fuerza_bruta")))
    severidad = st.slider("Severidad del SIEM (0-10)", 0.0, 10.0, float(v.get("severidad_siem", 6.0)), 0.5, key=f"{prefijo}_sev")
    reputacion = st.slider("Reputación de la IP (1 = muy maliciosa)", 0.0, 1.0, float(v.get("reputacion_ip", 0.5)), 0.05, key=f"{prefijo}_rep")
    intentos = st.slider("Intentos de login fallidos", 0, 30, int(v.get("intentos_fallidos", 5)), key=f"{prefijo}_int")
    trafico = st.slider("Tráfico anómalo (0-1)", 0.0, 1.0, float(v.get("trafico_anomalo", 0.4)), 0.05, key=f"{prefijo}_tr")
    tipo_activo = st.selectbox("Tipo de activo afectado", TIPOS_ACTIVO, key=f"{prefijo}_act",
                               index=TIPOS_ACTIVO.index(v.get("tipo_activo", "servidor_interno")))
    criticidad = st.slider("Criticidad del activo (0-1)", 0.0, 1.0, float(v.get("criticidad_activo", 0.5)), 0.05, key=f"{prefijo}_crit")
    externa = st.checkbox("IP de origen externa", value=bool(v.get("ip_externa", True)), key=f"{prefijo}_ext")
    sensores = dict(tipo_alerta=tipo_alerta, severidad_siem=severidad, reputacion_ip=reputacion,
                    intentos_fallidos=intentos, trafico_anomalo=trafico, tipo_activo=tipo_activo,
                    criticidad_activo=criticidad, ip_origen=v.get("ip_origen", "203.0.113.77"),
                    host=v.get("host", "HOST-DEMO"), ip_externa=externa)
    return Percepcion(prefijo, sensores, contexto_critico=tipo_activo == "servidor_critico")


# ------------------------------------------------------------------ encabezado
st.title("🛡️ Agente inteligente de triaje SOC")
st.caption("Agente basado en utilidad: decide entre ignorar, bloquear IP, revocar credenciales, aislar el host "
           "o escalar a un analista, maximizando U(s,a) = w_e·P + w_b·B − w_r·R − w_c·C.")

with st.sidebar:
    st.header("⚙️ Pesos de la utilidad")
    st.caption("Cambia el compromiso entre éxito, rapidez, riesgo y costo. Valores por defecto del informe.")
    w_e = st.slider("w_e (éxito)", 0.0, 200.0, cfg.PESOS_UTILIDAD["exito"], 5.0)
    w_b = st.slider("w_b (rapidez)", 0.0, 5.0, cfg.PESOS_UTILIDAD["beneficio"], 0.1)
    w_r = st.slider("w_r (riesgo)", 0.0, 1600.0, cfg.PESOS_UTILIDAD["riesgo"], 10.0)
    w_c = st.slider("w_c (costo)", 0.0, 100.0, cfg.PESOS_UTILIDAD["costo"], 1.0)
    PESOS = {"exito": w_e, "beneficio": w_b, "riesgo": w_r, "costo": w_c}
    if st.button("Restablecer pesos"):
        st.session_state.clear()
        st.rerun()

tab1, tab2, tab3, tab4 = st.tabs(["🔎 Probar una alerta", "📋 Escenarios del informe",
                                  "📊 Simulación y KPIs", "🧠 Memoria por IP"])

# ------------------------------------------------------------------ pestaña 1
with tab1:
    col_in, col_out = st.columns([1, 2])
    with col_in:
        st.subheader("Sensores")
        percepcion = percepcion_desde_widgets("manual")
        corrupto = st.checkbox("Simular sensor corrupto (severidad = 15)")
        if corrupto:
            percepcion.datos_sensores["severidad_siem"] = 15
    with col_out:
        st.subheader("Decisión del agente")
        mostrar_decision(AgenteSOC(pesos_utilidad=PESOS), percepcion)

# ------------------------------------------------------------------ pestaña 2
with tab2:
    casos = casos_de_prueba()
    etiquetas = [f"{c['percepcion'].id_evento} · {c['categoria']} · {c['descripcion']}" for c in casos]
    elegido = st.selectbox("Escenario", range(len(casos)), format_func=lambda i: etiquetas[i])
    caso = casos[elegido]
    st.write(f"**Acción esperada por el diseño:** {COLORES[caso['esperada']]} `{caso['esperada']}`")
    with st.expander("Ver los datos de los sensores"):
        st.json(caso["percepcion"].datos_sensores)
    mostrar_decision(AgenteSOC(pesos_utilidad=PESOS), caso["percepcion"])

    st.divider()
    st.subheader("Los 9 escenarios a la vez")
    filas = []
    for c in casos:
        ag = AgenteSOC(pesos_utilidad=PESOS)
        reg = ag.procesar_evento_seguro(c["percepcion"])
        filas.append({"ID": reg["evento"], "Categoría": c["categoria"], "Descripción": c["descripcion"],
                      "Esperada": c["esperada"], "Obtenida": reg["accion"],
                      "Coincide": "✅" if reg["accion"] == c["esperada"] else "❌"})
    st.dataframe(pd.DataFrame(filas), hide_index=True)
    st.caption("Si cambias los pesos en la barra lateral, algunas decisiones pueden dejar de coincidir con lo esperado.")

# ------------------------------------------------------------------ pestaña 3
@st.cache_data(show_spinner=False)
def correr_simulacion(n: int, prevalencia: float, semilla: int):
    eventos = generar_eventos(n=n, prevalencia=prevalencia, semilla=semilla)
    return comparar_politicas(eventos), analisis_sensibilidad(eventos)


with tab3:
    st.write("Genera alertas sintéticas con etiqueta real y compara el agente con dos líneas base "
             "(reglas if-else y 'siempre escalar') sobre los mismos eventos.")
    c1, c2, c3 = st.columns(3)
    n = c1.slider("Número de alertas", 200, 3000, 1000, 100)
    prevalencia = c2.slider("Proporción de amenazas reales", 0.05, 0.40, 0.15, 0.01)
    semilla = c3.number_input("Semilla aleatoria", 0, 9999, 42)
    if st.button("▶️ Ejecutar simulación", type="primary"):
        st.session_state["sim"] = correr_simulacion(int(n), float(prevalencia), int(semilla))
    if "sim" in st.session_state:
        comp, sens = st.session_state["sim"]
        df = pd.DataFrame(comp).T
        tabla = pd.DataFrame({
            "MTTC (min)": df["mttc_min"],
            "Bloqueo efectivo (%)": (df["tasa_bloqueo_efectivo"] * 100).round(1),
            "Amenazas no contenidas": df["amenazas_no_contenidas"],
            "Interrupciones críticas": df["interrupciones_servicios_criticos"],
            "FP afectados": df["falsos_positivos_afectados"],
            "Escalamiento (%)": (df["tasa_escalamiento"] * 100).round(1),
        })
        st.subheader("KPIs por política")
        st.dataframe(tabla)
        g1, g2 = st.columns(2)
        g1.caption("Tasa de bloqueo efectivo de amenazas (%)")
        g1.bar_chart(tabla["Bloqueo efectivo (%)"])
        g2.caption("Tiempo medio de contención (min)")
        g2.bar_chart(tabla["MTTC (min)"])
        st.subheader("Sensibilidad al peso de riesgo w_r")
        sdf = pd.DataFrame(sens).set_index("w_riesgo")
        st.line_chart(pd.DataFrame({
            "Bloqueo efectivo (%)": sdf["tasa_bloqueo_efectivo"] * 100,
            "Escalamiento (%)": sdf["tasa_escalamiento"] * 100,
        }))
    else:
        st.info("Pulsa el botón para ejecutar la simulación.")

# ------------------------------------------------------------------ pestaña 4
with tab4:
    st.write("El agente recuerda cuántas alertas ha visto de cada IP. Aquí se envía la **misma alerta "
             "repetida** desde una IP y se observa cómo sube la sospecha hasta que deja de ignorarla.")
    col_a, col_b = st.columns([1, 2])
    with col_a:
        base = dict(tipo_alerta="escaneo_puertos", severidad_siem=4.0, reputacion_ip=0.35, intentos_fallidos=0,
                    trafico_anomalo=0.3, tipo_activo="servidor_interno", criticidad_activo=0.5, ip_externa=True)
        percepcion_m = percepcion_desde_widgets("mem", base)
        repeticiones = st.slider("Repeticiones", 2, 10, 6)
    with col_b:
        agente_m = AgenteSOC(pesos_utilidad=PESOS)
        filas = []
        for i in range(repeticiones):
            sensores = dict(percepcion_m.datos_sensores, host=f"HOST-{i}")
            reg = agente_m.procesar_evento_seguro(Percepcion(f"ALERTA-{i + 1}", sensores))
            filas.append({"Alerta #": i + 1, "p (amenaza)": reg["metadatos"].get("p_amenaza"),
                          "Decisión": f"{COLORES.get(reg['accion'], '')} {reg['accion']}"})
        st.line_chart(pd.DataFrame(filas).set_index("Alerta #")["p (amenaza)"])
        st.dataframe(pd.DataFrame(filas), hide_index=True)
        st.caption("Cuando BLOQUEAR_IP ya se ejecutó, esa IP queda bloqueada y deja de ser una opción factible.")
