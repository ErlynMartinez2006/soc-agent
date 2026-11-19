"""Parámetros del agente SOC: pesos de U(s), catálogo de acciones y coeficientes del estimador de amenaza."""

# --- Pesos de la función de utilidad (alta penalización al riesgo operativo) ---
PESOS_UTILIDAD = {"exito": 100.0, "beneficio": 0.5, "riesgo": 400.0, "costo": 30.0}

# Ventana máxima de contención considerada (minutos). Una acción con t = T_MAX no aporta rapidez.
T_MAX = 60.0

# --- Catálogo de acciones (actuadores) ---
# e     : efectividad de contención si la amenaza es real            [0, 1]
# t     : tiempo hasta que la acción surte efecto (min)
# kappa : interrupción causada si la alerta era un falso positivo    [0, 1]
# f     : prob. de desenlace correcto si la alerta era benigna       [0, 1]
# costo : costo operativo / carga humana de ejecutar la acción       [0, 1]
ACCIONES = {
    "IGNORAR":              {"e": 0.00, "t": 0.0,  "kappa": 0.00, "f": 1.0, "costo": 0.00},
    "BLOQUEAR_IP":          {"e": 0.80, "t": 1.0,  "kappa": 0.15, "f": 0.0, "costo": 0.10},
    "REVOCAR_CREDENCIALES": {"e": 0.70, "t": 2.0,  "kappa": 0.35, "f": 0.0, "costo": 0.15},
    "AISLAR_HOST":          {"e": 0.95, "t": 1.0,  "kappa": 1.00, "f": 0.0, "costo": 0.30},
    "ESCALAR_ANALISTA":     {"e": 0.90, "t": 30.0, "kappa": 0.05, "f": 1.0, "costo": 0.80},
}

# Tipos de alerta para los que cada acción tiene sentido operativo.
TIPOS_REVOCAR = ("fuerza_bruta", "login_anomalo", "exfiltracion")

# --- Estimador de probabilidad de amenaza real: p = sigmoide(z) ---
SESGO = -3.0
COEF = {
    "reputacion_ip": 2.5,
    "severidad": 2.0,      # severidad_siem / 10
    "trafico_anomalo": 1.5,
    "intentos": 2.0,       # min(intentos_fallidos, 20) / 20
    "recurrencia": 1.5,    # min(alertas previas de la misma IP, 5) / 5 (estado interno)
}
BONO_TIPO = {
    "escaneo_puertos": 0.0,
    "fuerza_bruta": 0.0,
    "login_anomalo": 0.0,
    "malware": 1.5,
    "exfiltracion": 1.5,
}

# --- Umbrales de diagnóstico (solo para etiquetar el estado interno) ---
UMBRAL_FALSO_POSITIVO = 0.25
UMBRAL_AMBIGUO = 0.60
UMBRAL_CONFIRMADA = 0.90
