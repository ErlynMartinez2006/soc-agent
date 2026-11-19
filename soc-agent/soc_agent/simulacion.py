"""Simulación sintética con verdad de terreno para medir los KPIs del agente y compararlo con líneas base."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import config as cfg
from .agente_soc import AgenteSOC
from .modelos import Percepcion

TIPOS_AUTH = ("fuerza_bruta", "login_anomalo")


@dataclass
class EventoSimulado:
    percepcion: Percepcion
    es_amenaza: bool
    u_contencion: float   # número aleatorio fijo por evento: hace comparables las políticas (mismo "azar")
    u_interrupcion: float


def _clip(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def generar_eventos(n: int = 1000, prevalencia: float = 0.15, semilla: int = 42) -> List[EventoSimulado]:
    """Genera ``n`` alertas con etiqueta real (amenaza / falso positivo) y sensores dependientes de la etiqueta."""
    rng = random.Random(semilla)
    eventos: List[EventoSimulado] = []
    for i in range(n):
        amenaza = rng.random() < prevalencia
        if amenaza:
            tipo = rng.choices(list(cfg.BONO_TIPO), weights=[.15, .30, .20, .20, .15])[0]
            rep = rng.betavariate(5, 2)
            sev = _clip(rng.gauss(7.0, 1.5), 0, 10)
            tr = rng.betavariate(4, 2)
            lam = 12
        else:
            tipo = rng.choices(list(cfg.BONO_TIPO), weights=[.35, .10, .35, .10, .10])[0]
            rep = rng.betavariate(1.5, 6)
            sev = _clip(rng.gauss(3.5, 1.8), 0, 10)
            tr = rng.betavariate(1.5, 5)
            lam = 2
        intentos = int(_clip(rng.gauss(lam, 3), 0, 40)) if tipo in TIPOS_AUTH else 0
        tipo_activo = rng.choices(["estacion", "servidor_interno", "servidor_critico"], weights=[.6, .25, .15])[0]
        crit = {"estacion": rng.uniform(.1, .4), "servidor_interno": rng.uniform(.4, .7),
                "servidor_critico": rng.uniform(.85, 1.0)}[tipo_activo]
        sensores = dict(tipo_alerta=tipo, severidad_siem=round(sev, 2), reputacion_ip=round(rep, 3),
                        intentos_fallidos=intentos, trafico_anomalo=round(tr, 3), tipo_activo=tipo_activo,
                        criticidad_activo=round(crit, 3), ip_origen=f"198.51.{i // 250}.{i % 250 + 1}",
                        host=f"H-{i:04d}", ip_externa=rng.random() < (0.6 if amenaza else 0.35))
        eventos.append(EventoSimulado(Percepcion(f"S-{i:04d}", sensores, tipo_activo == "servidor_critico"),
                                      amenaza, rng.random(), rng.random()))
    return eventos


# ---------------------------------------------------------------- políticas
Politica = Callable[[Percepcion], str]


def politica_agente(pesos: Optional[Dict[str, float]] = None) -> Politica:
    agente = AgenteSOC(pesos_utilidad=pesos)
    return lambda p: agente.procesar_evento_seguro(p)["accion"]


def politica_reglas_rigidas() -> Politica:
    """Línea base 1: if-else sin ponderación. Aísla si la severidad del SIEM es >= 7; si no, ignora."""
    return lambda p: "AISLAR_HOST" if float(p.datos_sensores["severidad_siem"]) >= 7 else "IGNORAR"


def politica_siempre_escalar() -> Politica:
    """Línea base 2: todo va al analista humano."""
    return lambda p: "ESCALAR_ANALISTA"


# ---------------------------------------------------------------- KPIs
def evaluar(politica: Politica, eventos: List[EventoSimulado]) -> Dict[str, float]:
    """Aplica la política a los eventos y calcula los KPIs del PEAS (Performance)."""
    amenazas = contenidas = 0
    tiempos: List[float] = []
    interrupciones_criticas = falsos_positivos_afectados = escalamientos = 0
    disruptivas = {"AISLAR_HOST", "BLOQUEAR_IP", "REVOCAR_CREDENCIALES"}
    for ev in eventos:
        accion = politica(ev.percepcion)
        a = cfg.ACCIONES[accion]
        if accion == "ESCALAR_ANALISTA":
            escalamientos += 1
        if ev.es_amenaza:
            amenazas += 1
            if ev.u_contencion < a["e"]:
                contenidas += 1
                tiempos.append(a["t"])
        elif accion in disruptivas and ev.u_interrupcion < a["kappa"]:
            falsos_positivos_afectados += 1
            if ev.percepcion.datos_sensores["tipo_activo"] == "servidor_critico":
                interrupciones_criticas += 1
    n = len(eventos)
    return {
        "eventos": n,
        "amenazas_reales": amenazas,
        "mttc_min": round(sum(tiempos) / len(tiempos), 2) if tiempos else float("nan"),
        "tasa_bloqueo_efectivo": round(contenidas / amenazas, 4) if amenazas else float("nan"),
        "amenazas_no_contenidas": amenazas - contenidas,
        "interrupciones_servicios_criticos": interrupciones_criticas,
        "falsos_positivos_afectados": falsos_positivos_afectados,
        "tasa_escalamiento": round(escalamientos / n, 4),
    }


def comparar_politicas(eventos: List[EventoSimulado]) -> Dict[str, Dict[str, float]]:
    return {
        "Agente (utilidad)": evaluar(politica_agente(), eventos),
        "Reglas if-else": evaluar(politica_reglas_rigidas(), eventos),
        "Siempre escalar": evaluar(politica_siempre_escalar(), eventos),
    }


def analisis_sensibilidad(eventos: List[EventoSimulado], pesos_riesgo=(50, 100, 200, 400, 800, 1600)) -> List[Dict[str, float]]:
    """Barre el peso de riesgo w_r y mide su efecto en el dilema velocidad vs. falsos positivos."""
    filas = []
    for wr in pesos_riesgo:
        pesos = dict(cfg.PESOS_UTILIDAD, riesgo=float(wr))
        k = evaluar(politica_agente(pesos), eventos)
        filas.append({"w_riesgo": wr, **k})
    return filas
