"""Agente SOC de triaje y respuesta ante incidentes: basado en utilidad con restricciones de seguridad."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set

from . import config as cfg
from .base import AgenteBasadoEnUtilidad
from .modelos import EstadoProyectado, Percepcion


class AgenteSOC(AgenteBasadoEnUtilidad):
    """Agente autónomo de primer nivel.

    Decide entre ignorar, bloquear IP, revocar credenciales, aislar el host o escalar a un analista,
    maximizando U(s) = w_e*P + w_b*B - w_r*R - w_c*C.
    """

    def __init__(self, nombre_agente: str = "AgenteSOC-v1", pesos_utilidad: Optional[Dict[str, float]] = None):
        super().__init__(nombre_agente, pesos_utilidad or cfg.PESOS_UTILIDAD)
        # Estado interno (modelo del mundo): memoria de lo observado y de lo ya contenido.
        self.alertas_por_ip: Dict[str, int] = {}
        self.hosts_aislados: Set[str] = set()
        self.ips_bloqueadas: Set[str] = set()
        self.sesiones_revocadas: Set[str] = set()
        self.tickets: List[Dict[str, Any]] = []
        self.bitacora_actuadores: List[str] = []
        self._p_amenaza: float = 0.0

    # ------------------------------------------------------------------ PASO 1
    def estimar_probabilidad_amenaza(self, percepcion: Percepcion, recurrencia: int = 0) -> float:
        """p = sigmoide(z): probabilidad de que la alerta corresponda a una amenaza real."""
        d = percepcion.datos_sensores
        z = (
            cfg.SESGO
            + cfg.COEF["reputacion_ip"] * float(d["reputacion_ip"])
            + cfg.COEF["severidad"] * float(d["severidad_siem"]) / 10.0
            + cfg.COEF["trafico_anomalo"] * float(d["trafico_anomalo"])
            + cfg.COEF["intentos"] * min(int(d["intentos_fallidos"]), 20) / 20.0
            + cfg.COEF["recurrencia"] * min(recurrencia, 5) / 5.0
            + cfg.BONO_TIPO[d["tipo_alerta"]]
        )
        return 1.0 / (1.0 + math.exp(-z))

    def actualizar_estado_interno(self, percepcion: Percepcion) -> str:
        percepcion.validar()
        d = percepcion.datos_sensores
        ip, host = d["ip_origen"], d["host"]
        previas = self.alertas_por_ip.get(ip, 0)
        self._p_amenaza = self.estimar_probabilidad_amenaza(percepcion, previas)
        if host in self.hosts_aislados:
            return "YA_CONTENIDO"
        p = self._p_amenaza
        if p < cfg.UMBRAL_FALSO_POSITIVO:
            return "FALSO_POSITIVO_PROBABLE"
        if p < cfg.UMBRAL_AMBIGUO:
            return "INCIDENTE_AMBIGUO"
        if p < cfg.UMBRAL_CONFIRMADA:
            return "AMENAZA_PROBABLE"
        return "AMENAZA_CONFIRMADA"

    # ------------------------------------------------------------------ PASO 2
    def _acciones_factibles(self, percepcion: Percepcion) -> List[str]:
        """Acciones aplicables a esta alerta (restricciones operativas del entorno)."""
        d = percepcion.datos_sensores
        factibles = ["IGNORAR", "ESCALAR_ANALISTA"]  # ESCALAR siempre es una vía segura (fail-safe)
        if d.get("ip_externa", False) and d["ip_origen"] not in self.ips_bloqueadas:
            factibles.append("BLOQUEAR_IP")
        if d["tipo_alerta"] in cfg.TIPOS_REVOCAR:
            factibles.append("REVOCAR_CREDENCIALES")
        factibles.append("AISLAR_HOST")
        return factibles

    def proyectar(self, nombre: str, p: float, severidad: float, criticidad: float) -> EstadoProyectado:
        """Estado proyectado de ejecutar ``nombre`` dados p (amenaza real), s (severidad) y c (criticidad)."""
        a = cfg.ACCIONES[nombre]
        e, t, kappa, f = a["e"], a["t"], a["kappa"], a["f"]
        rapidez = 1.0 - t / cfg.T_MAX
        exito = p * e + (1.0 - p) * f
        beneficio = 100.0 * rapidez
        riesgo = (1.0 - p) * kappa * criticidad + p * severidad * (1.0 - e * rapidez)
        return EstadoProyectado(
            nombre_accion=nombre,
            probabilidad_exito=exito,
            beneficio_operativo=beneficio,
            riesgo_impacto=riesgo,
            costo_intervencion=a["costo"],
            metadatos={"p_amenaza": round(p, 4)},
        )

    def generar_estados_proyectados(self, diagnostico: str, percepcion: Percepcion) -> List[EstadoProyectado]:
        if diagnostico == "YA_CONTENIDO":
            # El host ya está aislado: no hay nada más que contener ni nada que interrumpir.
            return [EstadoProyectado("IGNORAR", 1.0, 100.0, 0.0, 0.0, {"p_amenaza": round(self._p_amenaza, 4), "motivo": "host ya aislado"})]
        d = percepcion.datos_sensores
        s = float(d["severidad_siem"]) / 10.0
        c = float(d["criticidad_activo"])
        return [self.proyectar(n, self._p_amenaza, s, c) for n in self._acciones_factibles(percepcion)]

    # ------------------------------------------------------------------ PASO 5
    def ejecutar_actuador(self, percepcion: Percepcion, accion_elegida: EstadoProyectado) -> None:
        d = percepcion.datos_sensores
        ip, host, nombre = d["ip_origen"], d["host"], accion_elegida.nombre_accion
        self.alertas_por_ip[ip] = self.alertas_por_ip.get(ip, 0) + 1
        if nombre == "BLOQUEAR_IP":
            self.ips_bloqueadas.add(ip)
            msg = f"FIREWALL: bloquear {ip}"
        elif nombre == "AISLAR_HOST":
            self.hosts_aislados.add(host)
            msg = f"EDR/NAC: aislar host {host}"
        elif nombre == "REVOCAR_CREDENCIALES":
            self.sesiones_revocadas.add(host)
            msg = f"IAM: revocar sesiones en {host}"
        elif nombre == "ESCALAR_ANALISTA":
            prioridad = "ALTA" if self._p_amenaza * float(d["severidad_siem"]) / 10.0 >= 0.3 else "MEDIA"
            self.tickets.append({"evento": percepcion.id_evento, "host": host, "prioridad": prioridad,
                                 "p_amenaza": round(self._p_amenaza, 3)})
            msg = f"TICKET: escalar {percepcion.id_evento} (prioridad {prioridad})"
        else:
            msg = f"SIN ACCION: {percepcion.id_evento} ({accion_elegida.metadatos.get('motivo', 'alerta descartada')})"
        self.bitacora_actuadores.append(msg)

    # ------------------------------------------------------------------ Tolerancia a fallos
    def procesar_evento_seguro(self, percepcion: Percepcion, verbose: bool = False) -> Dict[str, Any]:
        """Igual que ``procesar_evento`` pero, ante datos inválidos o fallos internos, escala (fail-safe)."""
        try:
            return self.procesar_evento(percepcion, verbose=verbose)
        except (ValueError, KeyError, TypeError) as exc:
            self.tickets.append({"evento": percepcion.id_evento, "prioridad": "ALTA", "error": str(exc)})
            self.bitacora_actuadores.append(f"TICKET: evento {percepcion.id_evento} con datos inválidos ({exc})")
            registro = {"evento": percepcion.id_evento, "accion": "ESCALAR_ANALISTA", "utilidad": None,
                        "utilidades": {}, "metadatos": {"error": str(exc)}}
            self.historial_decisiones.append(registro)
            return registro
