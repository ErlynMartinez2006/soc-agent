"""Estructuras de datos del agente SOC: percepciones (sensores) y estados proyectados."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

TIPOS_ALERTA = (
    "escaneo_puertos",
    "fuerza_bruta",
    "login_anomalo",
    "malware",
    "exfiltracion",
)
TIPOS_ACTIVO = ("estacion", "servidor_interno", "servidor_critico")


@dataclass
class Percepcion:
    """Datos crudos capturados por los SENSORES del agente en un instante t.

    ``datos_sensores`` admite las claves (ver ``validar``):

    - ``tipo_alerta``: una de ``TIPOS_ALERTA`` (alerta del SIEM).
    - ``severidad_siem``: 0-10, severidad asignada por el SIEM.
    - ``reputacion_ip``: 0-1, 1 = IP de origen con pésima reputación (listas de reputación).
    - ``intentos_fallidos``: entero >= 0, intentos de autenticación fallidos (registros de auth).
    - ``trafico_anomalo``: 0-1, puntaje de anomalía del tráfico de red (registros de tráfico).
    - ``tipo_activo``: una de ``TIPOS_ACTIVO``.
    - ``criticidad_activo``: 0-1, importancia del activo para el negocio.
    - ``ip_origen``: texto, IP de origen de la alerta.
    - ``host``: texto, nombre del activo afectado.
    - ``ip_externa``: bool, True si la IP de origen está fuera de la red corporativa.
    """

    id_evento: str
    datos_sensores: Dict[str, Any]
    contexto_critico: bool = False

    def validar(self) -> None:
        """Lanza ``ValueError`` si los datos de los sensores son inválidos o incompletos."""
        d = self.datos_sensores
        requeridos = (
            "tipo_alerta", "severidad_siem", "reputacion_ip", "intentos_fallidos",
            "trafico_anomalo", "tipo_activo", "criticidad_activo", "ip_origen", "host",
        )
        faltantes = [k for k in requeridos if k not in d or d[k] is None]
        if faltantes:
            raise ValueError(f"Faltan sensores: {faltantes}")
        if d["tipo_alerta"] not in TIPOS_ALERTA:
            raise ValueError(f"tipo_alerta desconocido: {d['tipo_alerta']!r}")
        if d["tipo_activo"] not in TIPOS_ACTIVO:
            raise ValueError(f"tipo_activo desconocido: {d['tipo_activo']!r}")
        rangos = {
            "severidad_siem": (0.0, 10.0),
            "reputacion_ip": (0.0, 1.0),
            "trafico_anomalo": (0.0, 1.0),
            "criticidad_activo": (0.0, 1.0),
        }
        for clave, (lo, hi) in rangos.items():
            try:
                v = float(d[clave])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{clave} no es numérico: {d[clave]!r}") from exc
            if not lo <= v <= hi:
                raise ValueError(f"{clave}={v} fuera del rango [{lo}, {hi}]")
        try:
            if int(d["intentos_fallidos"]) < 0:
                raise ValueError("intentos_fallidos no puede ser negativo")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"intentos_fallidos inválido: {d['intentos_fallidos']!r}") from exc


@dataclass
class EstadoProyectado:
    """Resultado futuro estimado si el agente ejecuta una acción concreta.

    Permite comparar alternativas antes de actuar en el entorno real.
    """

    nombre_accion: str
    probabilidad_exito: float   # [0, 1]   P_a: probabilidad de desenlace correcto
    beneficio_operativo: float  # [0, 100] B_a: rapidez de cierre del incidente
    riesgo_impacto: float       # [0, 1]   R_a: falso positivo disruptivo + amenaza residual
    costo_intervencion: float   # [0, 1]   C_a: costo operativo / carga humana
    metadatos: Dict[str, Any] = field(default_factory=dict)
