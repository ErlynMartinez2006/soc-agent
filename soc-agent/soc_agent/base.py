"""Clase base de un Agente Basado en Utilidad (Russell & Norvig), adaptada de la plantilla del taller."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple

from .modelos import EstadoProyectado, Percepcion


class AgenteBasadoEnUtilidad(ABC):
    """Ciclo de vida: percepción -> estado interno -> estados proyectados -> U(s) -> argmax -> actuador."""

    def __init__(self, nombre_agente: str, pesos_utilidad: Dict[str, float]):
        self.nombre = nombre_agente
        self.pesos = dict(pesos_utilidad)
        self.historial_decisiones: List[Dict[str, Any]] = []

    @abstractmethod
    def actualizar_estado_interno(self, percepcion: Percepcion) -> str:
        """PASO 1 (modelo del mundo): diagnostica qué ocurre a partir de sensores parciales."""

    @abstractmethod
    def generar_estados_proyectados(
        self, diagnostico: str, percepcion: Percepcion
    ) -> List[EstadoProyectado]:
        """PASO 2 (modelo de transición): acciones posibles y consecuencias estimadas."""

    def calcular_utilidad(self, estado: EstadoProyectado) -> float:
        """PASO 3: U(s) = w_e*P + w_b*B - w_r*R - w_c*C."""
        w = self.pesos
        utilidad = (
            w.get("exito", 1.0) * estado.probabilidad_exito
            + w.get("beneficio", 1.0) * estado.beneficio_operativo
            - w.get("riesgo", 1.0) * estado.riesgo_impacto
            - w.get("costo", 1.0) * estado.costo_intervencion
        )
        return round(utilidad, 2)

    def seleccionar_mejor_accion(
        self, percepcion: Percepcion
    ) -> Tuple[EstadoProyectado, Dict[str, float]]:
        """PASO 4: evalúa todas las acciones factibles y elige la que maximiza U(s)."""
        diagnostico = self.actualizar_estado_interno(percepcion)
        estados = self.generar_estados_proyectados(diagnostico, percepcion)
        if not estados:
            raise ValueError(f"No se generaron acciones para el diagnóstico: {diagnostico}")
        tabla: Dict[str, float] = {}
        mejor, u_max = estados[0], float("-inf")
        for estado in estados:
            u = self.calcular_utilidad(estado)
            tabla[estado.nombre_accion] = u
            if u > u_max:  # en empate gana la primera acción listada (orden de menor impacto)
                mejor, u_max = estado, u
        return mejor, tabla

    @abstractmethod
    def ejecutar_actuador(self, percepcion: Percepcion, accion_elegida: EstadoProyectado) -> None:
        """PASO 5: ejecuta la acción ganadora sobre el entorno y registra métricas."""

    def procesar_evento(self, percepcion: Percepcion, verbose: bool = True) -> Dict[str, Any]:
        """Orquesta el ciclo completo Percepción -> Decisión -> Acción."""
        mejor, evaluaciones = self.seleccionar_mejor_accion(percepcion)
        if verbose:
            print(f"\n[{self.nombre}] Evento {percepcion.id_evento}")
            print(f"  U(s) por acción: {evaluaciones}")
            print(f"  Decisión óptima: '{mejor.nombre_accion}' (U = {evaluaciones[mejor.nombre_accion]})")
        self.ejecutar_actuador(percepcion, mejor)
        registro = {
            "evento": percepcion.id_evento,
            "accion": mejor.nombre_accion,
            "utilidad": evaluaciones[mejor.nombre_accion],
            "utilidades": evaluaciones,
            "metadatos": mejor.metadatos,
        }
        self.historial_decisiones.append(registro)
        return registro
