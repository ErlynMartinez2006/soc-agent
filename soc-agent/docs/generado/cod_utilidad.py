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
