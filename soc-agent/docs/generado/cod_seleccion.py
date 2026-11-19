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
