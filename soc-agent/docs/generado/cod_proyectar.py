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
