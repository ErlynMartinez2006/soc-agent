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
