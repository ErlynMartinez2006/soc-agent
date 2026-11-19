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
