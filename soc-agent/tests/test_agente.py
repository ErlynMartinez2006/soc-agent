"""Pruebas unitarias del agente SOC. Ejecutar: python -m pytest -q  (o python -m unittest discover tests)"""
import copy
import unittest

from soc_agent import AgenteSOC, Percepcion
from soc_agent.escenarios import casos_de_prueba
from soc_agent.simulacion import (evaluar, generar_eventos, politica_agente,
                                  politica_reglas_rigidas, politica_siempre_escalar)


def percepcion(**kw):
    base = dict(tipo_alerta="malware", severidad_siem=9, reputacion_ip=0.9, intentos_fallidos=0,
                trafico_anomalo=0.8, tipo_activo="servidor_interno", criticidad_activo=0.5,
                ip_origen="203.0.113.9", host="SRV-T", ip_externa=True)
    base.update(kw)
    return Percepcion("T-1", base)


class TestEscenarios(unittest.TestCase):
    def test_todos_los_escenarios_coinciden_con_lo_esperado(self):
        agente = AgenteSOC()
        for caso in casos_de_prueba():
            reg = agente.procesar_evento_seguro(caso["percepcion"])
            self.assertEqual(reg["accion"], caso["esperada"], caso["descripcion"])

    def test_hay_al_menos_cinco_casos_de_las_tres_categorias(self):
        casos = casos_de_prueba()
        self.assertGreaterEqual(len(casos), 5)
        self.assertTrue({"Rutinario", "Ambiguo", "Crítico"} <= {c["categoria"] for c in casos})


class TestFuncionUtilidad(unittest.TestCase):
    def setUp(self):
        self.agente = AgenteSOC()

    def test_probabilidad_en_rango_y_monotona_en_reputacion(self):
        bajo = self.agente.estimar_probabilidad_amenaza(percepcion(reputacion_ip=0.1))
        alto = self.agente.estimar_probabilidad_amenaza(percepcion(reputacion_ip=0.9))
        self.assertTrue(0 < bajo < alto < 1)

    def test_utilidad_formula(self):
        est = self.agente.proyectar("AISLAR_HOST", p=1.0, severidad=1.0, criticidad=1.0)
        w = self.agente.pesos
        esperado = w["exito"] * 0.95 + w["beneficio"] * est.beneficio_operativo - w["riesgo"] * est.riesgo_impacto - w["costo"] * 0.30
        self.assertAlmostEqual(self.agente.calcular_utilidad(est), round(esperado, 2), places=2)

    def test_falso_positivo_seguro_no_se_aisla(self):
        reg = self.agente.procesar_evento(percepcion(severidad_siem=2, reputacion_ip=0.05, trafico_anomalo=0.1, tipo_alerta="escaneo_puertos"), verbose=False)
        self.assertEqual(reg["accion"], "IGNORAR")

    def test_mayor_criticidad_desplaza_hacia_acciones_menos_disruptivas(self):
        ev = dict(tipo_alerta="exfiltracion", severidad_siem=6, reputacion_ip=0.4, trafico_anomalo=0.4)
        estacion = AgenteSOC().procesar_evento(percepcion(**ev, criticidad_activo=0.2, tipo_activo="estacion"), verbose=False)
        critico = AgenteSOC().procesar_evento(percepcion(**ev, criticidad_activo=1.0, tipo_activo="servidor_critico"), verbose=False)
        self.assertEqual(estacion["accion"], "AISLAR_HOST")
        self.assertNotEqual(critico["accion"], "AISLAR_HOST")

    def test_sin_penalizacion_al_riesgo_el_agente_ignora_casos_ambiguos(self):
        ambiguo = dict(tipo_alerta="login_anomalo", severidad_siem=5, reputacion_ip=0.2, trafico_anomalo=0.1,
                       intentos_fallidos=10, criticidad_activo=0.3, tipo_activo="estacion", ip_externa=False)
        con_riesgo = AgenteSOC().procesar_evento(percepcion(**ambiguo), verbose=False)
        sin_riesgo = AgenteSOC(pesos_utilidad=dict(exito=100, beneficio=0.5, riesgo=0.0, costo=30)).procesar_evento(
            percepcion(**ambiguo), verbose=False)
        self.assertEqual(con_riesgo["accion"], "ESCALAR_ANALISTA")
        self.assertEqual(sin_riesgo["accion"], "IGNORAR")  # w_r = 0: la amenaza residual deja de pesar


class TestEstadoInternoYFallos(unittest.TestCase):
    def test_host_aislado_no_se_vuelve_a_aislar(self):
        agente = AgenteSOC()
        p = percepcion(severidad_siem=10, reputacion_ip=1.0, trafico_anomalo=1.0, criticidad_activo=0.3, tipo_activo="estacion")
        self.assertEqual(agente.procesar_evento(p, verbose=False)["accion"], "AISLAR_HOST")
        self.assertIn("SRV-T", agente.hosts_aislados)
        self.assertEqual(agente.procesar_evento(copy.deepcopy(p), verbose=False)["accion"], "IGNORAR")

    def test_recurrencia_aumenta_la_sospecha(self):
        agente = AgenteSOC()
        p = percepcion(tipo_alerta="escaneo_puertos", severidad_siem=4, reputacion_ip=0.35, trafico_anomalo=0.3)
        p0 = agente.estimar_probabilidad_amenaza(p, 0)
        agente.alertas_por_ip[p.datos_sensores["ip_origen"]] = 4
        self.assertGreater(agente.estimar_probabilidad_amenaza(p, 4), p0)

    def test_alertas_repetidas_dejan_de_ignorarse(self):
        agente = AgenteSOC()
        acciones = []
        for i in range(6):
            p = percepcion(tipo_alerta="escaneo_puertos", severidad_siem=4, reputacion_ip=0.35, trafico_anomalo=0.3,
                           tipo_activo="servidor_interno", criticidad_activo=0.5, host=f"SRV-{i}")
            acciones.append(agente.procesar_evento(p, verbose=False)["accion"])
        self.assertEqual(acciones[0], "IGNORAR")          # la primera alerta aislada se descarta
        self.assertNotEqual(acciones[-1], "IGNORAR")      # la recurrencia de la misma IP ya no se ignora

    def test_sensor_invalido_lanza_value_error(self):
        with self.assertRaises(ValueError):
            AgenteSOC().procesar_evento(percepcion(severidad_siem=15), verbose=False)
        with self.assertRaises(ValueError):
            AgenteSOC().procesar_evento(Percepcion("X", {"tipo_alerta": "malware"}), verbose=False)

    def test_modo_seguro_escala_ante_datos_invalidos(self):
        agente = AgenteSOC()
        reg = agente.procesar_evento_seguro(percepcion(reputacion_ip="n/a"))
        self.assertEqual(reg["accion"], "ESCALAR_ANALISTA")
        self.assertEqual(len(agente.tickets), 1)

    def test_bloquear_ip_solo_si_es_externa(self):
        agente = AgenteSOC()
        p = percepcion(ip_externa=False)
        agente.actualizar_estado_interno(p)
        self.assertNotIn("BLOQUEAR_IP", agente._acciones_factibles(p))


class TestSimulacionYKPIs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eventos = generar_eventos(n=500, semilla=7)

    def test_reproducible(self):
        a = generar_eventos(n=50, semilla=1)
        b = generar_eventos(n=50, semilla=1)
        self.assertEqual([e.percepcion.datos_sensores for e in a], [e.percepcion.datos_sensores for e in b])

    def test_agente_supera_reglas_rigidas_en_deteccion(self):
        agente = evaluar(politica_agente(), self.eventos)
        reglas = evaluar(politica_reglas_rigidas(), self.eventos)
        self.assertGreater(agente["tasa_bloqueo_efectivo"], reglas["tasa_bloqueo_efectivo"])

    def test_agente_es_mas_rapido_que_escalar_todo(self):
        agente = evaluar(politica_agente(), self.eventos)
        todo = evaluar(politica_siempre_escalar(), self.eventos)
        self.assertLess(agente["mttc_min"], todo["mttc_min"])
        self.assertLess(agente["tasa_escalamiento"], 0.5)


if __name__ == "__main__":
    unittest.main()
