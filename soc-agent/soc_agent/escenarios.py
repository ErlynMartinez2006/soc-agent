"""Casos de prueba nombrados: rutinarios, ambiguos, críticos y extremos."""
from __future__ import annotations

from typing import Callable, Dict, List

from .modelos import Percepcion


def _p(id_evento: str, critico: bool = False, **sensores) -> Percepcion:
    base = dict(ip_externa=True, host="WS-014", ip_origen="203.0.113.10")
    base.update(sensores)
    return Percepcion(id_evento, base, contexto_critico=critico)


def casos_de_prueba() -> List[Dict]:
    """Devuelve los escenarios con su categoría y la acción esperada por el diseño."""
    return [
        {"categoria": "Rutinario", "descripcion": "Escaneo de puertos de baja severidad desde IP con buena reputación",
         "esperada": "IGNORAR",
         "percepcion": _p("EVT-01", tipo_alerta="escaneo_puertos", severidad_siem=3, reputacion_ip=0.10,
                          intentos_fallidos=0, trafico_anomalo=0.20, tipo_activo="estacion", criticidad_activo=0.30)},
        {"categoria": "Rutinario", "descripcion": "Un único fallo de login en estación, origen interno",
         "esperada": "IGNORAR",
         "percepcion": _p("EVT-02", tipo_alerta="login_anomalo", severidad_siem=2, reputacion_ip=0.05,
                          intentos_fallidos=1, trafico_anomalo=0.05, tipo_activo="estacion", criticidad_activo=0.25,
                          ip_externa=False, ip_origen="10.0.4.21", host="WS-022")},
        {"categoria": "Ambiguo", "descripcion": "Usuario legítimo (posible olvido de clave): 10 fallos, IP de reputación baja",
         "esperada": "ESCALAR_ANALISTA",
         "percepcion": _p("EVT-03", tipo_alerta="login_anomalo", severidad_siem=5, reputacion_ip=0.20,
                          intentos_fallidos=10, trafico_anomalo=0.10, tipo_activo="estacion", criticidad_activo=0.30,
                          ip_externa=False, ip_origen="10.0.7.55", host="WS-031")},
        {"categoria": "Ambiguo", "descripcion": "Inicio de sesión anómalo en servidor crítico, origen interno, evidencia mixta",
         "esperada": "ESCALAR_ANALISTA",
         "percepcion": _p("EVT-04", critico=True, tipo_alerta="login_anomalo", severidad_siem=6, reputacion_ip=0.40,
                          intentos_fallidos=5, trafico_anomalo=0.40, tipo_activo="servidor_critico",
                          criticidad_activo=0.95, ip_externa=False, host="SRV-ERP-01", ip_origen="10.0.9.14")},
        {"categoria": "Ambiguo", "descripcion": "Posible exfiltración desde servidor crítico hacia IP externa (contención de menor impacto)",
         "esperada": "BLOQUEAR_IP",
         "percepcion": _p("EVT-05", critico=True, tipo_alerta="exfiltracion", severidad_siem=6, reputacion_ip=0.40,
                          intentos_fallidos=0, trafico_anomalo=0.40, tipo_activo="servidor_critico",
                          criticidad_activo=0.95, host="SRV-FILE-01", ip_origen="198.51.100.77")},
        {"categoria": "Crítico", "descripcion": "Malware confirmado en servidor crítico, IP maliciosa conocida",
         "esperada": "AISLAR_HOST",
         "percepcion": _p("EVT-06", critico=True, tipo_alerta="malware", severidad_siem=9.5, reputacion_ip=0.90,
                          intentos_fallidos=0, trafico_anomalo=0.80, tipo_activo="servidor_critico",
                          criticidad_activo=0.95, host="SRV-DB-02", ip_origen="192.0.2.99")},
        {"categoria": "Crítico", "descripcion": "Fuerza bruta masiva desde IP maliciosa contra una estación",
         "esperada": "AISLAR_HOST",
         "percepcion": _p("EVT-07", tipo_alerta="fuerza_bruta", severidad_siem=7, reputacion_ip=0.80,
                          intentos_fallidos=15, trafico_anomalo=0.50, tipo_activo="estacion", criticidad_activo=0.30,
                          host="WS-040", ip_origen="203.0.113.200")},
        {"categoria": "Extremo", "descripcion": "Sensor corrupto: severidad fuera de rango (fail-safe)",
         "esperada": "ESCALAR_ANALISTA",
         "percepcion": _p("EVT-08", tipo_alerta="malware", severidad_siem=15, reputacion_ip=0.90,
                          intentos_fallidos=0, trafico_anomalo=0.80, tipo_activo="servidor_interno",
                          criticidad_activo=0.60, host="SRV-APP-03")},
        {"categoria": "Extremo", "descripcion": "Todos los indicadores al máximo en servidor crítico",
         "esperada": "AISLAR_HOST",
         "percepcion": _p("EVT-09", critico=True, tipo_alerta="malware", severidad_siem=10, reputacion_ip=1.0,
                          intentos_fallidos=20, trafico_anomalo=1.0, tipo_activo="servidor_critico",
                          criticidad_activo=1.0, host="SRV-AD-01", ip_origen="192.0.2.250")},
    ]
