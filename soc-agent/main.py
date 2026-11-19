"""Ejecuta los escenarios de prueba y la simulación con KPIs. Uso: python main.py"""
import csv
import json
from pathlib import Path

from soc_agent import AgenteSOC
from soc_agent.escenarios import casos_de_prueba
from soc_agent.simulacion import analisis_sensibilidad, comparar_politicas, generar_eventos

SALIDA = Path(__file__).parent / "resultados"


def correr_escenarios() -> list:
    print("=" * 72)
    print("PARTE 1: CASOS DE PRUEBA (rutinarios, ambiguos, críticos y extremos)")
    print("=" * 72)
    agente = AgenteSOC()
    filas = []
    for caso in casos_de_prueba():
        reg = agente.procesar_evento_seguro(caso["percepcion"], verbose=True)
        ok = reg["accion"] == caso["esperada"]
        print(f"  [{caso['categoria']}] {caso['descripcion']}\n  Esperada: {caso['esperada']} | Obtenida: {reg['accion']} -> {'OK' if ok else 'FALLA'}")
        filas.append({"evento": reg["evento"], "categoria": caso["categoria"], "descripcion": caso["descripcion"],
                      "p_amenaza": reg["metadatos"].get("p_amenaza"), "esperada": caso["esperada"],
                      "obtenida": reg["accion"], "utilidad": reg["utilidad"], "utilidades": reg["utilidades"], "ok": ok})
    print("\nBitácora de actuadores:")
    for linea in agente.bitacora_actuadores:
        print("  -", linea)
    return filas


def correr_simulacion() -> tuple:
    print("\n" + "=" * 72)
    print("PARTE 2: SIMULACIÓN (1000 alertas sintéticas, semilla 42) Y KPIs")
    print("=" * 72)
    eventos = generar_eventos(n=1000, prevalencia=0.15, semilla=42)
    comp = comparar_politicas(eventos)
    cab = ["MTTC(min)", "Bloqueo efectivo", "No contenidas", "Interrup. críticas", "FP afectados", "Escalamiento"]
    print(f"{'Política':<20}" + "".join(f"{c:>19}" for c in cab))
    for nombre, k in comp.items():
        print(f"{nombre:<20}{k['mttc_min']:>19}{k['tasa_bloqueo_efectivo']:>19}{k['amenazas_no_contenidas']:>19}"
              f"{k['interrupciones_servicios_criticos']:>19}{k['falsos_positivos_afectados']:>19}{k['tasa_escalamiento']:>19}")
    sens = analisis_sensibilidad(eventos)
    print("\nSensibilidad al peso de riesgo w_r:")
    for f in sens:
        print(f"  w_r={f['w_riesgo']:>5}: bloqueo={f['tasa_bloqueo_efectivo']}, FP afectados={f['falsos_positivos_afectados']}, "
              f"escalamiento={f['tasa_escalamiento']}")
    return comp, sens


def guardar(filas, comp, sens) -> None:
    SALIDA.mkdir(exist_ok=True)
    (SALIDA / "escenarios.json").write_text(json.dumps(filas, indent=2, ensure_ascii=False), encoding="utf-8")
    (SALIDA / "comparacion_kpis.json").write_text(json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(SALIDA / "sensibilidad.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sens[0]))
        w.writeheader()
        w.writerows(sens)
    print(f"\nResultados guardados en {SALIDA}")


if __name__ == "__main__":
    filas = correr_escenarios()
    comp, sens = correr_simulacion()
    guardar(filas, comp, sens)
