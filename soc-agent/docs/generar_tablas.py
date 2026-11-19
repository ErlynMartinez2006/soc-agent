"""Genera las tablas, datos de gráficas y fragmentos de código que usa informe.tex a partir del código real.

Uso (desde la raíz del repositorio):  python docs/generar_tablas.py
Así, las cifras del informe son siempre las que produce el prototipo.
"""
import inspect
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from soc_agent import AgenteSOC, config as cfg          # noqa: E402
from soc_agent.agente_soc import AgenteSOC as _A        # noqa: E402
from soc_agent.base import AgenteBasadoEnUtilidad       # noqa: E402
from soc_agent.escenarios import casos_de_prueba        # noqa: E402
from soc_agent.simulacion import analisis_sensibilidad, comparar_politicas, generar_eventos  # noqa: E402

OUT = RAIZ / "docs" / "generado"
OUT.mkdir(exist_ok=True)


def tex(s: str) -> str:
    return str(s).replace("_", r"\_")


def nombre(a: str) -> str:
    return r"\texttt{" + tex(a) + "}"


def coma(texto: str) -> str:
    """Convierte el punto decimal en coma (convención del informe en español)."""
    return texto.replace(".", ",")


def num(x, nd=2):
    return coma(f"{x:.{nd}f}").replace("-", "$-$") if isinstance(x, float) else str(x)


def escribir(nombre_archivo: str, contenido: str) -> None:
    (OUT / nombre_archivo).write_text(contenido, encoding="utf-8")


# ---- 1. Catálogo de acciones
filas = []
for a, v in cfg.ACCIONES.items():
    filas.append(coma(f"{nombre(a)} & {v['e']:.2f} & {v['t']:g} & {v['kappa']:.2f} & {v['f']:.1f} & {v['costo']:.2f} \\\\"))
escribir("tab_acciones.tex", "\\begin{tabular}{lccccc}\n\\toprule\nAcción $a$ & $e_a$ & $t_a$ (min) & $\\kappa_a$ & $f_a$ & $C_a$ \\\\\n\\midrule\n"
         + "\n".join(filas) + "\n\\bottomrule\n\\end{tabular}\n")

# ---- 2. Coeficientes del estimador
c = cfg.COEF
escribir("tab_coef.tex", coma("\\begin{tabular}{lcl}\n\\toprule\nTérmino & Coeficiente & Variable normalizada \\\\\n\\midrule\n"
         f"Sesgo $\\beta_0$ & $-${abs(cfg.SESGO):.1f} & --- \\\\\n"
         f"Reputación de la IP & {c['reputacion_ip']:.1f} & $r\\in[0,1]$ \\\\\n"
         f"Severidad del SIEM & {c['severidad']:.1f} & $s=\\text{{severidad}}/10$ \\\\\n"
         f"Tráfico anómalo & {c['trafico_anomalo']:.1f} & $\\tau\\in[0,1]$ \\\\\n"
         f"Intentos fallidos & {c['intentos']:.1f} & $\\min(n,20)/20$ \\\\\n"
         f"Recurrencia (estado interno) & {c['recurrencia']:.1f} & $\\min(k,5)/5$ \\\\\n"
         f"Bono por tipo: malware / exfiltración & {cfg.BONO_TIPO['malware']:.1f} & $b_{{\\text{{tipo}}}}$ \\\\\n"
         "\\bottomrule\n\\end{tabular}\n"))

# ---- 3. Escenarios (ejecutando el agente)
agente = AgenteSOC()
filas, ejemplo = [], None
for caso in casos_de_prueba():
    reg = agente.procesar_evento_seguro(caso["percepcion"])
    p = reg["metadatos"].get("p_amenaza")
    u = reg["utilidad"]
    ok = r"\checkmark" if reg["accion"] == caso["esperada"] else r"$\times$"
    filas.append(f"{caso['percepcion'].id_evento} & {caso['categoria']} & {caso['descripcion']} & "
                 f"{'---' if p is None else coma(f'{p:.2f}')} & {nombre(reg['accion'])} & "
                 f"{'---' if u is None else num(u)} & {ok} \\\\")
escribir("tab_escenarios.tex", "\\begin{tabularx}{\\textwidth}{llXcccc}\n\\toprule\nID & Categoría & Descripción & $p$ & Decisión del agente & $U^*$ & OK \\\\\n\\midrule\n"
         + "\n".join(filas) + "\n\\bottomrule\n\\end{tabularx}\n")

# ---- 4. Ejemplo trabajado de U(s,a) para EVT-06 (malware en servidor crítico)
caso = [c for c in casos_de_prueba() if c["percepcion"].id_evento == "EVT-06"][0]
ag = AgenteSOC()
perc = caso["percepcion"]
ag.actualizar_estado_interno(perc)
d = perc.datos_sensores
s_, c_ = d["severidad_siem"] / 10, d["criticidad_activo"]
filas = []
for est in ag.generar_estados_proyectados("AMENAZA_CONFIRMADA", perc):
    u = ag.calcular_utilidad(est)
    filas.append((u, coma(f"{nombre(est.nombre_accion)} & {est.probabilidad_exito:.3f} & {est.beneficio_operativo:.1f} & "
                          f"{est.riesgo_impacto:.3f} & {est.costo_intervencion:.2f} & ") + f"{num(u)} \\\\"))
filas.sort(key=lambda t: -t[0])
escribir("tab_ejemplo.tex", "\\begin{tabular}{lrrrrr}\n\\toprule\nAcción $a$ & $P_a$ & $B_a$ & $R_a$ & $C_a$ & $U(s,a)$ \\\\\n\\midrule\n"
         + "\n".join(f[1] for f in filas) + "\n\\bottomrule\n\\end{tabular}\n")
escribir("ejemplo_valores.tex", f"\\newcommand{{\\ejP}}{{{ag._p_amenaza:.3f}}}\n\\newcommand{{\\ejS}}{{{s_:.2f}}}\n\\newcommand{{\\ejC}}{{{c_:.2f}}}\n".replace(".", "{,}"))

# ---- 5. KPIs y sensibilidad
eventos = generar_eventos(n=1000, prevalencia=0.15, semilla=42)
comp = comparar_politicas(eventos)
filas = []
for k, v in comp.items():
    filas.append(coma(f"{k} & {v['mttc_min']:.2f} & {100 * v['tasa_bloqueo_efectivo']:.1f}\\,\\% & {v['amenazas_no_contenidas']} & "
                      f"{v['interrupciones_servicios_criticos']} & {v['falsos_positivos_afectados']} & {100 * v['tasa_escalamiento']:.1f}\\,\\% \\\\"))
n_amen = list(comp.values())[0]["amenazas_reales"]
escribir("tab_kpis.tex", "\\begin{tabular}{lrrrrrr}\n\\toprule\nPolítica & MTTC (min) & Bloqueo efectivo & No contenidas & Interrup. críticas & FP afectados & Escalamiento \\\\\n\\midrule\n"
         + "\n".join(filas) + "\n\\bottomrule\n\\end{tabular}\n")
escribir("n_amenazas.tex", f"\\newcommand{{\\nAmenazas}}{{{n_amen}}}\n")

sens = analisis_sensibilidad(eventos)
escribir("sens_bloqueo.dat", "\n".join(f"{f['w_riesgo']} {100 * f['tasa_bloqueo_efectivo']:.2f}" for f in sens))
escribir("sens_escalamiento.dat", "\n".join(f"{f['w_riesgo']} {100 * f['tasa_escalamiento']:.2f}" for f in sens))
escribir("sens_fp.dat", "\n".join(f"{f['w_riesgo']} {f['falsos_positivos_afectados']}" for f in sens))
filas = [coma(f"{f['w_riesgo']} & {100 * f['tasa_bloqueo_efectivo']:.1f}\\,\\% & {f['amenazas_no_contenidas']} & {f['falsos_positivos_afectados']} & {100 * f['tasa_escalamiento']:.1f}\\,\\% \\\\")
         for f in sens]
escribir("tab_sens.tex", "\\begin{tabular}{rrrrr}\n\\toprule\n$w_r$ & Bloqueo efectivo & No contenidas & FP afectados & Escalamiento \\\\\n\\midrule\n"
         + "\n".join(filas) + "\n\\bottomrule\n\\end{tabular}\n")


# ---- 6. Fragmentos de código tomados del repositorio
def fragmento(obj, archivo):
    escribir(archivo, inspect.getsource(obj))


fragmento(AgenteBasadoEnUtilidad.calcular_utilidad, "cod_utilidad.py")
fragmento(AgenteBasadoEnUtilidad.seleccionar_mejor_accion, "cod_seleccion.py")
fragmento(_A.proyectar, "cod_proyectar.py")
fragmento(_A.estimar_probabilidad_amenaza, "cod_estimador.py")
fragmento(_A.procesar_evento_seguro, "cod_seguro.py")
print("Archivos generados en", OUT)
