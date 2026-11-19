# Agente inteligente de triaje y respuesta ante incidentes de ciberseguridad (SOC)

Proyecto 1 del *Taller de Ingeniería de Agentes Inteligentes* (Los Libertadores). Agente basado en utilidad que
analiza alertas de un SOC y decide entre **ignorar, bloquear IP, revocar credenciales, aislar host o escalar a un analista**
maximizando `U(s,a) = w_e·P + w_b·B − w_r·R − w_c·C`.

## Ejecución (solo biblioteca estándar, Python ≥ 3.9)

```bash
python main.py                  # 9 escenarios + simulación de 1000 alertas + KPIs (guarda en resultados/)
python -m pytest -q             # 16 pruebas (o: python -m unittest discover tests)
python docs/generar_tablas.py   # regenera las tablas del informe a partir del código
cd docs && xelatex informe.tex && xelatex informe.tex   # compila el informe (TikZ)
```

## Estructura

| Ruta | Contenido |
|---|---|
| `soc_agent/modelos.py` | `Percepcion` (sensores, con validación) y `EstadoProyectado` |
| `soc_agent/base.py` | `AgenteBasadoEnUtilidad`: ciclo percepción → estado → utilidad → argmax → actuador |
| `soc_agent/config.py` | Pesos, catálogo de acciones y coeficientes del estimador de amenaza |
| `soc_agent/agente_soc.py` | `AgenteSOC`: estimador de amenaza, acciones factibles, actuadores, modo seguro |
| `soc_agent/escenarios.py` | Casos rutinarios, ambiguos, críticos y extremos |
| `soc_agent/simulacion.py` | Simulación con verdad de terreno, KPIs, líneas base y sensibilidad |
| `tests/test_agente.py` | Pruebas unitarias |
| `docs/informe.tex` / `informe.pdf` | Informe técnico en LaTeX |

## Subir a GitHub

```bash
git init && git add . && git commit -m "Agente SOC basado en utilidad"
git branch -M main
git remote add origin https://github.com/<tu-usuario>/soc-agent.git
git push -u origin main
```
