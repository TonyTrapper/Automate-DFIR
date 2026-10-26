# DFIR AI 🛡️

**Automatización forense de Windows con Hayabusa, reglas deterministas e IA local opcional.**

> **Estado:** MVP `v0.1.1` · análisis **offline** · Python 3.11+ · Windows (adquisición) / Kali Linux (análisis) · sin Docker.
>
> **Aviso:** Los hallazgos requieren validación humana. No confirman intrusiones y no sustituyen un análisis forense completo.

DFIR AI ayuda a convertir exportaciones de eventos de Windows y snapshots de seguridad en una **cronología de actividad**, **hallazgos con referencias a evidencia** e **informes preliminares**. Puede integrar Hayabusa para procesar EVTX y Ollama para redactar hipótesis de investigación sin depender de una API externa de IA.

**Los ejemplos son sintéticos. No hay datos de clientes en el repositorio.**

## Funcionalidades

- Ingesta de resultados de Hayabusa en **CSV, JSON y JSONL**, carpetas y archivos ZIP.
- Procesamiento de archivos `.evtx` con una instalación externa de **Hayabusa** (`--hayabusa`).
- Snapshot de Windows obtenido mediante un recopilador PowerShell de solo lectura de configuración y logs.
- Detecciones propias de actividad PowerShell, Defender, servicios, tareas, cuentas, autenticaciones y estado de seguridad.
- Correlaciones temporales; **proximidad no equivale a causalidad**.
- Registro **SHA-256 de archivos de entrada**, referencias `EventID`/`RecordID` cuando están disponibles.
- Exportación `JSON`, `CSV`, `Markdown`, `HTML` y `DOCX`.
- Análisis adicional mediante **Ollama en loopback**, desactivado por defecto.

## Arquitectura

```text
Windows (adquisición)                    Kali Linux (análisis)
┌─────────────────────────┐              ┌───────────────────────────────┐
│ PowerShell collector    │  ZIP/EVTX    │ Hayabusa (opcional para EVTX) │
│ Event Logs + Snapshot   ├─────────────►│ Ingesta y normalización       │
└─────────────────────────┘              │ Reglas + correlación         │
                                       │ IA local (Ollama, opcional)   │
Hayabusa CSV/JSON/JSONL ────────────────►│ Reportes y SHA-256            │
                                       └──────────────┬────────────────┘
                                                      │
                                hallazgos.json / timeline.csv / informe.*
```

## Instalación rápida (Kali / Linux)

```bash
python3 --version    # Requiere Python 3.11 o superior
git clone https://github.com/TU-USUARIO/dfir-ai.git
cd dfir-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Sustituye `TU-USUARIO` por tu cuenta cuando publiques el repositorio. Si usas el ZIP, descomprímelo y entra directamente a su carpeta; `git clone` no es necesario.

### Primera prueba con datos sintéticos

```bash
python3 main.py --input samples/hayabusa_demo.jsonl samples/security_snapshot.json --out salida_demo
```

Se generarán `salida_demo/hallazgos.json`, `salida_demo/timeline.csv`, `salida_demo/informe.md`, `salida_demo/informe.html` e `salida_demo/informe.docx` (si está instalado `python-docx`).

```bash
# Sin dependencias externas y sin informe DOCX:
python3 main.py -i samples/hayabusa_demo.jsonl -o salida_demo --no-docx

# Ejecutar pruebas:
python3 -m unittest discover -s tests -v
```

## Recolección de evidencias en Windows

En una consola de **PowerShell 5.1 como administrador**, desde `collectors/`:

```powershell
powershell.exe -NoProfile -File .\Collect-WindowsEvidence.ps1 -Destination C:\Temp\DFIR
```

Se crea un ZIP local con registros EVTX, un snapshot de configuración, un manifiesto de hashes y advertencias de adquisición. La herramienta no desactiva controles ni modifica políticas, pero crea archivos de salida en el destino elegido. Puede requerir privilegios administrativos y algunos canales pueden no existir.

**Preserva el ZIP original** con SHA-256, fecha/hora UTC, custodio y transferencia segura. No publiques el ZIP ni los informes resultantes.

## Análisis con Hayabusa

[Hayabusa, de Yamato Security](https://github.com/Yamato-Security/hayabusa), es una herramienta independiente. **No está incluida** en este repositorio. Requiere instalar Hayabusa y sus reglas siguiendo sus instrucciones oficiales.

**Alternativa A: exportar primero la cronología con Hayabusa:**

```bash
hayabusa dfir-timeline -d /ruta/a/EVTX -w -p super-verbose -U -t jsonl -o timeline.jsonl
python3 main.py -i timeline.jsonl -o casos/caso_001
```

**Alternativa B: procesar directamente un ZIP del recopilador:**

```bash
python3 main.py -i /ruta/a/evidencias_windows.zip --hayabusa hayabusa -o casos/caso_001
```

El programa invoca Hayabusa sin asistente (`-w`) para que pueda ejecutarse de forma automatizada. Necesitas tener el ejecutable en `PATH` y los archivos de reglas configurados según la instalación de Hayabusa. **Sin `--hayabusa`, los EVTX se omiten** y el sistema añade una advertencia.

Para analizar directamente un CSV/JSONL de Hayabusa no hace falta instalar el binario:

```bash
python3 main.py -i /ruta/timeline.jsonl -o casos/caso_002
```

Consulta las [opciones oficiales de `dfir-timeline`](https://github.com/Yamato-Security/hayabusa/blob/main/website/docs/commands/dfir-timeline.md).

## IA local opcional con Ollama

Si tienes Ollama funcionando de forma local y un modelo descargado:

```bash
ollama pull qwen2.5:7b
python3 main.py -i samples/hayabusa_demo.jsonl -o salida_ia --ai --model qwen2.5:7b
```

- Usa únicamente `http://127.0.0.1:11434/api/generate` (o un servicio HTTP en loopback configurado explícitamente).
- Envía un resumen reducido de los hallazgos, no los EVTX completos.
- Aplica un filtrado básico de algunos identificadores y secretos; **no garantiza anonimización**.
- Las respuestas de IA se etiquetan como **hipótesis no verificadas** y no alteran el nivel de severidad calculado.

## Detecciones en la versión 0.1

| Fuente | Condición que se evalúa | Interpretación |
|---|---|---|
| 4104 | Descarga y ejecución en PowerShell; patrones de codificación | Posible ejecución sospechosa |
| 5007 | Cambio de configuración de Defender | Modificación a revisar, no necesariamente desactivación |
| 7045 / 4697 | Instalación de servicios | Cambio que podría ser legítimo o persistencia |
| 4698 | Creación de tarea programada | Persistencia potencial |
| 1102 | Limpieza de registro Security | Actividad antiforense potencial |
| 4720 / 4732 | Alta de cuenta / modificación de grupo local Administrators | Cambio de identidad o privilegios |
| 4625 | 5+ fallos asociados a una IP y host en 5 minutos | Heurística de autenticación |
| 4104 + 5007 | Proximidad temporal de ±15 minutos en un host | Correlación, **no** causalidad |
| Snapshot | AutoAdminLogon, firewall, Defender y exclusiones | Configuración puntual |
| Hayabusa | Reglas de nivel `high`/`critical` con RuleID | Detecciones de terceros preservadas |

El motor propio **no interpreta Sigma directamente**; Hayabusa evalúa sus reglas y el programa procesa sus resultados.

## Resultado y trazabilidad

```text
casos/caso_001/
├── hallazgos.json      # Evidencias, alertas, SHA-256 de entradas, advertencias
├── timeline.csv        # Línea temporal normalizada
├── informe.md          # Informe preliminar
├── informe.html        # Consulta local
└── informe.docx        # Word, si está disponible python-docx
```

Cada hallazgo ofrece referencias a fuente, fecha, equipo, `EventID`, `RecordID` y regla Hayabusa cuando están disponibles. Los hashes documentan **las entradas que recibió el programa**, no sustituyen una cadena de custodia integral.

## Limitaciones actuales

- **MVP, no plataforma DFIR de producción:** no analiza memoria, MFT, Prefetch, Amcache, navegadores ni discos completos.
- El recopilador exporta los canales configurados que estén disponibles; no captura todos los artefactos posibles.
- La calidad de las alertas depende de logs habilitados, retención, reglas y cobertura de eventos.
- ZIP: límite de 250 MiB por entrada; máximo 200 000 eventos por defecto, con error al superarlo. Procesa conjuntos grandes por lotes.
- Se asume UTC para timestamps sin zona, por coherencia con exportaciones recomendadas de Hayabusa (`-U`). Comprueba la zona temporal del origen.
- La falta de alertas **no implica ausencia de compromiso**. Los falsos positivos son posibles.
- Los snapshots son configuraciones **actuales**, no reconstrucción histórica.
- No ejecutes evidencia de fuentes desconocidas y usa permisos mínimos.

## Próximas versiones

- Panel web local con búsqueda, filtros y revisión de hallazgos.
- Integración de más artefactos de Velociraptor/KAPE.
- Reglas configurables, supresión documentada de falsos positivos y pivoteo entre equipos.
- Mejoras en normalización, integridad y procesamiento de grandes evidencias.

## Contribución, seguridad y licencia

- [Guía para contribuir](CONTRIBUTING.md)
- [Seguridad y manejo de evidencias](SECURITY.md)
- [Historial de cambios](CHANGELOG.md)
- **Licencia:** aún no se ha seleccionado una licencia de distribución. Publicarlo en GitHub **no** concede automáticamente permisos de reutilización; añade una licencia explícita cuando decidas los términos.

**Uso autorizado exclusivamente.** La herramienta es de apoyo al analista; los hallazgos deben ser revisados antes de emitir conclusiones.
