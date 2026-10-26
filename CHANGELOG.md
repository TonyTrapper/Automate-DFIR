# Historial de cambios

## v0.1.1 — 2026-10-26

- Preparación para repositorio público: README, `.gitignore`, política de seguridad y pruebas CI.
- Ejecución de Hayabusa con `-w` (no-wizard) para el procesamiento automatizado.
- Interpretación UTC coherente para timestamps sin zona explícita.
- Corrección del orden de generación DOCX para que las advertencias queden en todos los resultados.
- Validación de `--max-events` y parámetro `--version`.

## v0.1.0 — 2026-10-26

- MVP: ingesta de JSONL/CSV/JSON/ZIP y snapshots de Windows.
- Detecciones deterministas, correlación temporal, hashes de entradas y exportación de informes.
- Recopilador PowerShell y revisión opcional con Ollama local.
