# Política de seguridad

## Datos sensibles

Este software procesa registros e información potencialmente confidencial. Los resultados de análisis pueden contener rutas, nombres de cuentas, direcciones IP y fragmentos de comandos.

- No subas evidencias ni informes de casos a repositorios públicos.
- Comprueba el contenido de archivos antes de ejecutar `git add`.
- Mantén la copia forense original inmutable y registra su cadena de custodia fuera de este proyecto.
- La IA local es opcional: verifica el modelo y la política de tratamiento de datos; la anonimización de indicios no está garantizada.
- El informe es preliminar y nunca confirma por sí solo una intrusión.

## Comunicar vulnerabilidades

Usa el mecanismo privado **Report a vulnerability** de GitHub (Security Advisories), si está habilitado en el repositorio. Evita publicar pruebas de explotación, detalles sensibles o muestras reales en issues.

Este MVP no ofrece garantías para uso en producción. Valida los resultados antes de utilizarlos en decisiones operativas.
