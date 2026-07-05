"""
utils — Paquete de utilidades compartidas de NetSight.

Contiene helpers transversales que no son módulos de análisis en sí,
sino soporte usado antes/durante/después del análisis (p. ej.
validación de input, exportación de resultados). No debe contener
lógica de negocio de análisis heurístico.

Archivos:
    - validators: validar formato de dominio/IP antes de escanear.
    - export:     serializar el diccionario combinado de resultados a
                  un string JSON descargable (build_export_payload).
"""
