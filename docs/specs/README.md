# Especificaciones SOM

Esta carpeta es la fuente de requisitos para el desarrollo guiado por especificaciones (SDD). Cada cambio funcional debe partir de una especificación revisable y terminar con criterios de aceptación cubiertos o con pendientes declarados.

## Flujo de trabajo

1. Identifica el documento de especificación relacionado y confirma el alcance.
2. Si la solicitud cambia reglas o alcance, actualiza primero la especificación y marca la propuesta como `Propuesta` hasta acordar el comportamiento.
3. Implementa solo los criterios aceptados. Mantén requisitos de seguridad y límites de integración explícitos.
4. Ejecuta los comandos de verificación definidos en `docs/TESTING.md` y añade pruebas sintéticas cuando corresponda.
5. Actualiza el estado de implementación y anota límites, decisiones o criterios aún sin cubrir.

Los estados usados son: `Especificado`, `Parcial`, `Implementado` y `Bloqueado por información`. `Implementado` exige código y verificación; no basta con tener una pantalla o una interfaz vacía.

## Índice

| ID | Especificación | Estado actual |
|---|---|---|
| SOM-000 | [Producto y alcance](./SOM-000-producto.md) | Parcial |
| SOM-010 | [Aplicación de escritorio y seguridad local](./SOM-010-escritorio-seguridad.md) | Parcial |
| SOM-020 | [Infraestructura Hillstone](./SOM-020-infraestructura.md) | Parcial |
| SOM-030 | [Importación y custodia de respaldos](./SOM-030-respaldos.md) | Parcial |
| SOM-040 | [Actividades, análisis y reportes](./SOM-040-operaciones-reportes.md) | Parcial |
| SOM-050 | [Instalación y distribución Windows](./SOM-050-distribucion.md) | Especificado |

## Plantilla

Usa [SPEC_TEMPLATE.md](./SPEC_TEMPLATE.md) para nuevos módulos. Las especificaciones describen el comportamiento esperado; el estado real se contrasta con el código y las pruebas antes de marcarlo implementado.
