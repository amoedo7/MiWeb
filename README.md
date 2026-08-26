<div align="center">

# WebAMO

**Poné una URL. Recibí una auditoría técnica visual, explicable y exportable desde Android.**

`TLS/DNS` · `headers` · `SEO` · `mini-crawl` · `assets` · `rendimiento` · `privacidad` · `accesibilidad` · `PWA/IA` · `historial` · `informe` · `JSON`

</div>

---

## WebAMO 0.1.2

WebAMO es el auditor web de DesarrollAMO. La app Android realiza lecturas públicas, defensivas y no destructivas desde el propio dispositivo, sin backend de WebAMO y sin cuenta.

La base nació como **MiWeb** y como la familia **AuditorWeb** para Termux/Python. La v0.1.2 conserva la auditoría profunda y el dashboard de 0.1.1 y agrega una salida más práctica: **Copiar informe** lleva al portapapeles exactamente el reporte legible que se comparte, sin abrir otra app. Compartir informe y Copiar JSON completo siguen disponibles por separado.

## Qué revisa

- HTTP/HTTPS, redirección HTTP→HTTPS, Content-Type, charset y señales de compresión;
- DNS visible, versión/cipher TLS y vigencia del certificado;
- HSTS, CSP y debilidades obvias, `nosniff`, Referrer-Policy, Permissions-Policy, clickjacking, contenido mixto y SRI;
- CORS mediante una lectura GET no destructiva, `security.txt`, X-Powered-By, versión de servidor y una lista muy conservadora de exposiciones públicas confirmables;
- title, description, canonical, noindex, H1/jerarquía, robots, sitemap, 404 real, JSON-LD, Open Graph, Twitter/X Card y viewport;
- mini-crawl de hasta 6 páginas para errores, titles/descriptions duplicadas, H1, canonical y noindex;
- inventario de assets y muestra de peso JS/CSS/imágenes, asset más pesado, caching, JS bloqueante, lazy loading, dimensiones de imágenes y tamaño del DOM fuente;
- accesibilidad estática: lang, headings, alt, nombres accesibles en botones/links, labels de inputs, IDs duplicados, tabindex, iframes, landmarks y zoom;
- trackers conocidos, cookies y flags, hosts terceros, políticas visibles y señales de APIs sensibles;
- fingerprint orientativo de plataforma, framework/stack, CDN/proxy, librerías, endpoints visibles, PWA, llms.txt y reglas de robots para crawlers de IA;
- historial local por dominio: puntaje anterior, delta, regresiones y hallazgos resueltos;
- informe legible compartible/copiante y JSON completo con todos los controles, severidad, recomendación, puntaje y cobertura.

## Dashboard

La pantalla principal muestra un anillo de puntaje, riesgo, cobertura, barras por área, prioridades ordenadas por severidad, mapa técnico, privacidad/terceros, historial y una vista expandible con todos los controles.

**N/V no significa aprobado ni desaprobado.** Significa que WebAMO no puede verificar honestamente esa señal con la capa disponible. Por ejemplo, Core Web Vitals reales y contraste visual necesitan navegador/renderizado o datos de campo; la app reduce la cobertura en vez de inventar un 100.

## Seguridad y límites

WebAMO no explota vulnerabilidades, no intenta credenciales, no envía formularios, no inicia sesión y no modifica el sitio auditado. La búsqueda de exposición pública se limita a unas pocas rutas conservadoras y sólo marca un problema cuando reconoce contenido compatible con ese tipo de archivo.

Los puntajes son orientativos: no reemplazan Lighthouse, un pentest, una auditoría WCAG completa ni una evaluación legal de privacidad.

## Android

Paquete: `com.desarrollamo.webamo`

Versión candidate: `0.1.2`

```bash
gradle :app:testDebugUnitTest :app:assembleDebug
```

El workflow `WebAMO Android` valida versión, paquete, permisos, integridad del APK y firma antes de publicar la candidate.

## CLI legado

`miweb.py` sigue disponible como auditor liviano de terminal. Los AuditorWeb más extensos fueron la referencia conceptual para ampliar la app Android.

---

**DesarrollAMO** · una URL puede ser el comienzo de una mejora concreta.
