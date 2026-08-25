<div align="center">

# WebAMO

**Poné una URL. Recibí una auditoría técnica clara desde el teléfono.**

`HTTPS` · `headers` · `SEO técnico` · `rendimiento` · `accesibilidad básica` · `trackers` · `cookies` · `JSON`

</div>

---

## Qué es

WebAMO es el auditor web de DesarrollAMO. La app Android hace una lectura pública y no intrusiva desde el propio dispositivo, sin backend de WebAMO y sin cuenta.

La base nació como **MiWeb**, un auditor CLI para Termux/Python. Ese motor se conserva en `miweb.py` como herramienta de escritorio/terminal; la aplicación Android es la evolución orientada a uso cotidiano.

## Qué revisa la app Android

- estado HTTP, redirección final y tiempo de respuesta observado;
- HTTPS;
- headers de seguridad: HSTS, CSP, `nosniff`, Referrer-Policy, Permissions-Policy y protección de frames;
- `<title>`, meta description, canonical, idioma y cantidad de H1;
- imágenes sin `alt`;
- presencia de `robots.txt` y `sitemap.xml`;
- firmas conocidas de Google Analytics, GTM, Google Ads/DoubleClick, Meta Pixel, Hotjar, Microsoft Clarity, TikTok Pixel y LinkedIn Insight;
- cookies expuestas mediante `Set-Cookie` en la respuesta;
- puntajes separados de Seguridad, SEO, Rendimiento, Privacidad (señales) y Accesibilidad básica;
- informe compartible y JSON exportable.

## Límites deliberados

WebAMO **no ejecuta exploits, no intenta saltar autenticación y no hace pentesting**. Tampoco ejecuta JavaScript como un navegador completo, así que un tracker cargado dinámicamente puede no aparecer en la lectura inicial. El puntaje es orientativo y no debe presentarse como Lighthouse, auditoría legal de privacidad ni certificación de seguridad.

## Android

Paquete: `com.desarrollamo.webamo`

Versión inicial: `0.1.0`

Compilar:

```bash
gradle :app:testDebugUnitTest :app:assembleDebug
```

El workflow `WebAMO Android` valida paquete, versión, permisos y firma antes de publicar el APK de la candidate.

## CLI legado

```bash
python miweb.py https://example.com
python miweb.py https://example.com --output informe.json
```

---

**DesarrollAMO** · una URL puede ser el comienzo de una mejora concreta.
