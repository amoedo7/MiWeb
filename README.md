<div align="center">

# MiWeb

**Poné una URL. Recibí un diagnóstico técnico claro y exportable.**

[![CI](https://github.com/amoedo7/MiWeb/actions/workflows/ci.yml/badge.svg)](https://github.com/amoedo7/MiWeb/actions/workflows/ci.yml)

`HTTPS` · `headers` · `SEO técnico` · `HTML` · `accesibilidad básica` · `JSON`
</div>

---

## Qué revisa

MiWeb hace una lectura no destructiva de una URL pública y resume:

- estado HTTP y URL final;
- tiempo de respuesta observado;
- HTTPS;
- `Content-Type`;
- headers de seguridad habituales;
- `<title>` y meta description;
- canonical;
- Open Graph;
- cantidad de H1;
- imágenes sin `alt`;
- `robots.txt` y `sitemap.xml`;
- score técnico orientativo.

No intenta explotar vulnerabilidades ni realizar pruebas intrusivas.

## Ejecutar

```bash
python miweb.py https://example.com
```

Guardar informe:

```bash
python miweb.py https://example.com --output informe.json
```

Modo liviano, sin consultar `robots.txt` ni `sitemap.xml`:

```bash
python miweb.py https://example.com --light
```

## Ejemplo de salida

```json
{
  "schema": "desarrollamo.miweb.v1",
  "target": "https://example.com",
  "http": {"status": 200, "https": true},
  "seo": {"title": "Example Domain", "h1_count": 1},
  "security_headers": {"hsts": false},
  "summary": {"score": 72}
}
```

El score es una ayuda para leer el informe: **no reemplaza una auditoría de seguridad, accesibilidad o rendimiento especializada**.

---

**DesarrollAMO** · una URL puede ser el comienzo de una conversación concreta sobre qué mejorar.
