/**
 * Configuración de Tailwind para el CSS COMPILADO (app/static/css/tailwind.css).
 *
 * Sustituye al CDN `cdn.tailwindcss.com` (Play CDN): ese script generaba los estilos en el navegador,
 * lo que obligaba a `style-src 'unsafe-inline'` y a permitir un script de terceros no versionado en la CSP.
 *
 * Versión fijada a la que servía el CDN (3.4.17) para que el resultado visual sea idéntico:
 *   bash scripts/build_css.sh
 *
 * REGLA: tras añadir/cambiar clases Tailwind en una plantilla hay que volver a ejecutar el script y commitear
 * el CSS. `tests/unit/test_tailwind_css.py` falla si una clase usada en las plantillas no está en el CSS.
 *
 * Las clases que JavaScript construye CONCATENANDO cadenas (p.ej. 'bg-' + color + '-100') no las ve el
 * compilador al escanear los archivos: deben ir en `safelist`.
 */
module.exports = {
  content: ['./app/templates/**/*.html'],
  safelist: [],
  theme: { extend: {} },
  plugins: [],
};
