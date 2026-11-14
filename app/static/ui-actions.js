/**
 * SOC Agent - despachador de acciones de UI (compatible con CSP estricta).
 *
 * Sustituye a los handlers inline (onclick="...", onchange="...") que una CSP sin
 * 'unsafe-inline' bloquea. Las plantillas declaran la acción con atributos data-*:
 *
 *   <button data-action="doExport" data-args='["pdf"]'>      click  -> doExport('pdf')
 *   <select data-change="changeLLMProvider">                 change -> changeLLMProvider()
 *   <input  data-input="checkStrength">                      input  -> checkStrength()
 *   <input  data-enter="addNote">                            Enter  -> addNote()
 *   <button data-hide="export-modal">                        click  -> #export-modal.classList.add('hidden')
 *   <button data-remove-ancestor="2">                        click  -> elimina el 2º ancestro
 *   <button data-reload>                                     click  -> location.reload()
 *
 * Reglas de seguridad:
 *  - Solo se invocan FUNCIONES GLOBALES existentes, por nombre (validado con regex).
 *    Nunca se evalúa texto (no eval / new Function), que es justo lo que la CSP prohíbe.
 *  - data-args se parsea con JSON.parse: son datos, no código.
 *  - Los argumentos del servidor deben emitirse con |tojson (Jinja) o JSON.stringify + escapeHtml.
 */
(function () {
    'use strict';

    var NAME = /^[A-Za-z_$][\w$]*$/;

    function parseArgs(el) {
        var raw = el.getAttribute('data-args');
        if (!raw) return [];
        try {
            var parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : [parsed];
        } catch (e) {
            console.error('ui-actions: data-args no es JSON válido', raw);
            return null;
        }
    }

    function invoke(el, attr, ev) {
        var name = el.getAttribute(attr);
        if (!name || !NAME.test(name)) return;
        var fn = window[name];
        if (typeof fn !== 'function') {
            console.error('ui-actions: función global no encontrada:', name);
            return;
        }
        var args = parseArgs(el);
        if (args === null) return;
        fn.apply(el, args);
    }

    // Recorre desde el objetivo hasta el document respetando el burbujeo, igual que los
    // handlers inline (un ancestro con acción también se ejecuta).
    function walk(ev, selectorAttr, handler) {
        var el = ev.target;
        while (el && el !== document) {
            if (el.nodeType === 1 && el.hasAttribute(selectorAttr)) handler(el, ev);
            el = el.parentElement;
        }
    }

    document.addEventListener('click', function (ev) {
        walk(ev, 'data-action', function (el) { invoke(el, 'data-action', ev); });

        walk(ev, 'data-hide', function (el) {
            var target = document.getElementById(el.getAttribute('data-hide'));
            if (target) target.classList.add('hidden');
        });

        walk(ev, 'data-remove-ancestor', function (el) {
            var n = parseInt(el.getAttribute('data-remove-ancestor'), 10) || 1;
            var node = el;
            for (var i = 0; i < n && node; i++) node = node.parentElement;
            if (node) node.remove();
        });

        walk(ev, 'data-reload', function () { window.location.reload(); });
    });

    document.addEventListener('change', function (ev) {
        walk(ev, 'data-change', function (el) { invoke(el, 'data-change', ev); });
    });

    document.addEventListener('input', function (ev) {
        walk(ev, 'data-input', function (el) { invoke(el, 'data-input', ev); });
    });

    document.addEventListener('keydown', function (ev) {
        if (ev.key !== 'Enter') return;
        walk(ev, 'data-enter', function (el) { invoke(el, 'data-enter', ev); });
    });
})();
