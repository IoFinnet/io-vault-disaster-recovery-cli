// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

/*
 * io.finnet Disaster Recovery Tool — browser UI.
 *
 * A dependency-free single page app. It talks only to this tool's own localhost API:
 *   POST /api/list-zip-files  list the entries of an uploaded ZIP
 *   POST /api/verify          check which file holds which vault share (no key is rebuilt)
 *   POST /api/list-vaults     list the vaults the files can recover
 *   POST /api/recover         rebuild one vault's keys
 *
 * Security notes:
 * - Every value that came from a file or the server is HTML-escaped before rendering.
 * - Recovered secrets live only in the `secrets` map below. They are written into the DOM
 *   only while the user has revealed them, and are wiped by "Clear keys and finish".
 * - The page loads no remote resources (the server's CSP forbids it anyway).
 */
(() => {
    'use strict';

    // ------------------------------------------------------------------
    // Icons: Tabler outline glyphs (MIT licence), 24px grid, 1.5px stroke.
    // ------------------------------------------------------------------
    const ICONS = {
        home: ['M5 12l-2 0l9 -9l9 9l-2 0', 'M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7', 'M9 21v-6a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v6'],
        shieldCheck: ['M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06', 'M15 19l2 2l4 -4'],
        key: ['M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z', 'M15 9h.01'],
        terminal: ['M5 7l5 5l-5 5', 'M12 19l7 0'],
        book: ['M3 19a9 9 0 0 1 9 0a9 9 0 0 1 9 0', 'M3 6a9 9 0 0 1 9 0a9 9 0 0 1 9 0', 'M3 6l0 13', 'M12 6l0 13', 'M21 6l0 13'],
        file: ['M14 3v4a1 1 0 0 0 1 1h4', 'M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z'],
        lock: ['M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z', 'M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0', 'M8 11v-4a4 4 0 1 1 8 0v4'],
        upload: ['M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2', 'M7 9l5 -5l5 5', 'M12 4l0 12'],
        plus: ['M12 5l0 14', 'M5 12l14 0'],
        trash: ['M4 7l16 0', 'M10 11l0 6', 'M14 11l0 6', 'M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12', 'M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3'],
        phone: ['M6 5a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v14a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2v-14z', 'M11 4h2', 'M12 17v.01'],
        folder: ['M5 4h4l3 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2'],
        server: ['M3 7a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z', 'M3 15a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z', 'M7 8l0 .01', 'M7 16l0 .01'],
        arrowLeft: ['M5 12l14 0', 'M5 12l6 6', 'M5 12l6 -6'],
        arrowRight: ['M5 12l14 0', 'M13 18l6 -6', 'M13 6l6 6'],
        check: ['M5 12l5 5l10 -10'],
        alert: ['M12 9v4', 'M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z', 'M12 16h.01'],
        info: ['M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0', 'M12 9h.01', 'M11 12h1v4h1'],
        eye: ['M10 12a2 2 0 1 0 4 0a2 2 0 0 0 -4 0', 'M21 12c-2.4 4 -5.4 6 -9 6c-3.6 0 -6.6 -2 -9 -6c2.4 -4 5.4 -6 9 -6c3.6 0 6.6 2 9 6'],
        eyeOff: ['M10.585 10.587a2 2 0 0 0 2.829 2.828', 'M16.681 16.673a8.717 8.717 0 0 1 -4.681 1.327c-3.6 0 -6.6 -2 -9 -6c1.272 -2.12 2.712 -3.678 4.32 -4.674m2.86 -1.146a9.055 9.055 0 0 1 1.82 -.18c3.6 0 6.6 2 9 6c-.666 1.11 -1.379 2.067 -2.138 2.87', 'M3 3l18 18'],
        copy: ['M7 9.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667z', 'M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1'],
        download: ['M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2', 'M7 11l5 5l5 -5', 'M12 4l0 12'],
        history: ['M12 8l0 4l2 2', 'M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5'],
        x: ['M18 6l-12 12', 'M6 6l12 12'],
        externalLink: ['M12 6h-6a2 2 0 0 0 -2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-6', 'M11 13l9 -9', 'M15 4h5v5'],
        loader: ['M12 3a9 9 0 1 0 9 9'],
        wallet: ['M17 8v-3a1 1 0 0 0 -1 -1h-10a2 2 0 0 0 0 4h12a1 1 0 0 1 1 1v3m0 4v3a1 1 0 0 1 -1 1h-12a2 2 0 0 1 -2 -2v-12', 'M20 12v4h-4a2 2 0 0 1 0 -4h4'],
        coin: ['M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0', 'M14.8 9a2 2 0 0 0 -1.8 -1h-2a2 2 0 1 0 0 4h2a2 2 0 1 1 0 4h-2a2 2 0 0 1 -1.8 -1', 'M12 7v10'],
    };
    const SHIELD = 'M12 2.5c2.6 1.9 5.4 2.9 8.5 3c.5 6.9 -2.3 12 -8.5 15.5c-6.2 -3.5 -9 -8.6 -8.5 -15.5c3.1 -.1 5.9 -1.1 8.5 -3z';

    function svgIcon(name) {
        const paths = ICONS[name] || [];
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' +
            paths.map((d) => '<path d="' + d + '"/>').join('') + '</svg>';
    }
    function icon(name, extraClass) {
        return '<span class="icon ' + (extraClass || '') + '" aria-hidden="true">' + svgIcon(name) + '</span>';
    }
    function hydrateIcons(root) {
        root.querySelectorAll('[data-icon]').forEach((el) => {
            el.innerHTML = svgIcon(el.getAttribute('data-icon'));
            el.setAttribute('aria-hidden', 'true');
        });
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------
    const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    function esc(value) {
        return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (c) => ESCAPES[c]);
    }
    function truncateMiddle(value, head, tail) {
        const s = String(value || '');
        head = head || 6;
        tail = tail || 4;
        return s.length <= head + tail + 1 ? s : s.slice(0, head) + '…' + s.slice(-tail);
    }
    function baseNoExt(name) {
        const i = name.lastIndexOf('.');
        return i > 0 ? name.slice(0, i) : name;
    }
    function ext(name) {
        const i = name.lastIndexOf('.');
        return i >= 0 ? name.slice(i).toLowerCase() : '';
    }
    function normalizeMnemonic(text) {
        return String(text || '').replace(/\s+/g, ' ').trim();
    }
    function wordCount(text) {
        const n = normalizeMnemonic(text);
        return n ? n.split(' ').length : 0;
    }
    function plural(n, one, many) {
        return n + ' ' + (n === 1 ? one : (many || one + 's'));
    }
    function formatDate(value) {
        const d = value ? new Date(value) : new Date();
        if (isNaN(d.getTime())) {
            return String(value);
        }
        return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    }
    function cssId(value) {
        return String(value).replace(/[^A-Za-z0-9_-]/g, '_');
    }

    async function copyText(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (_) { /* fall back below */ }
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        // An open modal <dialog> (the chain tool) makes everything outside it inert, so a textarea
        // appended to <body> could not be selected. Put it inside the open dialog instead.
        const host = document.querySelector('dialog[open]') || document.body;
        host.appendChild(area);
        area.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
        area.value = '';
        area.remove();
        return ok;
    }

    let toastTimer = null;
    function toast(message) {
        const el = document.getElementById('toast');
        el.textContent = message;
        el.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
    }

    async function postForm(url, formData) {
        const res = await fetch(url, { method: 'POST', body: formData, credentials: 'same-origin' });
        if (!res.ok) {
            const text = (await res.text()).trim();
            if (res.status === 404) {
                throw new Error('This build of the recovery tool does not support this action (' + url + ').');
            }
            throw new Error(text || ('Request failed with status ' + res.status));
        }
        return res.json();
    }

    // ------------------------------------------------------------------
    // Reusable markup pieces (design system patterns)
    // ------------------------------------------------------------------
    function badge(tone, text) {
        return '<span class="badge ' + esc(tone || '') + '">' + esc(text) + '</span>';
    }
    function vaultBadge(threshold, opts) {
        opts = opts || {};
        const label = threshold ? String(threshold) : '?';
        return '<span class="vault-badge' + (opts.lg ? ' lg' : '') + (opts.mono ? ' mono' : '') + '" role="img" aria-label="Threshold ' + esc(label) + '">' +
            '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="' + SHIELD + '" fill="currentColor"/></svg><span>' + esc(label) + '</span></span>';
    }
    function copyField(value, opts) {
        opts = opts || {};
        const shown = opts.full ? value : truncateMiddle(value, opts.head || 6, opts.tail || 4);
        return '<button type="button" class="copy-field' + (opts.full ? ' full' : '') + (opts.compact ? ' compact' : '') + '" data-action="copy-value" data-value="' + esc(value) + '" title="' + esc(value) + '" aria-label="' + esc(opts.label || 'Copy') + '">' +
            '<span class="value">' + esc(shown) + '</span>' + icon('copy') + '</button>';
    }
    function kv(label, valueHtml) {
        return '<div class="kv"><span class="kv-label">' + esc(label) + '</span><span class="kv-value">' + valueHtml + '</span></div>';
    }
    function alertBox(tone, title, bodyHtml) {
        const glyph = tone === 'success' ? 'check' : (tone === 'info' ? 'info' : 'alert');
        return '<div class="alert ' + esc(tone) + '" role="' + (tone === 'danger' ? 'alert' : 'status') + '">' + icon(glyph) +
            '<div class="alert-body"><span class="alert-title">' + esc(title) + '</span>' + (bodyHtml ? '<span>' + bodyHtml + '</span>' : '') + '</div></div>';
    }
    function card(title, subtitle, bodyHtml, extraClass) {
        return '<section class="card ' + (extraClass || '') + '">' +
            '<header class="card-header"><div class="stack-sm" style="gap:2px"><h2 class="card-title">' + esc(title) + '</h2>' +
            (subtitle ? '<span class="card-subtitle">' + esc(subtitle) + '</span>' : '') + '</div></header>' +
            '<div class="card-body">' + bodyHtml + '</div></section>';
    }
    function stepper(steps, active) {
        const parts = [];
        steps.forEach((label, i) => {
            const cls = i < active ? 'done' : (i === active ? 'active' : '');
            if (i > 0) {
                parts.push('<span class="step-connector' + (i <= active ? ' done' : '') + '" aria-hidden="true"></span>');
            }
            parts.push('<span class="step ' + cls + '"' + (i === active ? ' aria-current="step"' : '') + '><span class="step-marker">' +
                (i < active ? icon('check') : String(i + 1)) + '</span><span>' + esc(label) + '</span></span>');
        });
        return '<nav class="stepper" aria-label="Progress">' + parts.join('') + '</nav>';
    }
    function pageHeader(opts) {
        return '<header class="page-header"><div class="page-header-main">' + (opts.media || '') +
            '<div class="page-header-text"><h1 class="page-title" tabindex="-1">' + esc(opts.title) + (opts.status || '') + '</h1>' +
            (opts.subtitle ? '<p class="page-subtitle">' + esc(opts.subtitle) + '</p>' : '') +
            (opts.meta ? '<div class="inline">' + opts.meta + '</div>' : '') + '</div></div>' +
            (opts.actions ? '<div class="page-actions">' + opts.actions + '</div>' : '') + '</header>';
    }
    function localTag() {
        return '<span class="tag">' + icon('lock', 'icon-14') + 'Runs locally · no network calls</span>';
    }
    function tileList(items) {
        return '<ol class="stack" style="list-style:none;margin:0;padding:0">' + items.map((item, i) =>
            '<li class="inline" style="align-items:flex-start;flex-wrap:nowrap;gap:12px">' +
            '<span class="choice-media" style="width:28px;height:28px;background:var(--io-blue-50);font-weight:600;font-size:var(--io-text-label)">' + (i + 1) + '</span>' +
            '<span class="stack-sm" style="gap:2px"><span style="font-weight:500">' + esc(item[0]) + '</span><span class="small muted">' + esc(item[1]) + '</span></span></li>'
        ).join('') + '</ol>';
    }

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    let nextId = 1;
    const secrets = new Map();

    function freshOptions() {
        return { threshold: '', requestId: '', nonce: '', exportWallet: false, exportFile: '', password: '', hdFile: null };
    }

    // Phrase and skip state is keyed by a name taken from a file name. A prototype-less object
    // keeps a file called e.g. "constructor.json" from reading an inherited Object member.
    function freshKeyed() {
        return Object.create(null);
    }

    const state = {
        view: 'home',
        loadingFor: '',
        task: 'verify',
        sources: { mobile: false, vs: false, hd: false },
        phraseIndex: 0,
        skipped: freshKeyed(),
        files: [],
        keys: [],
        mnemonics: freshKeyed(),
        error: '',
        busyText: '',
        report: null,
        reportFilter: 'all',
        vaults: null,
        vaultInfo: {},
        vaultSources: [],
        selectedVaultId: null,
        options: freshOptions(),
        recovered: null,
        recoveredVault: null,
        revealed: {},
        chain: null,
        network: null, // null until the first check: { connected, adapters, unknown? }
        allowConnected: false, // the user confirmed recovering on a connected computer
    };

    // Results belong to the inputs that produced them. When an input changes the result is dropped,
    // so the sidebar can never reopen a report or vault list that no longer describes the files,
    // keys and phrases on screen. Changing views alone keeps them.
    //   report: files, keys, entered or skipped phrases, and the HD addresses CSV.
    //   vault list: files, keys and phrases (the CSV is not sent to list vaults).
    function invalidateReport() {
        state.report = null;
    }
    function invalidateResults() {
        invalidateReport();
        state.vaults = null;
        state.vaultInfo = {};
        state.vaultSources = [];
        // state.selectedVaultId is kept on purpose: it is only a preference (e.g. the vault the user
        // chose with Recover on the report), and loadVaults checks it against the new list.
    }

    // Forgets one export's phrase, skip and reveal state.
    function forgetPhrase(key) {
        state.mnemonics[key] = '';
        delete state.mnemonics[key];
        delete state.skipped[key];
        delete state.revealed['mn:' + key];
    }

    // ------------------------------------------------------------------
    // Files and keys
    // ------------------------------------------------------------------
    function fileType(name) {
        switch (ext(name)) {
            case '.json': return 'json';
            case '.dr': return 'dr';
            case '.zip': return 'zip';
            case '.pem': return 'pem';
            default: return '';
        }
    }

    // Which file types each drop zone takes: mobile exports, or Virtual Signer files and keys.
    const GROUP_TYPES = { mobile: ['json', 'zip'], vs: ['dr', 'zip', 'pem'] };

    function addFiles(fileList, group) {
        group = GROUP_TYPES[group] ? group : 'mobile';
        let rejected = [];
        let added = 0;
        Array.from(fileList || []).forEach((file) => {
            const type = fileType(file.name);
            if (!type || GROUP_TYPES[group].indexOf(type) < 0) {
                rejected.push(file.name);
                return;
            }
            if (type === 'pem') {
                if (!state.keys.some((k) => k.name === file.name && k.file.size === file.size)) {
                    state.keys.push({ id: nextId++, name: file.name, file: file });
                    added++;
                }
                return;
            }
            if (state.files.some((f) => f.name === file.name)) {
                toast('A file named ' + file.name + ' is already in the list.');
                return;
            }
            const entry = { id: nextId++, name: file.name, file: file, type: type, group: group, zip: null, signer: null };
            state.files.push(entry);
            added++;
            if (type === 'zip') {
                entry.zip = { status: 'loading', kind: '', entries: [], error: '' };
                listZip(entry);
            } else if (type === 'json') {
                readSignerInfo(entry);
            }
        });
        if (rejected.length) {
            toast('Skipped ' + rejected.join(', ') + (group === 'mobile'
                ? ': mobile app exports are .json files or a ZIP of them.'
                : ': Virtual Signer backups are .dr files, a bundle .zip, or an ML-KEM-768 key (.pem).'));
        }
        if (added) {
            state.error = '';
            invalidateResults();
        }
        render();
    }

    async function listZip(entry) {
        const fd = new FormData();
        fd.append('zipFile', entry.file, entry.name);
        try {
            const names = await postForm('/api/list-zip-files', fd);
            const list = Array.isArray(names) ? names : [];
            // The server lists a signer bundle's .dr files only (never its manifest). A ZIP holding
            // only .dr files is treated the same way: it needs a key, not mnemonics.
            const isBundle = list.some((n) => n.toLowerCase() === 'manifest.json') ||
                (list.length > 0 && list.every((n) => ext(n) === '.dr'));
            entry.zip = {
                status: 'ready',
                kind: isBundle ? 'bundle' : 'archive',
                entries: list.filter((n) => !(isBundle && n.toLowerCase() === 'manifest.json')),
                error: '',
            };
        } catch (err) {
            entry.zip = { status: 'error', kind: '', entries: [], error: err.message };
        }
        if (state.view === 'files') {
            render();
        }
    }

    // Every JSON export, direct or inside a ZIP archive, is unlocked by its own 24-word mnemonic.
    // The server matches a mnemonic to its file with the form field mnemonic_<name without extension>.
    function mnemonicTargets() {
        const targets = [];
        state.files.forEach((f) => {
            if (f.type === 'json') {
                targets.push({ key: baseNoExt(f.name), label: f.name, fileId: f.id, signer: f.signer || null });
            } else if (f.type === 'zip' && f.zip && f.zip.kind === 'archive') {
                f.zip.entries.filter((n) => ext(n) === '.json').forEach((n) => {
                    targets.push({ key: baseNoExt(n), label: n + ' (in ' + f.name + ')', fileId: f.id, fromZip: true });
                });
            }
        });
        return targets;
    }
    function mnemonicState(key) {
        const wc = wordCount(state.mnemonics[key]);
        if (wc === 0) { return 'empty'; }
        return wc === 24 ? 'ready' : 'partial';
    }
    // Two uploads with the same field name would both claim one recovery phrase. A Set (not a
    // plain object) so a name such as "constructor" is not already "seen" through the prototype.
    function duplicateMnemonicKeys() {
        const seen = new Set();
        const dups = [];
        mnemonicTargets().forEach((t) => {
            if (seen.has(t.key)) { dups.push(t.key); }
            seen.add(t.key);
        });
        return dups;
    }
    function drCount(f) {
        if (f.type === 'dr') { return 1; }
        if (f.type === 'zip' && f.zip) { return f.zip.entries.filter((n) => ext(n) === '.dr').length; }
        return 0;
    }
    function needsKey() {
        return state.files.some((f) => drCount(f) > 0);
    }

    function describeFile(f) {
        if (f.type === 'json') {
            return { glyph: 'phone', kind: 'io.vault mobile app export', unlock: 'Mnemonic' };
        }
        if (f.type === 'dr') {
            const lower = f.name.toLowerCase();
            const algo = lower.indexOf('.eddsa.') >= 0 ? ' · EdDSA' : (lower.indexOf('.ecdsa.') >= 0 ? ' · ECDSA' : '');
            return { glyph: 'server', kind: 'Virtual Signer share' + algo, unlock: 'ML-KEM key' };
        }
        const z = f.zip || {};
        if (z.status === 'loading') { return { glyph: 'folder', kind: 'Reading ZIP contents…', unlock: '—' }; }
        if (z.status === 'error') { return { glyph: 'folder', kind: z.error, unlock: '—' }; }
        if (z.kind === 'bundle') {
            return { glyph: 'folder', kind: 'Signer backup bundle · ' + plural(z.entries.length, 'share file'), unlock: 'ML-KEM key' };
        }
        const json = z.entries.filter((n) => ext(n) === '.json').length;
        const dr = z.entries.filter((n) => ext(n) === '.dr').length;
        const parts = [];
        if (json) { parts.push(plural(json, 'mobile export')); }
        if (dr) { parts.push(plural(dr, '.dr share')); }
        return { glyph: 'folder', kind: 'ZIP archive · ' + (parts.join(', ') || 'no backup files'), unlock: json && dr ? 'Mnemonics and key' : (json ? 'Mnemonics' : 'ML-KEM key') };
    }

    // ------------------------------------------------------------------
    // Wizard
    //
    // One question per screen, in order:
    //   home     1. Verify or recover?
    //   sources  2. Which kinds of backup do you have? (mobile app, Virtual Signer, HD addresses)
    //   files    3. Add those files, and the ML-KEM keys for Virtual Signer backups
    //   phrases  4. One screen per mobile export: its 24-word recovery phrase
    //   then     Verify: the report. Recover: choose the vault, then the keys.
    // ------------------------------------------------------------------
    const SOURCE_TYPES = {
        mobile: {
            title: 'io.vault mobile app',
            desc: 'Exports from the io.vault app on a signer\'s phone: .json files, or a ZIP of them. Each one is unlocked by that phone\'s 24-word recovery phrase.',
            glyph: 'phone',
        },
        vs: {
            title: 'Virtual Signer',
            desc: 'Backups written by a Virtual Signer: .dr files, or a signer backup bundle (.zip). They are unlocked by your ML-KEM-768 private key (.pem).',
            glyph: 'server',
        },
        hd: {
            title: 'HD addresses',
            desc: 'A CSV of the vault\'s derived (HD) addresses, so they are checked or recovered too. Use it alongside a mobile app or Virtual Signer backup.',
            glyph: 'file',
        },
    };

    function wizardSteps() {
        const steps = [['home', 'Task'], ['sources', 'Backups'], ['files', 'Files']];
        if (state.sources.mobile || mnemonicTargets().length) { steps.push(['phrases', 'Recovery phrases']); }
        if (state.task === 'verify') {
            steps.push(['verify-results', 'Results']);
        } else {
            steps.push(['select-vault', 'Vault'], ['recover-results', 'Keys']);
        }
        return steps;
    }

    function wizardStepper() {
        const steps = wizardSteps();
        const view = state.view === 'loading' ? state.loadingFor : state.view;
        const index = Math.max(0, steps.findIndex((s) => s[0] === view));
        return stepper(steps.map((s) => s[1]), index);
    }

    // The bar every step ends with: a divider, Back on the left, the step's main action on the right.
    function footerBar(opts) {
        return '<div class="footer-bar">' +
            (opts.back ? '<button type="button" class="btn btn-ghost" data-action="' + opts.back + '">' + icon('arrowLeft', 'icon-16') + esc(opts.backLabel || 'Back') + '</button>' : '<span></span>') +
            '<div class="footer-actions">' +
            (opts.hint !== undefined ? '<span class="hint" id="footer-hint">' + esc(opts.hint) + '</span>' : '') +
            (opts.secondary || '') + opts.primary + '</div></div>';
    }

    function primaryButton(action, label, enabled, id) {
        return '<button type="button" class="btn btn-primary btn-lg" data-action="' + action + '"' + (id ? ' id="' + id + '"' : '') + (enabled ? '' : ' disabled') + '>' +
            esc(label) + icon('arrowRight', 'icon-16') + '</button>';
    }

    // Files step: whether Continue may proceed, with the reason shown when it can't.
    function filesCheck() {
        if (!state.files.length) {
            return { ok: false, reason: 'Add at least one backup file.' };
        }
        if (state.files.some((f) => f.zip && f.zip.status === 'loading')) {
            return { ok: false, reason: 'Still reading ZIP contents…' };
        }
        const broken = state.files.find((f) => f.zip && f.zip.status === 'error');
        if (broken) {
            return { ok: false, reason: 'Remove ' + broken.name + ': it could not be read.' };
        }
        const dups = duplicateMnemonicKeys();
        if (dups.length) {
            return { ok: false, reason: 'Two backup files share the name ' + dups[0] + '. Rename one so each recovery phrase matches a single file.' };
        }
        const verify = state.task === 'verify';
        if (!verify && needsKey() && !state.keys.length) {
            return { ok: false, reason: 'Add the ML-KEM-768 private key that opens your Virtual Signer files.' };
        }
        const hints = [];
        if (verify && needsKey() && !state.keys.length) {
            hints.push('Without a key, Virtual Signer files are checked by header only.');
        }
        if (state.sources.hd && !state.options.hdFile) {
            hints.push('No HD addresses CSV added, so HD addresses will not be ' + (verify ? 'checked.' : 'recovered.'));
        }
        return { ok: true, hint: hints.join(' ') };
    }

    // Phrase step: whether the current phrase lets the user move on.
    function phraseCheck(t) {
        const s = mnemonicState(t.key);
        if (s === 'ready') { return { ok: true, hint: '' }; }
        if (s === 'partial') { return { ok: false, reason: 'A recovery phrase has 24 words. ' + wordCount(state.mnemonics[t.key]) + ' entered so far.' }; }
        return { ok: false, reason: canSkipPhrase(t) ? 'Enter the 24 words, or skip this file.' : 'Enter the 24 words to continue.' };
    }

    // Verify can check any file by its header alone. Recovery needs every directly added export
    // unlocked; an export inside a ZIP archive may be left out, as before.
    function canSkipPhrase(t) {
        return state.task === 'verify' || !!t.fromZip;
    }

    function phraseStatus(t) {
        const s = mnemonicState(t.key);
        if (s === 'ready') { return ['success', 'Entered']; }
        if (s === 'partial') { return ['danger', wordCount(state.mnemonics[t.key]) + ' of 24 words']; }
        if (state.skipped[t.key]) { return ['', 'Skipped']; }
        return ['', 'To do'];
    }

    function buildForm() {
        const fd = new FormData();
        state.files.forEach((f) => fd.append('files', f.file, f.name));
        mnemonicTargets().forEach((t) => {
            if (mnemonicState(t.key) === 'ready') {
                fd.append('mnemonic_' + t.key, normalizeMnemonic(state.mnemonics[t.key]));
            }
        });
        state.keys.forEach((k) => fd.append('privateKeyFile', k.file, k.name));
        return fd;
    }

    // ------------------------------------------------------------------
    // Network status. The server reports this computer's active network adapters (names only);
    // the page polls it so the user can see whether the machine is offline before and during a
    // recovery. The server refuses to rebuild keys while connected unless the user overrides it.
    // ------------------------------------------------------------------
    const NETWORK_POLL_MS = 5000;
    let networkInFlight = false;
    let networkShown = '';

    async function refreshNetwork() {
        if (networkInFlight) { return; }
        networkInFlight = true;
        try {
            const status = await postForm('/api/network-status', new FormData());
            state.network = { connected: !!status.connected, adapters: Array.isArray(status.adapters) ? status.adapters : [] };
        } catch (err) {
            state.network = { unknown: true, connected: false, adapters: [] };
        } finally {
            networkInFlight = false;
        }
        // The override is for one connected session only: going offline (or reconnecting) asks again.
        if (!state.network.connected) { state.allowConnected = false; }
        updateNetworkUI();
    }

    function isConnected() {
        return !!(state.network && state.network.connected);
    }

    function networkBlocksRecover() {
        return isConnected() && !state.allowConnected;
    }

    function adapterNames(max) {
        const list = (state.network && state.network.adapters) || [];
        const shown = max ? list.slice(0, max) : list;
        const names = shown.map((a) => a.name + (a.virtual ? ' (virtual)' : ''));
        if (max && list.length > max) { names.push('+' + (list.length - max) + ' more'); }
        return names.join(', ');
    }

    function networkSidebar() {
        const n = state.network;
        let tone = '';
        let title = 'Checking network…';
        let detail = '';
        if (n && n.unknown) {
            title = 'Network status unknown';
            detail = 'The recovery tool did not answer.';
        } else if (n && !n.connected) {
            tone = 'ok';
            title = 'Offline';
            detail = 'No active network adapters';
        } else if (n) {
            tone = 'warn';
            title = 'Connected';
            detail = adapterNames(2);
        }
        return { tone: tone, html: '<span class="net-dot" aria-hidden="true"></span><span class="net-text"><span class="net-title">' + esc(title) + '</span>' +
            (detail ? '<span class="net-detail">' + esc(detail) + '</span>' : '') + '</span>' };
    }

    // A notice for one place in the wizard. Empty when there is nothing to say there.
    function networkNotice(slot) {
        const n = state.network;
        if (!n || n.unknown) {
            return slot === 'home' ? alertBox('info', 'Use an offline device', 'For a real recovery, run this tool on an air-gapped computer or a disposable virtual machine, and disconnect before you add backup files.') : '';
        }
        if (!n.connected) {
            if (slot === 'home') { return alertBox('success', 'This computer is offline', 'No active network adapters were found. Keep it disconnected until you finish and clear the keys.'); }
            if (slot === 'recover') { return alertBox('success', 'This computer is offline', 'No active network adapters were found.'); }
            return '';
        }
        const title = 'This computer is connected to a network';
        const names = esc(adapterNames());
        switch (slot) {
            case 'home':
                return alertBox('warning', title, 'Active: ' + names + '. For a real recovery, use an air-gapped computer or a disposable virtual machine, and disconnect before you add backup files.');
            case 'files':
                return alertBox('warning', title, 'Active: ' + names + '. Disconnect before you add backup files and recovery phrases.');
            case 'phrases':
                return alertBox('warning', title, 'Active: ' + names + '. Disconnect before you enter recovery phrases.');
            case 'recover':
                return alertBox('danger', title, 'Active: ' + names + '. Disconnect it (turn off Wi-Fi, unplug the network cable) before you rebuild a private key. This check updates on its own.' +
                    '<label class="checkbox net-override"><input type="checkbox" data-action="toggle-allow-connected"' + (state.allowConnected ? ' checked' : '') + '>' +
                    '<span>Recover anyway. I am using a disposable virtual machine or another isolated environment.</span></label>');
            case 'results':
                return alertBox('danger', title, 'Private keys are on screen while this computer is connected (' + names + '). Disconnect now, and clear the keys as soon as you finish.');
            default:
                return '';
        }
    }

    function networkSlot(slot) {
        return '<div class="network-slot" data-network-slot="' + slot + '">' + networkNotice(slot) + '</div>';
    }

    function recoverHint() {
        return networkBlocksRecover() ? 'Disconnect this computer, or confirm above that you want to recover anyway.' : 'Keys stay hidden on the next screen until you reveal them.';
    }

    function syncRecoverButton() {
        const btn = document.getElementById('recover-btn');
        if (!btn) { return; }
        btn.disabled = !selectedVault() || networkBlocksRecover();
        const hint = document.getElementById('recover-hint');
        if (hint) { hint.textContent = recoverHint(); }
    }

    // Updates the sidebar and the notices in place, without re-rendering the page, so polling never
    // moves focus or clears what the user is typing.
    function updateNetworkUI() {
        const key = JSON.stringify(state.network);
        if (key !== networkShown) {
            networkShown = key;
            const side = document.getElementById('network-status');
            if (side) {
                const s = networkSidebar();
                side.className = 'net-status' + (s.tone ? ' ' + s.tone : '');
                side.innerHTML = s.html;
            }
            document.querySelectorAll('[data-network-slot]').forEach((el) => {
                el.innerHTML = networkNotice(el.getAttribute('data-network-slot'));
            });
        }
        syncRecoverButton();
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------
    function choiceCard(opts) {
        return '<button type="button" class="choice-card" role="' + (opts.multi ? 'checkbox' : 'radio') + '" aria-checked="' + !!opts.checked + '" data-action="' + opts.action + '" data-value="' + esc(opts.value) + '">' +
            '<span class="choice-media">' + icon(opts.glyph, 'icon-20') + '</span>' +
            '<span class="choice-text"><span class="choice-title">' + esc(opts.title) + (opts.tag ? '<span class="choice-tag">' + esc(opts.tag) + '</span>' : '') + '</span>' +
            '<span class="choice-desc">' + esc(opts.desc) + '</span></span>' +
            '<span class="choice-indicator' + (opts.multi ? ' square' : '') + '">' + icon('check') + '</span></button>';
    }

    // The two tasks, described in full on step 1 so a customer knows what each is for before
    // choosing. The lead sentence also reminds them on step 2, which the sidebar can open directly.
    const TASKS = {
        verify: {
            glyph: 'shieldCheck',
            title: 'Verify my backups',
            tag: 'RECOMMENDED',
            lead: 'Check that your backups would work in a disaster, without recovering anything. The tool reads your backup files, finds the vaults they belong to and counts the shares for each one. No private key is rebuilt.',
            sections: [
                ['What it\'s for', [
                    'See which vaults each backup file holds a share for.',
                    'Confirm each vault has enough current shares to meet its threshold, so it could be recovered.',
                    'Find problems early: missing files, shares from an older reshare, or files that disagree.',
                    'Check your HD addresses against each vault, and export a report for your records.',
                ]],
                ['You\'ll need', [
                    'Your backup files: io.vault app exports (.json or ZIP) and Virtual Signer backups (.dr files or a backup bundle).',
                    'Optional: the 24-word recovery phrase of each app export, and your ML-KEM-768 private key (.pem) for Virtual Signer files. Without them, a file is checked by its header only.',
                ]],
            ],
            note: ['success', 'check', 'When to use it: after you create or reshare a vault, after a signer changes, and as a regular check of your disaster recovery plan. Backups made before a reshare no longer count.'],
        },
        recover: {
            glyph: 'key',
            title: 'Recover a vault\'s keys',
            tag: '',
            lead: 'Rebuild a vault\'s full private keys from your backups, so you can move its funds without io.finnet. Use this only in a disaster, for example when io.vault cannot sign for the vault and its funds must be moved.',
            sections: [
                ['What it\'s for', [
                    'Rebuild the vault\'s ECDSA and EdDSA private keys from a quorum of shares.',
                    'Get the keys in formats wallets accept: hex private keys, Bitcoin WIF and, optionally, a MetaMask wallet file.',
                    'Recover the private keys of your HD addresses from a CSV.',
                    'Move funds on Ethereum and EVM chains, Bitcoin, Tron, Solana, XRP Ledger and Bittensor.',
                ]],
                ['You\'ll need', [
                    'Backup files holding enough current shares to meet the vault\'s threshold.',
                    'The 24-word recovery phrase of each app export, and the ML-KEM-768 private key (.pem) for Virtual Signer files.',
                    'An offline computer: air-gapped, or a disposable virtual machine.',
                ]],
            ],
            note: ['danger', 'alert', 'Use it only as part of an approved disaster recovery. Anyone who sees a recovered key can move the vault\'s funds without approval.'],
        },
    };

    // A large task card. It holds lists, which a button cannot contain, so it uses the same
    // stretched-radio pattern as the vault cards: the title is the radio and covers the card.
    function taskCard(key) {
        const t = TASKS[key];
        const checked = state.task === key;
        return '<div class="choice-card task-card has-actions' + (checked ? ' is-checked' : '') + '">' +
            '<span class="choice-media task-media">' + icon(t.glyph, 'icon-24') + '</span>' +
            '<div class="choice-text task-body">' +
            '<button type="button" class="choice-hit" role="radio" aria-checked="' + checked + '" aria-describedby="task-lead-' + key + '" data-action="choose-task" data-value="' + key + '">' +
            '<span class="choice-title task-title">' + esc(t.title) + (t.tag ? '<span class="choice-tag">' + esc(t.tag) + '</span>' : '') + '</span></button>' +
            '<p class="task-lead" id="task-lead-' + key + '">' + esc(t.lead) + '</p>' +
            '<div class="task-columns">' + t.sections.map((s) =>
                '<div class="task-section"><h3 class="task-heading">' + esc(s[0]) + '</h3><ul class="task-list">' +
                s[1].map((item) => '<li>' + esc(item) + '</li>').join('') + '</ul></div>').join('') + '</div>' +
            '<div class="task-note ' + t.note[0] + '">' + icon(t.note[1], 'icon-16') + '<span>' + esc(t.note[2]) + '</span></div>' +
            '</div><span class="choice-indicator">' + icon('check') + '</span></div>';
    }

    // Step 1: verify or recover.
    function renderHome() {
        return wizardStepper() + pageHeader({
            title: 'What do you want to do?',
            subtitle: 'This tool works with the disaster recovery backups of your io.vault vaults. Choose a task and it takes you through it one step at a time. Everything runs on this device.',
            meta: localTag(),
        }) +
        networkSlot('home') +
        '<div class="choice-group" role="radiogroup" aria-label="Task">' + taskCard('verify') + taskCard('recover') + '</div>' +
        footerBar({ primary: primaryButton('start-task', 'Continue', true) });
    }

    // Step 2: which kinds of backup.
    function renderSources() {
        const verify = state.task === 'verify';
        const s = state.sources;
        const hasBackup = s.mobile || s.vs;
        const reason = hasBackup ? '' : (s.hd ? 'HD addresses need a mobile app or Virtual Signer backup too.' : 'Choose at least one kind of backup.');
        return wizardStepper() + pageHeader({
            title: verify ? 'Which backups do you want to check?' : 'What are you recovering from?',
            subtitle: 'Choose every kind you have. You can pick more than one.',
        }) +
        '<div class="note-box task-reminder">' + icon(TASKS[state.task].glyph) + '<span><strong>' + esc(verify ? 'Verify backup' : 'Recover keys') + ':</strong> ' +
        esc(verify ? 'checks which vaults your files cover and whether each could be recovered. No private key is rebuilt.'
            : 'rebuilds a vault\'s full private keys from a quorum of shares. Use it only in an approved disaster recovery.') +
        ' <button type="button" class="link-btn" data-action="go-home">Change task</button></span></div>' +
        '<div class="choice-group" role="group" aria-label="Backup types">' +
        ['mobile', 'vs', 'hd'].map((key) => choiceCard({ action: 'toggle-source', value: key, multi: true, checked: s[key], glyph: SOURCE_TYPES[key].glyph,
            title: SOURCE_TYPES[key].title, tag: key === 'hd' ? 'OPTIONAL' : '', desc: SOURCE_TYPES[key].desc })).join('') +
        '</div>' +
        footerBar({ back: 'go-home', hint: reason, primary: primaryButton('sources-continue', 'Continue', hasBackup) });
    }

    function dropzone(group, title, desc, accept) {
        return '<div class="dropzone compact" data-dropzone="' + group + '">' +
            '<span class="dropzone-media">' + icon('upload') + '</span>' +
            '<span class="dropzone-title">' + esc(title) + '</span>' +
            '<span class="dropzone-desc">' + esc(desc) + '</span>' +
            '<button type="button" class="btn btn-secondary btn-sm" data-action="pick-files" data-group="' + group + '">' + icon('plus', 'icon-16') + 'Choose files</button>' +
            '<input type="file" id="file-input-' + group + '" multiple accept="' + accept + '" hidden></div>';
    }

    function fileRows(group) {
        const files = state.files.filter((f) => f.group === group);
        if (!files.length) { return ''; }
        return '<div class="file-list">' + files.map((f) => {
            const d = describeFile(f);
            const st = filesStepStatus(f);
            return '<div class="file-row"><span class="file-glyph">' + icon(d.glyph) + '</span>' +
                '<span class="stack-sm" style="gap:2px;flex:1;min-width:0"><span class="file-name">' + esc(f.name) + '</span><span class="file-kind">' + esc(d.kind) + '</span></span>' +
                badge(st[0], st[1]) +
                '<button type="button" class="icon-btn" data-action="remove-file" data-id="' + f.id + '" aria-label="Remove ' + esc(f.name) + '">' + icon('trash') + '</button></div>';
        }).join('') + '</div>';
    }

    // A file's status on the files step. Recovery phrases come on the next step, so a mobile export
    // only says whether one is still needed.
    function filesStepStatus(f) {
        const verify = state.task === 'verify';
        const z = f.zip || {};
        if (z.status === 'loading') { return ['', 'Reading…']; }
        if (z.status === 'error') { return ['danger', 'Unreadable']; }
        const phrases = mnemonicTargets().filter((t) => t.fileId === f.id);
        const keyed = drCount(f) > 0;
        if (keyed && !state.keys.length) { return verify ? ['warning', 'No key: header only'] : ['warning', 'Needs key']; }
        if (phrases.length && phrases.some((t) => mnemonicState(t.key) !== 'ready')) {
            return ['', phrases.length > 1 ? plural(phrases.length, 'phrase') + ' next' : 'Phrase next'];
        }
        return ['success', 'Ready'];
    }

    // Step 3: add the files for each chosen kind of backup.
    function renderFiles() {
        const verify = state.task === 'verify';
        const check = filesCheck();
        const targets = mnemonicTargets();
        let html = wizardStepper() + pageHeader({
            title: 'Add your files',
            subtitle: 'Add every backup file you have for the vaults you want to ' + (verify ? 'check.' : 'recover.') + ' Files are read on this device only.',
        }) + networkSlot('files');
        if (state.error) {
            html += alertBox('danger', verify ? 'The files could not be checked' : 'The files could not be read', esc(state.error));
        }
        html += '<div class="stack" style="gap:24px">';
        // A kind of backup shows when chosen, or when it already has files, so nothing added is hidden.
        // Virtual Signer also shows whenever a file needs a key (e.g. a ZIP of .dr files added with
        // only the mobile app chosen), so the key picker is never hidden when a key can be used.
        const hasGroup = (g) => state.sources[g] || state.files.some((f) => f.group === g) || (g === 'vs' && (state.keys.length > 0 || needsKey()));
        if (hasGroup('mobile')) {
            html += card('io.vault mobile app exports', 'You enter each export\'s recovery phrase on the next step.',
                dropzone('mobile', 'Drop mobile app exports here', '.json exports, or a ZIP of them. A ZIP must be flat, with no folders inside.', '.json,.zip') + fileRows('mobile'));
        }
        if (hasGroup('vs')) {
            html += card('Virtual Signer backups', verify ? 'Add the ML-KEM-768 private key to check each share fully. Without it, files are checked by header only.' : 'Add the ML-KEM-768 private key that opens these files.',
                dropzone('vs', 'Drop Virtual Signer files here', '.dr files, a signer backup bundle (.zip), and your ML-KEM-768 private key (.pem).', '.dr,.zip,.pem') + fileRows('vs') +
                '<div class="stack-sm" style="border-top:1px solid var(--io-border-light);padding-top:16px">' +
                '<span style="font-weight:500">ML-KEM-768 private keys</span>' +
                (state.keys.length ? state.keys.map((k) => '<div class="file-row"><span class="file-glyph" style="color:var(--io-primary-ink)">' + icon('key') + '</span>' +
                    '<span class="stack-sm" style="gap:2px;flex:1;min-width:0"><span class="mono wrap-anywhere">' + esc(k.name) + '</span><span class="small muted">Read in memory only</span></span>' +
                    '<button type="button" class="icon-btn" data-action="remove-key" data-id="' + k.id + '" aria-label="Remove ' + esc(k.name) + '">' + icon('trash') + '</button></div>').join('')
                    : '<p class="small muted">No key added yet. One key per Virtual Signer.</p>') +
                '<div><button type="button" class="btn btn-outline btn-sm" data-action="pick-keys">' + icon('plus', 'icon-16') + (state.keys.length ? 'Add another key' : 'Add a key') + '</button>' +
                '<input type="file" id="key-input" multiple accept=".pem" hidden></div></div>');
        }
        if (state.sources.hd || state.options.hdFile) {
            html += card('HD addresses', verify ? 'Each address is checked against the vaults in your files, with public keys only: no private key is derived.' : 'Child keys are derived for each address after the vault is recovered.',
                '<div class="stack-sm">' + hdFileControl() + '<span class="small muted">Columns: address, xpub, path, algorithm, curve, flags.</span></div>');
        }
        html += '</div>';

        const next = targets.length ? 'Continue' : (verify ? 'Verify ' + plural(state.files.length, 'file') : 'Continue');
        html += footerBar({ back: 'go-sources', hint: check.ok ? (check.hint || '') : check.reason, primary: primaryButton('files-continue', next, check.ok, 'files-continue') });
        return html;
    }

    // Step 4: one recovery phrase per mobile export, one screen at a time.
    function renderPhrases() {
        const targets = mnemonicTargets();
        if (!targets.length) { return renderFiles(); }
        const i = Math.min(Math.max(state.phraseIndex, 0), targets.length - 1);
        state.phraseIndex = i;
        const t = targets[i];
        const verify = state.task === 'verify';
        const check = phraseCheck(t);
        const last = i === targets.length - 1;
        const id = 'mn-' + cssId(t.key);
        const s = mnemonicState(t.key);
        const revealed = !!state.revealed['mn:' + t.key];
        const signer = t.signer && (t.signer.name || t.signer.displayId)
            ? '<span class="tag">' + icon('phone', 'icon-14') + esc([t.signer.name, t.signer.displayId].filter(Boolean).join(' · ')) + '</span>' : '';

        let html = wizardStepper() + pageHeader({
            title: 'Enter the recovery phrase',
            subtitle: 'Export ' + (i + 1) + ' of ' + targets.length + '. Each io.vault app export is unlocked by the 24-word recovery phrase of the phone that made it.',
        }) + networkSlot('phrases');
        html += '<div class="row"><div class="col-main">' +
            '<section class="card"><div class="card-body" style="gap:20px">' +
            '<div class="file-row" style="padding:0;border:0"><span class="file-glyph">' + icon('phone') + '</span>' +
            '<span class="stack-sm" style="gap:4px;flex:1;min-width:0"><span class="file-name">' + esc(t.label) + '</span>' + (signer ? '<span class="inline">' + signer + '</span>' : '') + '</span></div>' +
            '<div class="field"><label class="field-label" for="' + id + '">24-word recovery phrase</label>' +
            '<div class="input-wrap"><input class="input has-action' + (s === 'partial' ? ' error' : '') + '" id="' + id + '" type="' + (revealed ? 'text' : 'password') + '" autocomplete="off" autocapitalize="off" spellcheck="false" data-mnemonic-key="' + esc(t.key) + '" value="' + esc(state.mnemonics[t.key] || '') + '">' +
            '<button type="button" class="icon-btn input-action" data-action="toggle-mnemonic" data-key="' + esc(t.key) + '" aria-label="' + (revealed ? 'Hide' : 'Show') + ' phrase">' + icon(revealed ? 'eyeOff' : 'eye') + '</button></div>' +
            '<span class="field-hint' + (s === 'ready' ? ' ok' : (s === 'partial' ? ' error' : '')) + '" id="' + id + '-hint">' + esc(phraseHint(t)) + '</span></div>' +
            '<p class="small muted">Type or paste the words in order, separated by spaces. The phrase stays masked and is cleared when you finish.</p>' +
            (canSkipPhrase(t) ? '<div class="note-box">' + icon('info') + '<span>' + (verify ? 'Don\'t have this phrase? Skip the file: it is still checked by its header, without its threshold or public key.' : 'Don\'t have this phrase? Skip it: this export is left out of the recovery.') + '</span></div>' : '') +
            '</div></section></div>' +
            '<aside class="col-side">' + card('Exports', '', '<div class="phrase-list">' + targets.map((x, n) => {
                const st = phraseStatus(x);
                return '<button type="button" class="phrase-item' + (n === i ? ' current' : '') + '" data-action="phrase-jump" data-index="' + n + '"' + (n === i ? ' aria-current="step"' : '') + '>' +
                    '<span class="phrase-num">' + (n + 1) + '</span><span class="ellipsis" style="flex:1;text-align:left" title="' + esc(x.label) + '">' + esc(x.label) + '</span>' +
                    '<span id="phrase-status-' + cssId(x.key) + '">' + badge(st[0], st[1]) + '</span></button>';
            }).join('') + '</div>') + '</aside></div>';

        const nextLabel = last ? (verify ? 'Verify ' + plural(state.files.length, 'file') : 'Continue to vaults') : 'Next phrase';
        html += footerBar({
            back: 'phrase-back',
            hint: check.ok ? '' : check.reason,
            secondary: canSkipPhrase(t) ? '<button type="button" class="btn btn-secondary btn-lg" data-action="phrase-skip">Skip this file</button>' : '',
            primary: primaryButton('phrase-next', nextLabel, check.ok, 'phrase-next'),
        });
        return html;
    }

    function phraseHint(t) {
        const s = mnemonicState(t.key);
        const wc = wordCount(state.mnemonics[t.key]);
        return s === 'ready' ? '24 words entered' : (s === 'partial' ? wc + ' of 24 words' : 'Enter all 24 words');
    }

    // Typing a phrase updates its hint, the Continue button and the progress list in place, so
    // the field keeps focus.
    function onMnemonicInput(input) {
        const key = input.getAttribute('data-mnemonic-key');
        state.mnemonics[key] = input.value;
        delete state.skipped[key];
        invalidateResults();
        const t = mnemonicTargets().find((x) => x.key === key);
        if (!t) { return; }
        const s = mnemonicState(key);
        const hint = document.getElementById(input.id + '-hint');
        if (hint) {
            hint.textContent = phraseHint(t);
            hint.className = 'field-hint' + (s === 'ready' ? ' ok' : (s === 'partial' ? ' error' : ''));
        }
        input.classList.toggle('error', s === 'partial');
        const check = phraseCheck(t);
        const btn = document.getElementById('phrase-next');
        if (btn) { btn.disabled = !check.ok; }
        const hintEl = document.getElementById('footer-hint');
        if (hintEl) { hintEl.textContent = check.ok ? '' : check.reason; }
        const status = document.getElementById('phrase-status-' + cssId(key));
        if (status) {
            const st = phraseStatus(t);
            status.innerHTML = badge(st[0], st[1]);
        }
    }

    // After the files and phrases: run the check, or list the vaults to recover.
    function proceed() {
        if (state.task === 'verify') { runVerify(); } else { loadVaults(); }
    }

    // Reads the signer's name and display ID from a mobile export's unencrypted header, so the
    // phrase screen can say whose phone the words come from. Read locally; nothing is sent.
    async function readSignerInfo(entry) {
        try {
            const doc = JSON.parse(await entry.file.text());
            if (doc && (typeof doc.name === 'string' || typeof doc.displayId === 'string')) {
                entry.signer = { name: typeof doc.name === 'string' ? doc.name : '', displayId: typeof doc.displayId === 'string' ? doc.displayId : '' };
                // Refresh the phrase screen unless the user is typing in it.
                if (state.view === 'phrases' && !(document.activeElement && document.activeElement.tagName === 'INPUT')) { render(); }
            }
        } catch (_) { /* not a readable export: no signer label */ }
    }

    function renderLoading() {
        return wizardStepper() + '<div class="loading-panel" role="status">' + icon('loader', 'spin') +
            '<span style="font-weight:500">' + esc(state.busyText) + '</span>' +
            '<span class="small muted">Shares are decrypted in memory on this device. This can take a few seconds for large backups.</span></div>';
    }

    // ---------- Verify results ----------
    const VAULT_STATUS = {
        recoverable: ['success', 'Recoverable'],
        'below-threshold': ['warning', 'Below threshold'],
        'threshold-unknown': ['warning', 'Threshold unknown'],
        'not-checked': ['', 'Not checked'],
        conflict: ['danger', 'Conflict'],
    };
    // What a file holds for a vault: [badge tone, badge label, icon, short text].
    const CONTRIB = {
        counted: ['success', 'Counted', 'check', 'Counted'],
        header: ['', 'Header only', 'lock', 'Header only'],
        'other-reshare': ['warning', 'Other reshare', 'history', 'Older reshare'],
        error: ['danger', 'Error', 'alert', 'Error'],
        conflict: ['danger', 'Conflict', 'alert', 'Conflict'],
    };
    const SOURCE_KIND = {
        'mobile-export': ['phone', 'Mobile app export'],
        'legacy-export': ['phone', 'Legacy app export'],
        'legacy-zip-entry': ['phone', 'Export from a ZIP archive'],
        'dr-share': ['server', 'Virtual Signer share'],
        'signer-bundle': ['folder', 'Signer backup bundle'],
        'zip-archive': ['folder', 'ZIP archive'],
    };
    function vaultLabel(v) {
        return v.name && v.name !== v.vaultId ? v.name : 'Vault ' + truncateMiddle(v.vaultId, 5, 4);
    }
    function sourceKind(s) {
        const k = SOURCE_KIND[s.kind] || ['file', 'Backup file'];
        let text = k[1];
        if (s.kind === 'signer-bundle' && s.fileCount) { text += ' · ' + plural(s.fileCount, 'file'); }
        if (s.signerId) { text += ' · signer ' + s.signerId; }
        return [k[0], text];
    }

    function renderVerifyResults() {
        const r = state.report;
        const sources = r.sources || [];
        const vaults = r.vaults || [];
        const attention = vaults.filter((v) => v.status !== 'recoverable');
        const recoverable = vaults.length - attention.length;
        const decrypted = sources.filter((s) => s.level === 'decrypted').length;
        const header = sources.filter((s) => s.level === 'header').length;
        const errors = sources.filter((s) => s.level === 'error').length;

        let html = wizardStepper() + pageHeader({
            title: 'Backup coverage',
            subtitle: plural(sources.length, 'file') + ' checked on ' + formatDate(r.checkedAt) + '. No private key was reconstructed.',
            actions: '<button type="button" class="btn btn-primary" data-action="export-report">' + icon('download', 'icon-16') + 'Export report</button>' +
                '<button type="button" class="btn btn-secondary" data-action="back-to-files">' + icon('plus', 'icon-16') + 'Add more files</button>',
        });

        if (!vaults.length) {
            html += alertBox('warning', 'No vaults found', 'None of these files contain a vault share that could be read. Check that you added backup files, not other JSON files.');
        } else if (attention.length) {
            html += alertBox('warning', plural(attention.length, 'vault needs', 'vaults need') + ' attention',
                attention.map((v) => '<strong>' + esc(vaultLabel(v)) + ':</strong> ' + esc(v.message || (VAULT_STATUS[v.status] || ['', v.status])[1])).join('<br>'));
        } else {
            html += alertBox('success', 'Every vault can be recovered', 'Each vault found in these files has enough current shares to meet its threshold.');
        }
        const hd = r.hdAddresses || null;
        const vaultsById = {};
        vaults.forEach((v) => { vaultsById[v.vaultId] = v; });
        const hdRows = hd && !hd.error ? (hd.rows || []) : [];
        const hdOk = hdRows.filter((row) => hdRowRecoverable(row, vaultsById)).length;
        if (hd && hd.error) {
            html += alertBox('danger', 'The HD addresses CSV could not be read', '<strong>' + esc(hd.file) + ':</strong> ' + esc(hd.error));
        } else if (hdRows.length && hdOk < hdRows.length) {
            const counts = {};
            hdRows.filter((row) => !hdRowRecoverable(row, vaultsById)).forEach((row) => {
                const why = row.status === 'match' || row.status === 'label' ? 'their vault is not recoverable from these files' : (HD_STATUS[row.status] || ['', row.status])[2];
                counts[why] = (counts[why] || 0) + 1;
            });
            html += alertBox('warning', plural(hdRows.length - hdOk, 'HD address', 'HD addresses') + ' can\'t be recovered from these files',
                Object.keys(counts).map((why) => esc(plural(counts[why], 'address', 'addresses') + ': ' + why)).join('<br>'));
        }
        const unreadable = sources.filter((s) => s.level === 'error');
        if (unreadable.length) {
            html += alertBox('danger', plural(unreadable.length, 'file') + ' could not be read',
                unreadable.map((s) => '<strong>' + esc(s.name) + ':</strong> ' + esc(s.error || 'Unknown error')).join('<br>') +
                '<br>Check the recovery phrase or key for ' + (unreadable.length === 1 ? 'this file' : 'these files') + ', then verify again.');
        }
        if (r.warnings && r.warnings.length) {
            html += '<details class="card"><summary class="card-header" style="cursor:pointer"><span class="card-title">' + plural(r.warnings.length, 'note') + ' from the file check</span></summary>' +
                '<div class="card-body"><ul class="stack-sm small" style="margin:0;padding-left:18px">' + r.warnings.map((w) => '<li>' + esc(w) + '</li>').join('') + '</ul></div></details>';
        }

        // One row of equal tiles, however many there are, so none sits alone on a second row.
        const stat = (label, value, note) => '<div class="stat"><span class="small muted">' + esc(label) + '</span><span class="stat-value">' + esc(value) + '</span><span class="small muted">' + esc(note) + '</span></div>';
        const tiles = [
            stat('Files checked', sources.length, [decrypted + ' decrypted', header ? header + ' header only' : '', errors ? plural(errors, 'error') : ''].filter(Boolean).join(' · ')),
            stat('Vaults found', vaults.length, 'Across all files'),
            stat('Recoverable', recoverable, 'Threshold met with current shares'),
            stat('Need attention', attention.length, attention.length ? 'See the vaults below' : 'Nothing to fix'),
        ];
        if (hdRows.length) { tiles.push(stat('HD addresses', hdOk + ' / ' + hdRows.length, 'Recoverable from these files')); }
        html += '<div class="stats" style="--stat-cols:' + tiles.length + '">' + tiles.join('') + '</div>';

        const shown = state.reportFilter === 'attention' ? attention : vaults;
        html += '<section class="stack"><div class="spread"><h2 class="section-title">Vaults</h2>' +
            '<div class="toggle-group" role="group" aria-label="Filter vaults">' +
            '<button type="button" data-action="filter-vaults" data-filter="all" aria-pressed="' + (state.reportFilter === 'all') + '">All vaults (' + vaults.length + ')</button>' +
            '<button type="button" data-action="filter-vaults" data-filter="attention" aria-pressed="' + (state.reportFilter === 'attention') + '">Needs attention (' + attention.length + ')</button></div></div>' +
            (shown.length ? vaultList(shown, sources) : '<p class="muted">Nothing needs attention.</p>') +
            '</section>';

        if (hdRows.length) {
            html += hdSection(hd, vaultsById, hdOk);
        }

        html += footerBar({
            back: 'back-to-files',
            backLabel: 'Back to files',
            primary: '<button type="button" class="btn btn-secondary btn-lg" data-action="clear-all">Clear and finish</button>',
        });
        return html;
    }

    // HD address checks: [badge tone, badge label, reason a row can't be recovered].
    const HD_STATUS = {
        match: ['success', 'Matches', ''],
        label: ['info', 'Derived', ''],
        mismatch: ['danger', 'Mismatch', 'the address is not what its path derives'],
        'no-vault': ['warning', 'Vault not found', 'no vault in these files has the xpub\'s key'],
        invalid: ['danger', 'Invalid row', 'the row can\'t be derived'],
    };
    function hdRowRecoverable(row, vaultsById) {
        const v = vaultsById[row.vaultId];
        return (row.status === 'match' || row.status === 'label') && !!v && v.status === 'recoverable';
    }

    function hdSection(hd, vaultsById, recoverable) {
        const rows = hd.rows || [];
        const body = '<div class="table-wrap" style="border:0;border-radius:0"><table class="table hd-table"><thead><tr>' +
            '<th scope="col">Line</th><th scope="col">Address in CSV</th><th scope="col">Path</th><th scope="col">Vault</th><th scope="col">Check</th><th scope="col">Vault status</th></tr></thead><tbody>' +
            rows.map((row) => {
                const st = HD_STATUS[row.status] || ['', row.status, ''];
                const v = vaultsById[row.vaultId];
                const vst = v ? (VAULT_STATUS[v.status] || ['', v.status]) : null;
                const showDerived = row.derivedAddress && row.status !== 'match';
                const address = row.status === 'label' || !row.address
                    ? '<span class="muted">' + esc(row.address || '—') + '</span>'
                    : copyField(row.address, { label: 'Copy address', head: 8, tail: 6 });
                return '<tr><td class="small muted">' + esc(row.row) + '</td>' +
                    '<td><div class="stack-sm" style="gap:4px;align-items:flex-start">' + address +
                    (row.status === 'match' && row.chain ? '<span class="small muted">' + esc(row.chain) + '</span>' : '') +
                    (showDerived ? '<span class="small muted inline" style="gap:6px">Derived ' + esc(row.chain) + ': ' + copyField(row.derivedAddress, { label: 'Copy derived address', head: 8, tail: 6 }) + '</span>' : '') +
                    '</div></td>' +
                    '<td><span class="stack-sm" style="gap:2px"><span class="mono small">' + esc(row.path) + '</span><span class="small muted">' + esc(row.algorithm + ' · ' + row.curve) + '</span></span></td>' +
                    '<td class="hd-vault">' + (v ? esc(vaultLabel(v)) : '<span class="muted">—</span>') + '</td>' +
                    '<td class="hd-check"><span class="stack-sm" style="gap:4px;align-items:flex-start">' + badge(st[0], st[1]) +
                    (row.message && row.status !== 'match' ? '<span class="small muted">' + esc(row.message) + '</span>' : '') + '</span></td>' +
                    '<td>' + (vst ? badge(vst[0], vst[1]) : '<span class="muted">—</span>') + '</td></tr>';
            }).join('') + '</tbody></table></div>';
        return card('HD addresses',
            hd.file + ' · ' + plural(rows.length, 'address', 'addresses') + ' · ' + recoverable + ' recoverable from these files. Checked with public keys only: no private key was derived.',
            body);
    }

    // A reshare is an identifier, not a wallet address, so it is shown as a plain ID tag. Legacy
    // exports identify a reshare by a small nonce number instead of a request ID.
    function reshareKv(id) {
        if (!id) {
            return kv('Reshare', '<span class="muted">—</span>');
        }
        if (/^\d+$/.test(id)) {
            return kv('Reshare nonce', esc(id));
        }
        return kv('Reshare request', idTag(id, 'Copy reshare request ID'));
    }

    // An identifier (vault ID, reshare request ID) as a plain ID tag with a copy button, so it never
    // looks like a wallet address.
    function idTag(id, copyLabel) {
        return '<span class="inline" style="gap:2px;flex-wrap:nowrap">' +
            '<span class="tag mono" title="' + esc(id) + '">' + esc(truncateMiddle(id, 8, 6)) + '</span>' +
            '<button type="button" class="icon-btn" data-action="copy-value" data-value="' + esc(id) + '" aria-label="' + esc(copyLabel) + '">' + icon('copy') + '</button></span>';
    }

    // The vault's own (non-HD) addresses, derived from the shares' public keys, for comparing
    // against io.vault. Vault info from /api/verify uses these field names.
    const VAULT_ADDRESS_FIELDS = [
        ['ethereumAddress', 'Ethereum'],
        ['bitcoinAddress', 'Bitcoin (SegWit)'],
        ['solanaAddress', 'Solana'],
        ['xrplAddress', 'XRP Ledger'],
    ];
    function vaultAddresses(v, emptyText) {
        const rows = VAULT_ADDRESS_FIELDS.filter((f) => v && v[f[0]]).map((f) =>
            kv(f[1], copyField(v[f[0]], { label: 'Copy ' + f[1] + ' address', head: 8, tail: 6 })));
        return rows.length ? rows.join('') : '<p class="small muted" style="padding:6px 0">' + esc(emptyText) + '</p>';
    }

    // Vaults as one full-width list: a row per vault with everything on it, so a full-size screen
    // never needs to scroll sideways. Narrow containers stack each row's cells instead.
    const ROW_ADDRESSES = [['ethereumAddress', 'ETH', 'Ethereum'], ['bitcoinAddress', 'BTC', 'Bitcoin (SegWit)'], ['solanaAddress', 'SOL', 'Solana'], ['xrplAddress', 'XRP', 'XRP Ledger']];
    const MAX_ROW_FILES = 3;

    function vaultList(vaults, sources) {
        return '<div class="vault-list" role="list">' +
            '<div class="vault-list-head" aria-hidden="true"><span>Vault</span><span>Shares</span><span>Files holding shares</span><span>Addresses</span><span>Status</span></div>' +
            vaults.map((v) => vaultRow(v, sources)).join('') + '</div>';
    }

    function vaultRow(v, sources) {
        const st = VAULT_STATUS[v.status] || ['', v.status];
        const checked = v.status !== 'not-checked';
        const counted = v.sharesCounted || 0;
        const segCount = v.threshold ? Math.max(v.threshold, counted) : Math.max(counted + 1, 2);
        let segs = '';
        for (let i = 0; i < segCount; i++) {
            segs += '<span class="' + (i < counted ? 'on' : (v.threshold && i < v.threshold ? 'missing' : '')) + '"></span>';
        }
        const sharesText = v.threshold ? counted + ' of ' + v.threshold + ' required' : (checked ? counted + ' counted · threshold unknown' : 'Not counted yet');
        const reshare = v.currentRequestId
            ? (/^\d+$/.test(v.currentRequestId) ? '<span class="small muted">Reshare nonce ' + esc(v.currentRequestId) + '</span>' : '<span class="stack-sm" style="gap:2px"><span class="small muted">Reshare request</span>' + idTag(v.currentRequestId, 'Copy reshare request ID') + '</span>')
            : '';

        // Files: counted shares first, then the rest; a long list is cut with a count.
        const order = { counted: 0, 'other-reshare': 1, header: 2, conflict: 3, error: 4 };
        // `??`, not `||`: counted has rank 0, which `||` would treat as unknown and sort last.
        const contribs = (v.contributions || []).slice().sort((a, b) => (order[a.state] ?? 9) - (order[b.state] ?? 9));
        const files = contribs.slice(0, MAX_ROW_FILES).map((c) => {
            const s = sources[c.source] || { name: 'Unknown file', kind: '' };
            const m = CONTRIB[c.state] || CONTRIB.header;
            const algos = c.algorithms && c.algorithms.length ? ' · ' + c.algorithms.join(' + ') : '';
            return '<span class="vr-file ' + esc(c.state) + '" title="' + esc(s.name + ' — ' + m[1] + algos) + '">' + icon(m[2], 'icon-14') +
                '<span class="ellipsis">' + esc(s.name) + '</span></span>';
        }).join('') + (contribs.length > MAX_ROW_FILES ? '<span class="small muted">+' + plural(contribs.length - MAX_ROW_FILES, 'more file') + '</span>' : '');

        const addresses = ROW_ADDRESSES.filter((a) => v[a[0]]).map((a) =>
            '<span class="vr-addr"><span class="vr-chain" title="' + esc(a[2]) + '">' + a[1] + '</span>' +
            copyField(v[a[0]], { label: 'Copy ' + a[2] + ' address', head: 6, tail: 4 }) + '</span>').join('');

        const hd = state.report && state.report.hdAddresses;
        const hdMine = hd && !hd.error ? (hd.rows || []).filter((row) => row.vaultId === v.vaultId) : [];
        const hdText = hdMine.length ? 'HD: ' + hdMine.filter((row) => row.status === 'match').length + ' of ' + hdMine.length + ' matched' : '';

        return '<div class="vault-row" role="listitem">' +
            '<div class="vr-cell vr-identity">' + vaultBadge(v.threshold, { mono: !checked }) +
            '<span class="stack-sm" style="gap:2px;min-width:0"><span class="vault-name">' + esc(vaultLabel(v)) + '</span>' +
            '<span class="inline" style="gap:2px;flex-wrap:nowrap;min-width:0"><span class="vault-id ellipsis" title="' + esc(v.vaultId) + '">' + esc(v.vaultId) + '</span>' +
            '<button type="button" class="icon-btn sm" data-action="copy-value" data-value="' + esc(v.vaultId) + '" aria-label="Copy vault ID">' + icon('copy') + '</button></span></span></div>' +
            '<div class="vr-cell"><span class="vr-label">Shares</span><span style="font-weight:500">' + esc(sharesText) + '</span>' +
            '<span class="meter" role="img" aria-label="' + esc(sharesText) + '">' + segs + '</span>' +
            (checked ? '<span class="small muted">' + esc(v.hasEdDSA ? 'ECDSA · EdDSA' : 'ECDSA') + '</span>' : '') + reshare + '</div>' +
            '<div class="vr-cell vr-files"><span class="vr-label">Files holding shares</span>' + (files || '<span class="small muted">None</span>') + '</div>' +
            '<div class="vr-cell"><span class="vr-label">Addresses</span>' + (addresses ? '<span class="vr-addresses">' + addresses + '</span>' : '<span class="small muted">' + (checked ? 'Not available' : 'Unlock a file to derive them') + '</span>') + '</div>' +
            '<div class="vr-cell vr-status"><span class="vr-label">Status</span>' + badge(st[0], st[1]) +
            (hdText ? '<span class="small muted">' + esc(hdText) + '</span>' : '') +
            (v.status === 'recoverable' ? '<button type="button" class="btn btn-ghost btn-sm" data-action="recover-from-report" data-vault="' + esc(v.vaultId) + '">Recover' + icon('arrowRight', 'icon-16') + '</button>' : '') + '</div>' +
            (v.message ? '<div class="vr-message">' + icon('info', 'icon-16') + '<span>' + esc(v.message) + '</span></div>' : '') +
            '</div>';
    }

    // ---------- Recover: select vault ----------
    function vaultTitle(v) {
        return v.Name && v.Name !== v.VaultID ? v.Name : 'Vault ' + truncateMiddle(v.VaultID, 5, 4);
    }
    // A reshare request ID or nonce under Advanced options picks a reshare other than the latest.
    // The listed share count and the verify verdict describe the latest reshare only, so they say
    // nothing about the one entered: a vault is not blocked on them then. The server checks the
    // entered reshare when recovering, and returns an error if it is short of shares.
    function reshareOverridden() {
        const o = state.options;
        return !!(o.requestId.trim() || o.nonce.trim());
    }
    function vaultBlocked(v) {
        if (reshareOverridden()) { return ''; }
        const info = state.vaultInfo[v.VaultID];
        const threshold = Number(state.options.threshold) || v.Quorum;
        if (threshold > 0 && v.NumberOfShares < threshold) { return 'Below threshold: ' + v.NumberOfShares + ' of ' + threshold + ' shares'; }
        if (info && info.status === 'below-threshold' && !state.options.threshold) { return info.message || 'Below threshold'; }
        return '';
    }

    // The vault Recover acts on: the chosen one, unless the current options block it. The choice
    // itself is kept, so it comes back if the options change again.
    function selectedVault() {
        const sel = (state.vaults || []).find((v) => v.VaultID === state.selectedVaultId);
        return sel && !vaultBlocked(sel) ? sel : null;
    }

    // Tags a vault by the kind of file that actually holds its shares, read from the verify report.
    // A missing vault name says nothing about the source: v4/v5 mobile exports and Virtual Signer
    // files both leave names out. Without the report there is no tag.
    function vaultSourceTag(vaultId) {
        const info = state.vaultInfo[vaultId];
        if (!info || !Array.isArray(info.contributions)) { return ''; }
        const kinds = new Set();
        info.contributions.forEach((c) => {
            const s = state.vaultSources[c.source];
            if (s) { kinds.add(s.kind === 'dr-share' || s.kind === 'signer-bundle' ? 'vs' : 'mobile'); }
        });
        if (kinds.has('vs') && kinds.has('mobile')) { return 'MOBILE APP + VIRTUAL SIGNER'; }
        if (kinds.has('vs')) { return 'VIRTUAL SIGNER'; }
        if (kinds.has('mobile')) { return 'MOBILE APP'; }
        return '';
    }

    function renderSelectVault() {
        const vaults = state.vaults || [];
        const sel = selectedVault();
        const o = state.options;
        const overridden = reshareOverridden();

        let html = wizardStepper() + pageHeader({
            title: 'Select a vault',
            subtitle: 'Only vaults with enough current shares can be recovered.',
            meta: localTag(),
        }) + alertBox('warning', 'Recovery rebuilds the full private key on this device',
            "Anyone who sees the recovered key can move this vault's funds without approval. Continue only as part of an approved disaster recovery, on an offline device.") +
            networkSlot('recover');
        if (state.error) {
            html += alertBox('danger', 'Recovery failed', esc(state.error));
        }

        html += '<div class="row"><div class="col-main">';
        html += '<section class="stack" style="gap:12px"><h2 class="section-title">Vaults in your files</h2>';
        if (!vaults.length) {
            html += '<p class="muted">No vaults were found in these files.</p>';
        } else {
            // Each card holds a copy button for the vault ID, and a button cannot sit inside another
            // button. So the card is a plain container: its radio is the title button, stretched over
            // the whole card, and the copy button sits on top of it.
            html += '<div class="choice-group" role="radiogroup" aria-label="Vault to recover">' + vaults.map((v, i) => {
                const blocked = vaultBlocked(v);
                // A blocked card is never shown as chosen, matching what Recover would act on.
                const checked = v.VaultID === state.selectedVaultId && !blocked;
                const info = state.vaultInfo[v.VaultID];
                const notes = [];
                if (!v.Quorum) { notes.push('threshold not in backup: enter it under Advanced options'); }
                if (overridden) { notes.push('recovery uses the reshare entered under Advanced options; its shares are checked when you recover'); }
                if (blocked) { notes.push(blocked); } else if (info && info.status === 'conflict' && info.message) { notes.push(info.message); }
                const tag = vaultSourceTag(v.VaultID);
                const sep = '<span aria-hidden="true">·</span>';
                return '<div class="choice-card has-actions' + (checked ? ' is-checked' : '') + (blocked ? ' is-disabled' : '') + '">' +
                    vaultBadge(v.Quorum, { mono: !!blocked }) +
                    '<span class="choice-text">' +
                    '<button type="button" class="choice-hit" role="radio" aria-checked="' + checked + '"' + (blocked ? ' aria-disabled="true"' : '') +
                    ' aria-describedby="vault-desc-' + i + '" data-action="select-vault" data-vault="' + esc(v.VaultID) + '">' +
                    '<span class="choice-title">' + esc(vaultTitle(v)) + (tag ? '<span class="choice-tag">' + tag + '</span>' : '') + '</span></button>' +
                    '<span class="choice-desc with-copy" id="vault-desc-' + i + '"><span>' + esc(v.NumberOfShares + ' of ' + (v.Quorum || '?') + ' shares' + (overridden ? ' in the latest reshare' : '')) + '</span>' + sep +
                    copyField(v.VaultID, { compact: true, head: 8, tail: 4, label: 'Copy vault ID' }) +
                    (notes.length ? sep + '<span>' + esc(notes.join(' · ')) + '</span>' : '') + '</span></span>' +
                    '<span class="choice-indicator">' + icon('check') + '</span></div>';
            }).join('') + '</div>';
        }
        html += '</section>';

        html += '<details class="card"' + (o.threshold || o.requestId || o.nonce ? ' open' : '') + '><summary class="card-header" style="cursor:pointer"><span class="card-title">Advanced options</span></summary><div class="card-body">' +
            '<p class="small muted">The tool picks these automatically. Change them only if io.finnet support asks you to.</p><div class="grid-fields">' +
            textField('opt-threshold', 'Threshold', o.threshold, 'options.threshold', 'Shares needed to sign', { inputmode: 'numeric', placeholder: sel && sel.Quorum ? 'Auto: ' + sel.Quorum : 'Auto' }) +
            textField('opt-request', 'Reshare request ID', o.requestId, 'options.requestId', '.dr files and v4 exports', { placeholder: 'Auto: latest' }) +
            textField('opt-nonce', 'Reshare nonce', o.nonce, 'options.nonce', 'Legacy JSON exports only', { inputmode: 'numeric', placeholder: 'Auto: highest' }) +
            '</div></div></details>';

        html += card('Optional exports', 'Produced at the same time as the keys.',
            '<label class="checkbox"><input type="checkbox" data-action="toggle-export" ' + (o.exportWallet ? 'checked' : '') + '><span>Export an Ethereum wallet file (keystore v3) for MetaMask</span></label>' +
            (o.exportWallet ? '<div class="grid-fields" style="padding-left:28px">' +
                textField('opt-export-file', 'File name', o.exportFile, 'options.exportFile', 'Saved in the folder you started the tool from', { placeholder: 'wallet.json' }) +
                '<div class="field"><label class="field-label" for="opt-password">Wallet file password</label><div class="input-wrap">' +
                '<input class="input has-action" id="opt-password" type="' + (state.revealed['opt-password'] ? 'text' : 'password') + '" autocomplete="new-password" data-model="options.password" value="' + esc(o.password) + '">' +
                '<button type="button" class="icon-btn input-action" data-action="toggle-password" aria-label="' + (state.revealed['opt-password'] ? 'Hide' : 'Show') + ' password">' + icon(state.revealed['opt-password'] ? 'eyeOff' : 'eye') + '</button></div>' +
                '<span class="field-hint">You need this password to import the file.</span></div></div>' : '') +
            '<div class="stack-sm" style="border-top:1px solid var(--io-border-light);padding-top:16px">' +
            '<span style="font-weight:500">HD addresses</span><span class="small muted">Add a CSV of derived addresses to recover their child keys too. Columns: address, xpub, path, algorithm, curve, flags.</span>' +
            hdFileControl() + '</div>');
        html += '</div><aside class="col-side">';

        if (sel) {
            const info = state.vaultInfo[sel.VaultID] || {};
            html += card('Selected vault', '',
                '<div>' + kv('Name', esc(vaultTitle(sel))) + kv('Vault ID', copyField(sel.VaultID, { label: 'Copy vault ID' })) +
                kv('Threshold', sel.Quorum ? esc(plural(sel.Quorum, 'share')) : '<span class="muted">Not in backup</span>') +
                kv('Shares found', esc(String(sel.NumberOfShares)) + (overridden ? ' <span class="small muted">(latest reshare)</span>' : '')) + '</div>' +
                '<div class="vault-section"><span class="vault-section-label">Addresses</span>' + vaultAddresses(info, 'Shown after recovery') + '</div>' +
                '<div class="note-box">' + icon('info') + '<span>Check that these addresses match the vault in io.vault before you continue. They come from the shares\' public keys, so no private key is needed to show them.</span></div>');
        } else {
            html += card('Selected vault', '', '<p class="small muted">Choose a vault to see its details.</p>');
        }
        html += '</aside></div>';

        html += '<div class="footer-bar"><button type="button" class="btn btn-ghost" data-action="vaults-back">' + icon('arrowLeft', 'icon-16') + 'Back</button>' +
            '<div class="footer-actions"><span class="hint" id="recover-hint">' + esc(recoverHint()) + '</span>' +
            '<button type="button" class="btn btn-primary btn-lg" id="recover-btn" data-action="recover"' + (sel && !networkBlocksRecover() ? '' : ' disabled') + '>' + icon('key', 'icon-16') +
            (sel ? 'Recover ' + esc(vaultTitle(sel)) : 'Recover keys') + '</button></div></div>';
        return html;
    }

    // The HD addresses CSV picker, shared by Verify (checked against public keys) and Recover
    // (child keys derived). One file serves both, so a CSV added while verifying carries over.
    function hdFileControl() {
        const f = state.options.hdFile;
        return (f ? '<div class="note-box" style="align-items:center">' + icon('file') + '<span class="mono" style="flex:1;color:var(--io-text);overflow-wrap:anywhere">' + esc(f.name) + '</span>' +
                '<button type="button" class="icon-btn" data-action="remove-hd" aria-label="Remove ' + esc(f.name) + '">' + icon('trash') + '</button></div>'
                : '<div><button type="button" class="btn btn-outline btn-sm" data-action="pick-hd">' + icon('plus', 'icon-16') + 'Add CSV</button></div>') +
            '<input type="file" id="hd-input" accept=".csv" hidden>';
    }

    function textField(id, label, value, model, hint, attrs) {
        attrs = attrs || {};
        return '<div class="field"><label class="field-label" for="' + id + '">' + esc(label) + '</label>' +
            '<input class="input" id="' + id + '" type="text" autocomplete="off" spellcheck="false" data-model="' + model + '" value="' + esc(value) + '"' +
            (attrs.placeholder ? ' placeholder="' + esc(attrs.placeholder) + '"' : '') + (attrs.inputmode ? ' inputmode="' + attrs.inputmode + '"' : '') + '>' +
            (hint ? '<span class="field-hint">' + esc(hint) + '</span>' : '') + '</div>';
    }

    // ---------- Recover: results ----------
    function secretBlock(id, label, hint) {
        const value = secrets.get(id) || '';
        const shown = !!state.revealed[id];
        const masked = '•'.repeat(Math.min(Math.max(value.length, 16), 64));
        return '<div class="secret" data-secret-block="' + esc(id) + '"><div class="spread"><span style="font-weight:500">' + esc(label) + '</span>' +
            '<span class="inline" style="gap:4px"><button type="button" class="btn btn-ghost btn-sm" data-action="toggle-secret" data-secret="' + esc(id) + '">' +
            icon(shown ? 'eyeOff' : 'eye', 'icon-16') + (shown ? 'Hide' : 'Reveal') + '</button>' +
            '<button type="button" class="icon-btn" data-action="copy-secret" data-secret="' + esc(id) + '" aria-label="Copy ' + esc(label) + '">' + icon('copy') + '</button></span></div>' +
            '<div class="secret-value' + (shown ? '' : ' masked') + '">' + esc(shown ? value : masked) + '</div>' +
            (hint ? '<span class="small muted">' + esc(hint) + '</span>' : '') + '</div>';
    }

    function renderRecoverResults() {
        const r = state.recovered;
        const v = state.recoveredVault;
        let html = wizardStepper() + pageHeader({
            media: vaultBadge(v.threshold, { lg: true }),
            title: v.title,
            status: badge('success', 'Keys recovered'),
            subtitle: 'Keys recovered on ' + formatDate(v.at) + ' from ' + plural(v.shares, 'share') + '.',
            meta: '<span class="tag mono">' + esc(v.id) + '</span>',
        }) + alertBox('danger', 'Private keys are on this screen',
            "Keys stay hidden until you reveal them. Anyone who sees a key can move this vault's funds. When you finish, choose Clear keys and finish: the page forgets them and the files you added.") +
            networkSlot('results');
        if (r.hdError) {
            html += alertBox('warning', 'HD address derivation failed', esc(r.hdError));
        }

        html += '<div class="row"><div class="col-main">';
        html += card('ECDSA keys', 'Ethereum and EVM chains, Tron, Bitcoin and other secp256k1 networks.',
            '<div>' + secretBlock('ecdsa', 'Private key (hex)', 'Import into MetaMask or TronLink. Some wallets need a 0x prefix.') +
            secretBlock('wifMain', 'Bitcoin WIF — mainnet (bc1)', 'For Electrum. Add the p2wpkh: prefix when you import.') +
            secretBlock('wifTest', 'Bitcoin WIF — testnet (tb1)', 'For Electrum in testnet mode, with the p2wpkh: prefix.') + '</div>');

        if (r.eddsaPrivateKey) {
            const chainRow = (chainId) => {
                const c = CHAINS[chainId];
                const addr = r[c.addressKey];
                return '<div class="share-row" style="flex-wrap:wrap">' + icon(c.glyph) +
                    '<span class="share-text" style="flex:1 1 200px"><span style="font-weight:500">' + esc(c.name) + '</span>' +
                    (addr ? copyField(addr, { label: 'Copy ' + c.name + ' address', head: 8, tail: 6 }) : '<span class="small muted">Address unavailable</span>') + '</span>' +
                    '<button type="button" class="btn btn-outline btn-sm" data-action="open-chain" data-chain="' + chainId + '"' + (addr ? '' : ' disabled') + '>' + icon('terminal', 'icon-16') + 'Open chain tool</button></div>';
            };
            html += '<div id="eddsa-card">' + card('EdDSA keys', 'Solana, XRP Ledger and Bittensor.',
                '<div>' + secretBlock('eddsa', 'Private key (hex)', '') + '</div>' +
                (r.eddsaPublicKey ? kv('Public key', copyField(r.eddsaPublicKey, { label: 'Copy EdDSA public key', head: 8, tail: 6 })) : '') +
                '<div><span class="small muted">Addresses</span>' + ['solana', 'xrpl', 'bittensor'].map(chainRow).join('') + '</div>') + '</div>';
        }

        if (r.hdAddresses && r.hdAddresses.length) {
            html += '<section class="stack" style="gap:12px"><div class="spread"><h2 class="section-title">HD addresses</h2>' +
                '<button type="button" class="btn btn-secondary btn-sm" data-action="copy-hd-csv">' + icon('copy', 'icon-16') + 'Copy all as CSV (includes private keys)</button></div>' +
                '<div class="table-wrap"><table class="table"><thead><tr><th scope="col">Address</th><th scope="col">Path</th><th scope="col">Curve</th><th scope="col">Public key</th><th scope="col">Private key</th><th scope="col">WIF</th></tr></thead><tbody>' +
                r.hdAddresses.map((a, i) => '<tr><td>' + copyField(a.address, { label: 'Copy address' }) + '</td>' +
                    '<td class="mono small">' + esc(a.path) + '</td><td><span class="tag">' + esc(a.algorithm + ' · ' + a.curve) + '</span></td>' +
                    '<td>' + copyField(a.publicKey, { label: 'Copy public key' }) + '</td>' +
                    '<td>' + hdSecretCell('hd-' + i + '-pk') + '</td><td>' + (a.wif ? hdSecretCell('hd-' + i + '-wif') : '<span class="muted">—</span>') + '</td></tr>').join('') +
                '</tbody></table></div></section>';
        }
        html += '</div><aside class="col-side">';

        // The same addresses as the Select vault step. Those come from the shares' public keys;
        // here the ones the recovery returns come from the rebuilt keys and take precedence.
        const info = state.vaultInfo[v.id] || {};
        html += card('Addresses', '', '<div>' + vaultAddresses({
            ethereumAddress: r.address || info.ethereumAddress,
            bitcoinAddress: info.bitcoinAddress,
            solanaAddress: r.solanaAddress || info.solanaAddress,
            xrplAddress: r.xrplAddress || info.xrplAddress,
        }, 'No addresses available') + '</div>');

        const reshareSource = {
            request: 'Reshare request ID set by you under Advanced options.',
            nonce: 'Reshare nonce set by you under Advanced options.',
            auto: 'Reshare picked automatically: the latest one in your files.',
        }[v.requestSource] || '';
        html += card('Recovery details', '', '<div>' +
            kv('Vault ID', idTag(v.id, 'Copy vault ID')) +
            (v.requestId ? reshareKv(v.requestId) : kv('Reshare', '<span class="muted">Not reported</span>')) +
            kv('Threshold', esc(plural(v.threshold, 'share')) + (v.thresholdManual ? ' <span class="small muted">(set by you)</span>' : '')) +
            kv('Shares used', esc(String(v.shares))) + '</div>' +
            (reshareSource ? '<p class="small muted">' + esc(reshareSource) + '</p>' : ''));

        if (r.exportedKsFile) {
            const name = String(r.exportedKsFile).split(/[\\/]/).pop();
            html += card('Wallet file', '', '<div class="inline" style="flex-wrap:nowrap;align-items:flex-start;gap:12px">' +
                '<span class="file-glyph" style="background:var(--io-success-faded);color:var(--io-success-text)">' + icon('check') + '</span>' +
                '<span class="stack-sm" style="gap:2px;min-width:0"><span class="mono wrap-anywhere">' + esc(name) + '</span>' +
                '<span class="small muted">Keystore v3, saved in the folder you started the tool from. Import it into MetaMask with its password.</span></span></div>');
        }

        html += card('Import into a wallet', '', tileList([
            ['MetaMask', 'Import the wallet file with its password, or paste the ECDSA private key.'],
            ['Electrum (Bitcoin)', 'Import the WIF with the p2wpkh: prefix.'],
            ['TronLink (Tron)', 'Import the ECDSA private key.'],
            ['Solana, XRP Ledger, Bittensor', 'Use Open chain tool to check a balance or build a transfer command.'],
        ]));
        html += '</aside></div>';

        html += '<div class="footer-bar"><button type="button" class="btn btn-ghost" data-action="back-to-vaults">' + icon('arrowLeft', 'icon-16') + 'Back to vaults</button>' +
            '<button type="button" class="btn btn-danger-light btn-lg" data-action="clear-all">' + icon('trash', 'icon-16') + 'Clear keys and finish</button></div>';
        return html;
    }

    function hdSecretCell(id) {
        const shown = !!state.revealed[id];
        const value = secrets.get(id) || '';
        return '<span class="inline" style="flex-wrap:nowrap;gap:4px" data-secret-block="' + esc(id) + '">' +
            '<span class="mono small' + (shown ? '' : ' muted') + '">' + esc(shown ? truncateMiddle(value, 8, 6) : '••••••••') + '</span>' +
            '<button type="button" class="icon-btn" data-action="toggle-secret" data-secret="' + esc(id) + '" aria-label="' + (shown ? 'Hide' : 'Reveal') + ' value">' + icon(shown ? 'eyeOff' : 'eye') + '</button>' +
            '<button type="button" class="icon-btn" data-action="copy-secret" data-secret="' + esc(id) + '" aria-label="Copy value">' + icon('copy') + '</button></span>';
    }

    // ------------------------------------------------------------------
    // Chain tools (XRPL, Solana, Bittensor). The tool builds commands for the bundled
    // scripts; the user runs them. The private key is masked on screen and only included
    // in what is copied to the clipboard.
    // ------------------------------------------------------------------
    const BASE58 = '[1-9A-HJ-NP-Za-km-z]';
    const CHAINS = {
        xrpl: {
            name: 'XRP Ledger', glyph: 'coin', unit: 'XRP', script: 'scripts/xrpl-tool', addressKey: 'xrplAddress',
            networks: [['testnet', 'Testnet'], ['mainnet', 'Mainnet']], defaultNetwork: 'testnet',
            pattern: new RegExp('^r' + BASE58 + '{24,34}$'), destHint: 'An XRPL address starts with r and is 25 to 35 characters.', max: 100000000000,
        },
        solana: {
            name: 'Solana', glyph: 'coin', unit: 'SOL', script: 'scripts/solana-tool', addressKey: 'solanaAddress',
            networks: [['mainnet', 'Mainnet'], ['testnet', 'Testnet'], ['devnet', 'Devnet']], defaultNetwork: 'devnet',
            pattern: new RegExp('^' + BASE58 + '{32,44}$'), destHint: 'A Solana address is 32 to 44 characters.',
        },
        bittensor: {
            name: 'Bittensor', glyph: 'coin', unit: 'TAO', script: 'scripts/bittensor-tool', addressKey: 'bittensorAddress',
            networks: [['mainnet', 'Mainnet (Finney)'], ['testnet', 'Testnet']], defaultNetwork: 'mainnet',
            pattern: new RegExp('^' + BASE58 + '{48}$'), destHint: 'A Bittensor address is 48 characters.',
        },
    };
    const BITTENSOR_ENDPOINTS = { mainnet: 'wss://entrypoint-finney.opentensor.ai:443', testnet: 'wss://test.finney.opentensor.ai:443' };
    const MASKED_KEY = '••••••••';

    function detectShell() {
        return /Win/i.test(navigator.platform || navigator.userAgent || '') ? 'windows' : 'posix';
    }

    function chainInputsValid() {
        const ch = state.chain;
        const c = CHAINS[ch.id];
        const amount = Number(ch.amount);
        const destOk = c.pattern.test(ch.destination.trim());
        const amountOk = /^\d+(\.\d{1,9})?$/.test(ch.amount.trim()) && amount > 0 && (!c.max || amount < c.max);
        return { destOk: destOk, amountOk: amountOk };
    }

    function chainArgs(reveal) {
        const ch = state.chain;
        const c = CHAINS[ch.id];
        const r = state.recovered;
        const key = reveal ? secrets.get('eddsa') : MASKED_KEY;
        if (ch.tab === 'balance') {
            return ['--check-balance', '--address', r[c.addressKey], '--network', ch.network];
        }
        const dest = ch.destination.trim();
        const amount = ch.amount.trim();
        if (ch.id === 'xrpl') {
            return ['--private-key', key, '--public-key', r.eddsaPublicKey, '--destination', dest, '--amount', amount, '--network', ch.network];
        }
        if (ch.id === 'bittensor') {
            return ['--private-key', key, '--destination', dest, '--amount', amount, '--endpoint', BITTENSOR_ENDPOINTS[ch.network], '--network', ch.network];
        }
        return ['--private-key', key, '--destination', dest, '--amount', amount, '--network', ch.network];
    }

    function chainCommands(reveal) {
        const ch = state.chain;
        const c = CHAINS[ch.id];
        const win = ch.shell === 'windows';
        const dir = win ? c.script.replace(/\//g, '\\') : c.script;
        const args = chainArgs(reveal).join(' ');
        return {
            install: win ? 'pushd ' + dir + ' && npm install && popd' : 'cd ' + dir + ' && npm install && cd -',
            run: win ? 'pushd ' + dir + ' && npm start -- ' + args + ' && popd' : 'cd ' + dir + ' && npm start -- ' + args + ' && cd -',
        };
    }

    function openChain(chainId) {
        const c = CHAINS[chainId];
        state.chain = { id: chainId, network: c.defaultNetwork, tab: 'balance', shell: detectShell(), destination: '', amount: '' };
        renderChain();
        const dialog = document.getElementById('chain-dialog');
        if (!dialog.open) {
            dialog.showModal();
        }
    }

    function renderChain() {
        const ch = state.chain;
        const c = CHAINS[ch.id];
        const r = state.recovered;
        const inner = document.getElementById('chain-dialog-inner');
        const transfer = ch.tab === 'transfer';
        inner.innerHTML =
            '<div class="modal-header"><div class="stack-sm" style="gap:4px"><h2 class="modal-title" id="chain-dialog-title">' + esc(c.name) + ' chain tool</h2>' +
            '<p class="muted">Check the balance or build a transfer. You run the command yourself, in a terminal on this device.</p></div>' +
            '<button type="button" class="icon-btn" data-action="close-chain" aria-label="Close">' + icon('x') + '</button></div>' +
            '<div class="modal-body">' +
            '<div class="stack-sm"><span class="field-label">Network</span><div class="toggle-group" role="group" aria-label="Network">' +
            c.networks.map((n) => '<button type="button" data-action="chain-network" data-value="' + n[0] + '" aria-pressed="' + (ch.network === n[0]) + '">' + esc(n[1]) + '</button>').join('') + '</div></div>' +
            '<div class="tabs" role="tablist"><button type="button" role="tab" data-action="chain-tab" data-value="balance" aria-selected="' + !transfer + '">Check balance</button>' +
            '<button type="button" role="tab" data-action="chain-tab" data-value="transfer" aria-selected="' + transfer + '">Create transfer</button></div>' +
            (transfer
                ? '<div class="stack">' + kv('From', copyField(r[c.addressKey], { label: 'Copy source address', head: 8, tail: 6 })) +
                  '<div class="field"><label class="field-label" for="chain-dest">Destination address</label>' +
                  '<input class="input" id="chain-dest" type="text" autocomplete="off" spellcheck="false" data-chain-input="destination" value="' + esc(ch.destination) + '">' +
                  '<span class="field-hint" id="chain-dest-hint">' + esc(c.destHint) + '</span></div>' +
                  '<div class="field"><label class="field-label" for="chain-amount">Amount</label><div class="input-wrap">' +
                  '<input class="input has-suffix" id="chain-amount" type="text" inputmode="decimal" autocomplete="off" data-chain-input="amount" value="' + esc(ch.amount) + '">' +
                  '<span class="input-suffix">' + esc(c.unit) + '</span></div><span class="field-hint" id="chain-amount-hint">Must be greater than 0.</span></div></div>'
                : '<p class="small muted">The balance check uses only the public address, so it is safe to run on a connected computer.</p>') +
            '<div class="stack-sm"><div class="spread"><span class="field-label">Commands</span>' +
            '<div class="toggle-group" role="group" aria-label="Terminal"><button type="button" data-action="chain-shell" data-value="posix" aria-pressed="' + (ch.shell === 'posix') + '">macOS / Linux</button>' +
            '<button type="button" data-action="chain-shell" data-value="windows" aria-pressed="' + (ch.shell === 'windows') + '">Windows</button></div></div>' +
            '<div id="chain-commands"></div></div>' +
            '<div class="note-box">' + icon('info') + '<span>The commands need Node.js. Run step 1 while connected to install the tool, then disconnect if you can before step 2.' +
            (transfer ? ' The private key is masked here and added only when you copy. Clear your terminal history afterwards.' : '') + '</span></div>' +
            '</div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-action="close-chain">Close</button>' +
            '<button type="button" class="btn btn-primary" data-action="copy-chain-run" id="chain-copy-run">' + icon('copy', 'icon-16') + (transfer ? 'Copy transfer command' : 'Copy balance command') + '</button></div>';
        renderChainCommands();
    }

    function renderChainCommands() {
        const ch = state.chain;
        const target = document.getElementById('chain-commands');
        if (!target) { return; }
        const transfer = ch.tab === 'transfer';
        const valid = chainInputsValid();
        const ready = !transfer || (valid.destOk && valid.amountOk);
        const cmds = chainCommands(false);
        const block = (step, text, action) => '<div class="command"><div class="stack-sm" style="gap:4px;flex:1;min-width:0">' +
            '<span class="small muted">' + esc(step) + '</span><code>' + esc(text) + '</code></div>' +
            '<button type="button" class="icon-btn" data-action="' + action + '" aria-label="Copy: ' + esc(step) + '">' + icon('copy') + '</button></div>';
        target.innerHTML = '<div class="stack-sm">' + block('1. Install the tool (needs a network connection)', cmds.install, 'copy-chain-install') +
            (ready ? block(transfer ? '2. Send the transfer' : '2. Check the balance', cmds.run, 'copy-chain-run')
                   : '<div class="note-box">' + icon('info') + '<span>Enter a valid destination and amount to build the transfer command.</span></div>') + '</div>';
        const copyRun = document.getElementById('chain-copy-run');
        if (copyRun) { copyRun.disabled = !ready; }
        if (transfer) {
            const dh = document.getElementById('chain-dest-hint');
            const ah = document.getElementById('chain-amount-hint');
            const destTouched = ch.destination.trim() !== '';
            const amountTouched = ch.amount.trim() !== '';
            if (dh) { dh.className = 'field-hint' + (destTouched && !valid.destOk ? ' error' : ''); }
            if (ah) { ah.className = 'field-hint' + (amountTouched && !valid.amountOk ? ' error' : ''); }
            const di = document.getElementById('chain-dest');
            const ai = document.getElementById('chain-amount');
            if (di) { di.classList.toggle('error', destTouched && !valid.destOk); }
            if (ai) { ai.classList.toggle('error', amountTouched && !valid.amountOk); }
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------
    function go(view) {
        state.view = view;
        render();
        window.scrollTo(0, 0);
        const heading = document.querySelector('.page-title');
        if (heading) { heading.focus({ preventScroll: true }); }
    }

    // Request ownership. Each server operation (verify, list vaults, recover) takes a token when it
    // starts. Clearing the session, leaving the loading screen (the sidebar is the only way off it)
    // or starting another operation makes the token stale. A response whose token is stale is
    // discarded: it writes no results or secrets, changes no view and resets no attempt state, so a
    // late reply can never reopen a screen the user cleared or left.
    let currentOp = 0;
    function beginOp() {
        currentOp += 1;
        return currentOp;
    }
    function cancelOps() {
        currentOp += 1;
    }
    function ownsOp(token) {
        // Every operation waits on the loading screen, so leaving it by any route also disowns it.
        return token === currentOp && state.view === 'loading';
    }

    async function runVerify() {
        const op = beginOp();
        state.error = '';
        state.busyText = 'Checking ' + plural(state.files.length, 'file') + '…';
        state.loadingFor = 'verify-results';
        go('loading');
        let report;
        try {
            const fd = buildForm();
            if (state.options.hdFile) {
                fd.append('hdAddressesCSV', state.options.hdFile, state.options.hdFile.name);
            }
            report = await postForm('/api/verify', fd);
        } catch (err) {
            if (!ownsOp(op)) { return; }
            state.error = err.message;
            go('files');
            return;
        }
        if (!ownsOp(op)) { return; }
        state.report = report;
        state.reportFilter = 'all';
        go('verify-results');
    }

    async function loadVaults() {
        const op = beginOp();
        state.error = '';
        state.busyText = 'Reading vaults from ' + plural(state.files.length, 'file') + '…';
        state.loadingFor = 'select-vault';
        go('loading');
        const results = await Promise.allSettled([postForm('/api/list-vaults', buildForm()), postForm('/api/verify', buildForm())]);
        if (!ownsOp(op)) { return; }
        if (results[0].status === 'rejected') {
            state.error = results[0].reason.message;
            go('files');
            return;
        }
        state.vaults = Array.isArray(results[0].value) ? results[0].value : [];
        state.vaultInfo = {};
        state.vaultSources = [];
        if (results[1].status === 'fulfilled' && results[1].value && Array.isArray(results[1].value.vaults)) {
            results[1].value.vaults.forEach((v) => { state.vaultInfo[v.vaultId] = v; });
            state.vaultSources = Array.isArray(results[1].value.sources) ? results[1].value.sources : [];
        }
        const preselect = state.selectedVaultId && state.vaults.find((v) => v.VaultID === state.selectedVaultId && !vaultBlocked(v));
        if (!preselect) {
            const first = state.vaults.find((v) => !vaultBlocked(v));
            state.selectedVaultId = first ? first.VaultID : null;
        }
        go('select-vault');
    }

    async function recover() {
        // selectedVault() is null when the current options block the chosen vault, so this sends
        // only what the cards and the Recover button show as recoverable.
        const sel = selectedVault();
        if (!sel) { return; }
        const o = state.options;
        const fail = (message) => { state.error = message; render(); window.scrollTo(0, 0); };
        if (o.threshold && !/^\d+$/.test(o.threshold.trim())) { return fail('Threshold must be a whole number.'); }
        if (o.nonce && !/^\d+$/.test(o.nonce.trim())) { return fail('Reshare nonce must be a whole number.'); }
        if (!sel.Quorum && !o.threshold) { return fail("This vault's backup does not record its threshold. Enter it under Advanced options."); }
        if (o.exportWallet && !o.exportFile.trim()) { return fail('Enter a file name for the wallet file.'); }
        if (o.exportWallet && !o.password) { return fail('Enter a password for the wallet file.'); }

        const fd = buildForm();
        fd.append('vaultId', sel.VaultID);
        if (o.threshold.trim()) { fd.append('quorumOverride', o.threshold.trim()); }
        if (o.requestId.trim()) { fd.append('requestIdOverride', o.requestId.trim()); }
        if (o.nonce.trim()) { fd.append('nonceOverride', o.nonce.trim()); }
        if (o.exportWallet) {
            fd.append('exportFile', o.exportFile.trim());
            fd.append('password', o.password);
        }
        if (o.hdFile) { fd.append('hdAddressesCSV', o.hdFile, o.hdFile.name); }
        if (networkBlocksRecover()) { return fail('This computer is connected to a network. Disconnect it, or confirm that you want to recover anyway.'); }
        if (state.allowConnected && isConnected()) { fd.append('allowConnected', 'true'); }

        // The wallet password and the "recover anyway" confirmation belong to this one attempt.
        // Clear them now, before any screen is rendered: a failed attempt then shows both empty
        // (the user enters and confirms again), and a stale response has nothing to reset.
        o.password = '';
        state.allowConnected = false;

        const op = beginOp();
        state.error = '';
        state.busyText = 'Recovering ' + vaultTitle(sel) + '…';
        state.loadingFor = 'recover-results';
        go('loading');
        let result;
        try {
            result = await postForm('/api/recover', fd);
        } catch (err) {
            if (!ownsOp(op)) { return; }
            state.error = err.message;
            go('select-vault');
            return;
        }
        if (!ownsOp(op)) {
            // The session was cleared or the user moved on: never publish these keys.
            discardRecoverResult(result);
            return;
        }
        if (result && result.networkBlocked) {
            refreshNetwork();
        }
        if (!result || !result.success) {
            state.error = (result && result.errorMessage) || 'Recovery failed.';
            go('select-vault');
            return;
        }
        wipeSecrets();
        secrets.set('ecdsa', result.ecdsaPrivateKey || '');
        secrets.set('wifMain', result.mainnetWIF || '');
        secrets.set('wifTest', result.testnetWIF || '');
        if (result.eddsaPrivateKey) { secrets.set('eddsa', result.eddsaPrivateKey); }
        (result.hdAddresses || []).forEach((a, i) => {
            secrets.set('hd-' + i + '-pk', a.privateKey || '');
            if (a.wif) { secrets.set('hd-' + i + '-wif', a.wif); }
        });
        // Keep only non-secret fields on the result object; secrets live in the map.
        state.recovered = {
            address: result.address,
            eddsaPrivateKey: !!result.eddsaPrivateKey,
            eddsaPublicKey: result.eddsaPublicKey,
            xrplAddress: result.xrplAddress,
            solanaAddress: result.solanaAddress,
            bittensorAddress: result.bittensorAddress,
            exportedKsFile: result.exportedKsFile,
            hdError: result.hdError,
            hdAddresses: (result.hdAddresses || []).map((a) => ({ address: a.address, path: a.path, algorithm: a.algorithm, curve: a.curve, publicKey: a.publicKey, wif: !!a.wif })),
        };
        state.recoveredVault = {
            id: sel.VaultID,
            title: vaultTitle(sel),
            threshold: result.threshold || Number(o.threshold) || sel.Quorum,
            shares: result.sharesUsed || sel.NumberOfShares,
            at: new Date().toISOString(),
            requestId: result.requestId || '',
            requestSource: o.requestId.trim() ? 'request' : (o.nonce.trim() ? 'nonce' : 'auto'),
            thresholdManual: !!o.threshold.trim(),
        };
        // The keys now live in the secrets map only; drop the response's copies.
        discardRecoverResult(result);
        state.revealed = {};
        updateNav();
        go('recover-results');
    }

    function wipeSecrets() {
        secrets.forEach((_, k) => secrets.set(k, ''));
        secrets.clear();
    }

    // Drops the key material a /api/recover response holds. JavaScript strings cannot be
    // overwritten in place, so, like wipeSecrets(), this removes the references to them.
    function discardRecoverResult(result) {
        if (!result || typeof result !== 'object') { return; }
        ['ecdsaPrivateKey', 'mainnetWIF', 'testnetWIF', 'eddsaPrivateKey'].forEach((k) => { result[k] = ''; });
        (Array.isArray(result.hdAddresses) ? result.hdAddresses : []).forEach((a) => {
            if (a && typeof a === 'object') {
                a.privateKey = '';
                a.wif = '';
            }
        });
    }

    function clearAll() {
        // A response still in flight must not refill the session after it is cleared.
        cancelOps();
        wipeSecrets();
        const dialog = document.getElementById('chain-dialog');
        if (dialog.open) { dialog.close(); }
        document.getElementById('chain-dialog-inner').innerHTML = '';
        Object.keys(state.mnemonics).forEach((k) => { state.mnemonics[k] = ''; });
        Object.assign(state, {
            sources: { mobile: false, vs: false, hd: false }, phraseIndex: 0, skipped: freshKeyed(),
            files: [], keys: [], mnemonics: freshKeyed(), error: '', report: null, vaults: null, vaultInfo: {}, vaultSources: [], selectedVaultId: null,
            options: freshOptions(), recovered: null, recoveredVault: null, revealed: {}, chain: null, allowConnected: false,
        });
        updateNav();
        go('home');
        toast('Cleared. Close this tab to finish.');
    }

    function exportReport() {
        const r = state.report;
        const payload = Object.assign({ tool: 'io.finnet disaster recovery tool', type: 'backup-verification-report' }, r);
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
        a.href = url;
        a.download = 'backup-verification-' + stamp + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        toast('Report saved. It lists vault IDs, file names and public addresses only.');
    }

    function hdCsv() {
        const csvEscape = (val) => {
            const s = String(val === undefined || val === null ? '' : val);
            return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const rows = ['address,path,algorithm,curve,publicKey,privateKey,wif'];
        state.recovered.hdAddresses.forEach((a, i) => {
            rows.push([a.address, a.path, a.algorithm, a.curve, a.publicKey, secrets.get('hd-' + i + '-pk'), secrets.get('hd-' + i + '-wif') || ''].map(csvEscape).join(','));
        });
        return rows.join('\n') + '\n';
    }

    function setModel(path, value) {
        const parts = path.split('.');
        let obj = state;
        for (let i = 0; i < parts.length - 1; i++) { obj = obj[parts[i]]; }
        obj[parts[parts.length - 1]] = value;
    }

    function updateSecretBlock(id) {
        const el = document.querySelector('[data-secret-block="' + CSS.escape(id) + '"]');
        if (!el) { render(); return; }
        const wrapper = document.createElement('div');
        if (id.indexOf('hd-') === 0) {
            wrapper.innerHTML = hdSecretCell(id);
        } else {
            const labels = { ecdsa: ['Private key (hex)', 'Import into MetaMask or TronLink. Some wallets need a 0x prefix.'], wifMain: ['Bitcoin WIF — mainnet (bc1)', 'For Electrum. Add the p2wpkh: prefix when you import.'], wifTest: ['Bitcoin WIF — testnet (tb1)', 'For Electrum in testnet mode, with the p2wpkh: prefix.'], eddsa: ['Private key (hex)', ''] };
            wrapper.innerHTML = secretBlock(id, labels[id][0], labels[id][1]);
        }
        el.replaceWith(wrapper.firstElementChild);
    }

    // renderChain() rebuilds the whole dialog, which drops keyboard focus from the option just
    // chosen. Put it back on that option's replacement.
    function focusChainOption(action, value) {
        const again = document.querySelector('#chain-dialog [data-action="' + action + '"][data-value="' + CSS.escape(value) + '"]');
        if (again) { again.focus(); }
    }

    // Puts the cursor in the phrase field after moving between exports.
    function focusPhrase() {
        const input = document.querySelector('[data-mnemonic-key]');
        if (input) { input.focus(); }
    }

    async function onAction(el, event) {
        const action = el.getAttribute('data-action');
        switch (action) {
            case 'choose-task':
                state.task = el.getAttribute('data-value');
                render();
                document.querySelector('[data-action="choose-task"][data-value="' + state.task + '"]').focus();
                break;
            case 'start-task':
                state.error = '';
                go('sources');
                break;
            case 'go-home':
                go('home');
                break;
            case 'go-sources':
                go('sources');
                break;
            case 'toggle-source': {
                const key = el.getAttribute('data-value');
                state.sources[key] = !state.sources[key];
                render();
                const again = document.querySelector('[data-action="toggle-source"][data-value="' + key + '"]');
                if (again) { again.focus(); }
                break;
            }
            case 'sources-continue':
                if (!state.sources.mobile && !state.sources.vs) { return; }
                state.error = '';
                go('files');
                break;
            case 'pick-files': {
                const input = document.getElementById('file-input-' + el.getAttribute('data-group'));
                if (input) { input.click(); }
                break;
            }
            case 'files-continue': {
                if (!filesCheck().ok) { return; }
                const targets = mnemonicTargets();
                if (targets.length) {
                    const firstOpen = targets.findIndex((t) => mnemonicState(t.key) !== 'ready' && !state.skipped[t.key]);
                    state.phraseIndex = firstOpen >= 0 ? firstOpen : 0;
                    go('phrases');
                    focusPhrase();
                } else {
                    proceed();
                }
                break;
            }
            case 'phrase-jump':
                state.phraseIndex = Number(el.getAttribute('data-index')) || 0;
                render();
                focusPhrase();
                break;
            case 'phrase-back':
                if (state.phraseIndex > 0) {
                    state.phraseIndex--;
                    render();
                    focusPhrase();
                } else {
                    go('files');
                }
                break;
            case 'phrase-skip':
            case 'phrase-next': {
                const targets = mnemonicTargets();
                const t = targets[state.phraseIndex];
                if (!t) { proceed(); break; }
                if (action === 'phrase-skip') {
                    if (!canSkipPhrase(t)) { return; }
                    state.mnemonics[t.key] = '';
                    state.skipped[t.key] = true;
                    invalidateResults();
                } else if (!phraseCheck(t).ok) {
                    return;
                }
                if (state.phraseIndex < targets.length - 1) {
                    state.phraseIndex++;
                    render();
                    focusPhrase();
                } else {
                    const missing = targets.findIndex((x) => mnemonicState(x.key) !== 'ready' && !(state.skipped[x.key] && canSkipPhrase(x)));
                    if (missing >= 0) {
                        state.phraseIndex = missing;
                        render();
                        focusPhrase();
                        toast('Enter the recovery phrase for ' + targets[missing].label + ' first.');
                    } else {
                        proceed();
                    }
                }
                break;
            }
            case 'pick-keys':
                document.getElementById('key-input').click();
                break;
            case 'pick-hd':
                document.getElementById('hd-input').click();
                break;
            case 'remove-file': {
                const id = Number(el.getAttribute('data-id'));
                // Phrase, skip and reveal state is keyed by a name derived from the file name (also the
                // multipart field name). Forget it for every export in the removed upload, ZIP entries
                // included, so a different file added later under the same name cannot inherit its
                // phrase or its revealed (plain-text) state. If another upload shares that name the
                // phrase was ambiguous anyway, so it is entered again.
                mnemonicTargets().filter((t) => t.fileId === id).forEach((t) => forgetPhrase(t.key));
                state.files = state.files.filter((f) => f.id !== id);
                invalidateResults();
                render();
                break;
            }
            case 'remove-key': {
                const id = Number(el.getAttribute('data-id'));
                state.keys = state.keys.filter((k) => k.id !== id);
                invalidateResults();
                render();
                break;
            }
            case 'remove-hd':
                state.options.hdFile = null;
                invalidateReport();
                render();
                break;
            case 'toggle-mnemonic': {
                const key = el.getAttribute('data-key');
                state.revealed['mn:' + key] = !state.revealed['mn:' + key];
                const input = document.getElementById('mn-' + cssId(key));
                if (input) {
                    input.type = state.revealed['mn:' + key] ? 'text' : 'password';
                    el.innerHTML = icon(state.revealed['mn:' + key] ? 'eyeOff' : 'eye');
                    el.setAttribute('aria-label', (state.revealed['mn:' + key] ? 'Hide' : 'Show') + ' phrase');
                }
                break;
            }
            case 'toggle-password': {
                state.revealed['opt-password'] = !state.revealed['opt-password'];
                const input = document.getElementById('opt-password');
                if (input) { input.type = state.revealed['opt-password'] ? 'text' : 'password'; }
                el.innerHTML = icon(state.revealed['opt-password'] ? 'eyeOff' : 'eye');
                break;
            }
            case 'back-to-files':
                state.error = '';
                go('files');
                break;
            case 'vaults-back': {
                state.error = '';
                const targets = mnemonicTargets();
                if (targets.length) {
                    state.phraseIndex = targets.length - 1;
                    go('phrases');
                } else {
                    go('files');
                }
                break;
            }
            case 'filter-vaults':
                state.reportFilter = el.getAttribute('data-filter');
                render();
                break;
            case 'export-report':
                exportReport();
                break;
            case 'recover-from-report':
                state.task = 'recover';
                state.selectedVaultId = el.getAttribute('data-vault');
                go('files');
                toast('Add any missing mnemonics or keys, then continue.');
                break;
            case 'select-vault':
                if (el.getAttribute('aria-disabled') === 'true') { return; }
                state.selectedVaultId = el.getAttribute('data-vault');
                state.error = '';
                render();
                {
                    const card = document.querySelector('[data-action="select-vault"][data-vault="' + CSS.escape(state.selectedVaultId) + '"]');
                    if (card) { card.focus(); }
                }
                break;
            case 'toggle-export':
                state.options.exportWallet = el.checked;
                if (el.checked && !state.options.exportFile) {
                    const sel = (state.vaults || []).find((v) => v.VaultID === state.selectedVaultId);
                    const stem = sel ? vaultTitle(sel).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') : 'vault';
                    state.options.exportFile = (stem || 'vault') + '-wallet.json';
                }
                render();
                break;
            case 'toggle-allow-connected':
                state.allowConnected = el.checked;
                syncRecoverButton();
                break;
            case 'recover':
                recover();
                break;
            case 'back-to-vaults':
                go('select-vault');
                break;
            case 'toggle-secret': {
                const id = el.getAttribute('data-secret');
                state.revealed[id] = !state.revealed[id];
                updateSecretBlock(id);
                const again = document.querySelector('[data-action="toggle-secret"][data-secret="' + CSS.escape(id) + '"]');
                if (again) { again.focus(); }
                break;
            }
            case 'copy-secret': {
                const ok = await copyText(secrets.get(el.getAttribute('data-secret')) || '');
                toast(ok ? 'Copied. Clear your clipboard when you are done.' : 'Copy failed. Reveal the value and copy it by hand.');
                break;
            }
            case 'copy-value': {
                const ok = await copyText(el.getAttribute('data-value') || '');
                if (ok) {
                    el.classList.add('copied');
                    setTimeout(() => el.classList.remove('copied'), 1200);
                }
                toast(ok ? 'Copied' : 'Copy failed');
                break;
            }
            case 'copy-hd-csv': {
                const ok = await copyText(hdCsv());
                toast(ok ? 'Copied all HD addresses, including private keys.' : 'Copy failed');
                break;
            }
            case 'open-chain':
                openChain(el.getAttribute('data-chain'));
                break;
            case 'close-chain':
                document.getElementById('chain-dialog').close();
                break;
            case 'chain-network':
                state.chain.network = el.getAttribute('data-value');
                renderChain();
                focusChainOption(action, state.chain.network);
                break;
            case 'chain-tab':
                state.chain.tab = el.getAttribute('data-value');
                renderChain();
                focusChainOption(action, state.chain.tab);
                break;
            case 'chain-shell':
                state.chain.shell = el.getAttribute('data-value');
                renderChain();
                focusChainOption(action, state.chain.shell);
                break;
            case 'copy-chain-install': {
                const ok = await copyText(chainCommands(false).install);
                toast(ok ? 'Install command copied' : 'Copy failed');
                break;
            }
            case 'copy-chain-run': {
                const transfer = state.chain.tab === 'transfer';
                const ok = await copyText(chainCommands(transfer).run);
                toast(ok ? (transfer ? 'Transfer command copied. It contains the private key: clear your clipboard and terminal history afterwards.' : 'Balance command copied') : 'Copy failed');
                break;
            }
            case 'clear-all':
                clearAll();
                break;
            default:
                break;
        }
        if (event) { event.preventDefault(); }
    }

    // ------------------------------------------------------------------
    // Rendering and navigation
    // ------------------------------------------------------------------
    function updateNav() {
        const active = state.view === 'home' ? 'home' : (state.task === 'verify' ? 'verify' : 'recover');
        document.querySelectorAll('.nav-item[data-nav]').forEach((el) => {
            const nav = el.getAttribute('data-nav');
            if (nav === active) { el.setAttribute('aria-current', 'page'); } else { el.removeAttribute('aria-current'); }
            if (nav === 'tools') {
                const enabled = !!(state.recovered && state.recovered.eddsaPrivateKey);
                el.setAttribute('aria-disabled', enabled ? 'false' : 'true');
                el.title = enabled ? '' : 'Recover a vault to use chain tools';
            }
        });
    }

    function render() {
        const page = document.getElementById('page');
        let html;
        switch (state.view) {
            case 'sources': html = renderSources(); break;
            case 'files': html = renderFiles(); break;
            case 'phrases': html = renderPhrases(); break;
            case 'loading': html = renderLoading(); break;
            case 'verify-results': html = state.report ? renderVerifyResults() : renderFiles(); break;
            case 'select-vault': html = state.vaults ? renderSelectVault() : renderFiles(); break;
            case 'recover-results': html = state.recovered ? renderRecoverResults() : renderHome(); break;
            default: html = renderHome(); break;
        }
        page.innerHTML = html;
        // Question steps use a narrow column; the verify report gets more width for its vault rows.
        const narrow = ['home', 'sources', 'files', 'phrases'].indexOf(state.view) >= 0;
        page.className = 'page' + (narrow ? ' narrow' : (state.view === 'verify-results' ? ' wide' : ''));
        updateNav();
    }

    function onNav(nav) {
        // The sidebar is the way off the loading screen: leaving it abandons any request in flight.
        cancelOps();
        // A result dropped because its inputs changed falls back to the files step, so the files
        // already added are one click from a fresh check.
        const start = state.files.length ? 'files' : 'sources';
        if (nav === 'home') {
            go('home');
        } else if (nav === 'verify') {
            state.task = 'verify';
            go(state.report ? 'verify-results' : start);
        } else if (nav === 'recover') {
            state.task = 'recover';
            go(state.recovered ? 'recover-results' : (state.vaults ? 'select-vault' : start));
        } else if (nav === 'tools' && state.recovered && state.recovered.eddsaPrivateKey) {
            state.task = 'recover';
            go('recover-results');
            const target = document.getElementById('eddsa-card');
            if (target) { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
        }
    }

    // ------------------------------------------------------------------
    // Wiring
    // ------------------------------------------------------------------
    function init() {
        hydrateIcons(document);

        document.addEventListener('click', (event) => {
            const nav = event.target.closest('[data-nav]');
            if (nav) {
                if (nav.getAttribute('aria-disabled') !== 'true') { onNav(nav.getAttribute('data-nav')); }
                return;
            }
            const el = event.target.closest('[data-action]');
            if (!el || el.disabled) { return; }
            // Checkboxes must keep their native toggle; everything else is a button.
            if (el.type === 'checkbox') { return; }
            onAction(el, event);
        });

        document.addEventListener('change', (event) => {
            const el = event.target;
            if (el.id.indexOf('file-input-') === 0) {
                addFiles(el.files, el.id.slice('file-input-'.length));
                el.value = '';
            } else if (el.id === 'key-input') {
                let added = 0;
                Array.from(el.files || []).forEach((file) => {
                    if (ext(file.name) !== '.pem') {
                        toast('Skipped ' + file.name + ': keys must be .pem files.');
                        return;
                    }
                    state.keys.push({ id: nextId++, name: file.name, file: file });
                    added++;
                });
                if (added) { invalidateResults(); }
                el.value = '';
                render();
            } else if (el.id === 'hd-input') {
                state.options.hdFile = el.files && el.files[0] ? el.files[0] : null;
                // The CSV is an input of the verify report only, not of the vault list, so it can be
                // added on the select-vault step without losing the list.
                invalidateReport();
                el.value = '';
                render();
            } else if (el.type === 'checkbox' && el.hasAttribute('data-action')) {
                onAction(el, null);
            } else if (['options.threshold', 'options.requestId', 'options.nonce'].indexOf(el.getAttribute('data-model')) >= 0 && state.view === 'select-vault') {
                // A threshold, reshare request ID or nonce override changes which vaults can be selected.
                render();
            }
        });

        document.addEventListener('input', (event) => {
            const el = event.target;
            if (el.hasAttribute('data-mnemonic-key')) {
                onMnemonicInput(el);
            } else if (el.hasAttribute('data-model')) {
                setModel(el.getAttribute('data-model'), el.value);
            } else if (el.hasAttribute('data-chain-input')) {
                state.chain[el.getAttribute('data-chain-input')] = el.value;
                renderChainCommands();
            }
        });

        // Arrow keys move between the radios of a radio group (choice cards, or a vault card's title).
        document.addEventListener('keydown', (event) => {
            const radio = event.target.closest && event.target.closest('[role="radio"]');
            if (!radio || ['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].indexOf(event.key) < 0) { return; }
            const group = radio.closest('[role="radiogroup"]');
            if (!group) { return; }
            const items = Array.from(group.querySelectorAll('[role="radio"]:not([aria-disabled="true"])'));
            const i = items.indexOf(radio);
            const next = items[(i + (event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : items.length - 1)) % items.length];
            if (next) {
                event.preventDefault();
                next.click();
            }
        });

        // Drag and drop onto the drop zone.
        ['dragenter', 'dragover'].forEach((type) => document.addEventListener(type, (event) => {
            const zone = event.target.closest && event.target.closest('[data-dropzone]');
            if (!zone) { return; }
            event.preventDefault();
            zone.classList.add('dragover');
        }));
        document.addEventListener('dragleave', (event) => {
            const zone = event.target.closest && event.target.closest('[data-dropzone]');
            if (zone && !zone.contains(event.relatedTarget)) { zone.classList.remove('dragover'); }
        });
        document.addEventListener('drop', (event) => {
            const zone = event.target.closest && event.target.closest('[data-dropzone]');
            event.preventDefault();
            if (zone && event.dataTransfer) {
                zone.classList.remove('dragover');
                addFiles(event.dataTransfer.files, zone.getAttribute('data-dropzone'));
            }
        });
        // Dropping a file anywhere else must not navigate away and lose the session.
        window.addEventListener('dragover', (event) => event.preventDefault());

        const dialog = document.getElementById('chain-dialog');
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) { dialog.close(); }
        });

        render();

        // Keep the offline indicator current: poll, and check at once when the browser notices a
        // change or the tab comes back into view.
        updateNetworkUI();
        refreshNetwork();
        setInterval(refreshNetwork, NETWORK_POLL_MS);
        window.addEventListener('online', refreshNetwork);
        window.addEventListener('offline', refreshNetwork);
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) { refreshNetwork(); }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
