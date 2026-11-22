// The Dashboard: is anything wrong, is mail moving, and what is waiting.
// Server-supplied text reaches it only through textContent.
(function () {
    'use strict';
    const el = id => document.getElementById(id);
    const SVG = 'http://www.w3.org/2000/svg';
    let hours = [], drawnWidth = 0;

    function shape(tag, attrs, parent) {
        const node = document.createElementNS(SVG, tag);
        for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
        if (parent) parent.appendChild(node);
        return node;
    }
    function short(n) { return n < 10000 ? Number(n).toLocaleString() : Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n); }

    // The banner is for trouble: with nothing wrong it isn't shown. items is
    // null when the checks couldn't be read, which is trouble too, and
    // undefined for someone who may not read them.
    window.setOverallStatus = function (items) {
        const banner = el('overall'), badge = el('nav-attention');
        if (items === undefined) { banner.hidden = true; badge.hidden = true; return; }
        let level = '', title = '', detail = '';
        if (items === null) {
            level = 'unknown'; title = "Couldn't check the server"; detail = 'The status checks didn\'t answer.';
        } else {
            const count = severity => items.filter(i => i.severity === severity).length;
            const critical = count('critical'), warning = count('warning'), unknown = count('unknown');
            const problems = critical + warning;
            if (problems) {
                level = critical ? 'critical' : 'warning';
                title = problems === 1 ? '1 thing needs attention' : problems + ' things need attention';
                detail = [critical && critical + ' critical', warning && warning + (warning === 1 ? ' warning' : ' warnings'), unknown && unknown + " couldn't be checked"].filter(Boolean).join(', ') + '.';
            } else if (unknown) {
                level = 'unknown'; title = 'No known problems'; detail = unknown + " check" + (unknown === 1 ? '' : 's') + " couldn't run, so this isn't the whole picture.";
            }
            badge.hidden = !problems;
            badge.textContent = problems;
            badge.classList.toggle('critical', critical > 0);
        }
        banner.hidden = !level;
        if (!level) return;
        banner.dataset.level = level;
        el('overall-mark').textContent = { warning: '!', critical: '!', unknown: '?' }[level];
        el('overall-title').textContent = title;
        el('overall-detail').textContent = detail;
    };

    function draw() {
        const box = el('overview-chart'), width = box.clientWidth;
        if (!width) return;
        drawnWidth = width;
        const height = 180, left = 42, top = 8, plot = height - top - 24;
        const total = h => h.delivered + h.deferred + h.failed;
        const largest = Math.max(0, ...hours.map(total));
        const power = Math.pow(10, Math.floor(Math.log10(Math.max(1, largest / 3))));
        const step = Math.max(1, [1, 2, 5, 10].find(m => m * power >= largest / 3) * power);
        const max = Math.max(step, Math.ceil(largest / step) * step);
        const y = value => top + plot - value / max * plot;
        const delivered = hours.reduce((n, h) => n + h.delivered, 0);
        const svg = shape('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img' });
        svg.setAttribute('aria-label', `Last 24 hours: ${delivered} delivered, ${hours.reduce((n, h) => n + h.deferred + h.failed, 0)} deferred or failed. The Delivery report has each hour.`);
        for (let tick = 0; tick <= max; tick += step) {
            shape('line', { x1: left, x2: width, y1: y(tick), y2: y(tick), class: tick ? 'overview-grid' : 'overview-axis' }, svg);
            shape('text', { x: left - 6, y: y(tick) + 4, class: 'overview-tick', 'text-anchor': 'end' }, svg).textContent = short(tick);
        }
        const slot = (width - left) / Math.max(1, hours.length), bar = Math.min(24, Math.max(2, slot * .65));
        const every = Math.max(1, Math.ceil(hours.length / Math.max(2, Math.floor((width - left) / 70))));
        hours.forEach((hour, i) => {
            const group = shape('g', {}, svg), x = left + slot * i + (slot - bar) / 2;
            const at = new Date(hour.label);
            const when = isNaN(at) ? hour.label : at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
            shape('rect', { x: left + slot * i, y: top, width: slot, height: plot, class: 'overview-hit' }, group);
            shape('title', {}, group).textContent = `${when}: ${hour.delivered} delivered, ${hour.deferred} deferred, ${hour.failed} failed`;
            let base = top + plot;
            const parts = [['overview-good', hour.delivered], ['overview-bad', hour.deferred + hour.failed]].filter(part => part[1] > 0);
            parts.forEach(([className, value], n) => {
                const h = Math.max(2, value / max * plot - (n ? 2 : 0)), end = base - h;
                const r = n === parts.length - 1 ? Math.min(4, bar / 2, h) : 0;
                shape('path', { class: className, d: `M${x},${base}V${end + r}Q${x},${end} ${x + r},${end}H${x + bar - r}Q${x + bar},${end} ${x + bar},${end + r}V${base}Z` }, group);
                base = end - 2;
            });
            if ((hours.length - 1 - i) % every === 0 && x > left + 12) {
                shape('text', { x: Math.min(x + bar / 2, width - 22), y: height - 5, class: 'overview-tick', 'text-anchor': 'middle' }, svg).textContent = when;
            }
        });
        box.replaceChildren(svg);
        if (!largest) {
            const empty = document.createElement('p');
            empty.className = 'overview-empty';
            empty.textContent = 'No mail in the last 24 hours.';
            box.appendChild(empty);
        }
    }

    async function getJSON(path) {
        const response = await fetch(path);
        if (!response.ok) throw Object.assign(new Error('HTTP ' + response.status), { status: response.status });
        return response.json();
    }

    // What abuse protection did today, for whoever may read its report. Off,
    // it has nothing to say and the card isn't shown.
    async function loadProtection() {
        const card = el('protection-card');
        if (!shell.allowed('configure')) { card.hidden = true; return; }
        const note = el('protection-note'), list = el('protection-top'), empty = el('protection-empty');
        try {
            const status = await getJSON('/api/abuse');
            const mode = status.policy.mode;
            if (mode === 'off') { card.hidden = true; return; }
            const stats = await getJSON('/api/abuse/metrics?range=24h');
            const blocks = status.blocks || [], top = (stats.top || []).slice(0, 5);
            el('protection-failures').textContent = short(stats.failures);
            el('protection-refused').textContent = short(stats.refused);
            el('protection-blocks').textContent = short(stats.blocks);
            el('protection-active').textContent = short(blocks.length);

            const notes = [];
            if (mode === 'log') notes.push('Log only: nothing is being blocked.');
            if (!status.shared) notes.push("Valkey isn't available, so these are this console's counts alone.");
            note.textContent = notes.join(' ');
            note.hidden = !notes.length;

            const blocked = new Set(blocks.map(block => block.network));
            list.replaceChildren(...top.map(offender => {
                const row = document.createElement('li');
                const cell = (className, text) => {
                    const span = document.createElement('span');
                    span.className = className;
                    span.textContent = text;
                    row.appendChild(span);
                };
                cell('protection-network', offender.network);
                if (blocked.has(offender.network)) cell('protection-blocked', 'Blocked');
                cell('protection-count', short(offender.failures) + ' failed');
                return row;
            }));
            empty.hidden = top.length > 0;
            card.hidden = false;
        } catch (error) {
            if ([401, 403, 404].includes(error.status)) { card.hidden = true; return; }
            console.error('Abuse protection unavailable:', error);
            ['protection-failures', 'protection-refused', 'protection-blocks', 'protection-active'].forEach(id => { el(id).textContent = '—'; });
            list.replaceChildren();
            empty.hidden = true;
            note.textContent = "Couldn't load abuse protection.";
            note.hidden = false;
            card.hidden = false;
        }
    }

    window.loadOverview = async function () {
        if (!shell.is('dashboard')) return;
        loadProtection();
        try {
            const response = await fetch('/api/stats/delivery?timeScale=hour');
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const stats = await response.json();
            hours = (stats.data || []).map(h => ({ label: h.label || h.hour || '', delivered: h.delivered || 0, deferred: h.deferred || 0, failed: h.failed || 0 }));
            const sum = key => hours.reduce((n, h) => n + h[key], 0);
            const delivered = sum('delivered'), failed = sum('failed');
            el('overview-delivered').textContent = short(delivered);
            el('overview-failed').textContent = short(failed);
            el('overview-deferred').textContent = short(sum('deferred'));
            el('overview-success').textContent = delivered + failed ? (Math.floor(delivered / (delivered + failed) * 1000) / 10) + '%' : '—';
            draw();
        } catch (error) {
            console.error('Overview unavailable:', error);
            ['overview-delivered', 'overview-failed', 'overview-deferred', 'overview-success'].forEach(id => { el(id).textContent = '—'; });
            el('overview-chart').textContent = "Couldn't load delivery figures.";
        }
    };
    document.addEventListener('DOMContentLoaded', () => {
        new ResizeObserver(() => { if (hours.length && el('overview-chart').clientWidth !== drawnWidth) draw(); }).observe(el('overview-chart'));
    });
})();
