// Abuse protection: the policy every service follows, and what it is doing
// (internal/abuse). Addresses, account names and reasons come from clients:
// they only ever reach the page through textContent.
(function () {
    'use strict';
    const view = document.getElementById('view-abuse');
    if (!view) return;
    const el = id => document.getElementById(id);
    let you = '', allowlist = [], range = '24h', timer = null;

    // Fixed order, so a service keeps its colour whichever ones have data.
    const SERVICES = [['mailbox', 'IMAP and POP3'], ['smtp', 'SMTP'], ['webmail', 'Webmail'], ['admin', 'Admin console']];
    const REASONS = [['blocked', 'Blocked'], ['limit', 'Too many connections'], ['rate', 'Too fast']];

    async function call(path, method = 'GET', body) {
        const options = { method, headers: { Accept: 'application/json' } };
        if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await fetch('/api/abuse' + path, options);
        if (response.status === 401) throw new Error('Your administrator session has ended. Sign in again.');
        if (response.status === 403) throw new Error('Abuse protection requires an administrator account.');
        if (!response.ok) throw new Error((await response.text()).trim() || 'The request failed.');
        return response.json();
    }
    function notice(text, error = false) {
        const line = el('abuse-notice');
        line.textContent = text; line.hidden = !text;
        line.classList.toggle('abuse-error', error);
    }
    function cell(row, value) {
        const td = document.createElement('td');
        if (value instanceof Node) td.appendChild(value); else td.textContent = value === undefined || value === null ? '' : String(value);
        row.appendChild(td);
    }
    function table(body, rows, columns, empty) {
        const target = el(body); target.replaceChildren();
        if (!rows.length) {
            const row = document.createElement('tr'), td = document.createElement('td');
            td.textContent = empty; td.colSpan = columns; row.appendChild(td); target.appendChild(row);
        }
        return target;
    }
    function when(value) { return value ? new Date(value).toLocaleString() : ''; }
    function remaining(value) {
        const minutes = Math.max(1, Math.ceil((new Date(value) - Date.now()) / 60000));
        return minutes < 120 ? minutes + ' min' : Math.round(minutes / 60) + ' h';
    }
    function fillPolicy(p) {
        el('abuse-mode').value = p.mode;
        el('abuse-connections').value = p.connections_per_address;
        el('abuse-rate').value = p.connections_per_minute;
        el('abuse-network').value = p.failures_per_network;
        el('abuse-firewall').value = p.firewall;
        el('abuse-failures').value = p.failures_per_address;
        el('abuse-window').value = p.window_minutes;
        el('abuse-block').value = p.block_minutes;
        el('abuse-max-block').value = p.max_block_hours;
        allowlist = p.allowlist || [];
        el('abuse-allowlist').value = allowlist.join('\n');
    }
    function readPolicy() {
        return {
            mode: el('abuse-mode').value,
            connections_per_address: Number(el('abuse-connections').value),
            connections_per_minute: Number(el('abuse-rate').value),
            failures_per_network: Number(el('abuse-network').value),
            firewall: el('abuse-firewall').value,
            failures_per_address: Number(el('abuse-failures').value),
            window_minutes: Number(el('abuse-window').value),
            block_minutes: Number(el('abuse-block').value),
            max_block_hours: Number(el('abuse-max-block').value),
            allowlist: el('abuse-allowlist').value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean),
        };
    }
    function fillStatus(status) {
        const shared = el('abuse-shared');
        shared.textContent = status.shared
            ? 'Shared across all services through Valkey.'
            : 'Valkey is unreachable: services keep the last policy they received and count on their own.';
        shared.classList.toggle('abuse-error', !status.shared);
    }
    function fillYou(status) {
        you = status.you || '';
        el('abuse-you').hidden = !you || status.you_exempt;
        el('abuse-you-address').textContent = you;
    }
    function fillBlocks(blocks) {
        const body = table('abuse-blocks', blocks, 5, 'No addresses are blocked.');
        blocks.forEach(b => {
            const row = document.createElement('tr');
            cell(row, b.network);
            cell(row, b.reason + (b.service ? ' (' + b.service + ')' : ''));
            cell(row, b.manual ? 'By hand' : b.failures);
            cell(row, remaining(b.until));
            const button = document.createElement('button');
            button.type = 'button'; button.className = 'btn btn-secondary btn-sm'; button.textContent = 'Unblock';
            button.addEventListener('click', () => act(async () => {
                await call('/blocks?address=' + encodeURIComponent(b.network), 'DELETE');
                notice(b.network + ' unblocked.');
            }));
            cell(row, button);
            body.appendChild(row);
        });
    }
    function fillAccounts(accounts) {
        const body = table('abuse-accounts', accounts, 2, 'No failed sign-ins in this window.');
        accounts.forEach(a => {
            const row = document.createElement('tr');
            cell(row, a.account); cell(row, a.failures);
            body.appendChild(row);
        });
    }
    function fillEvents(events) {
        const body = table('abuse-events', events, 5, 'Nothing recorded yet.');
        events.forEach(ev => {
            const row = document.createElement('tr');
            cell(row, when(ev.time)); cell(row, ev.action.replace('-', ' ')); cell(row, ev.network);
            cell(row, ev.detail); cell(row, ev.by);
            body.appendChild(row);
        });
    }
    function fillEnforcers(enforcers, policy) {
        const body = table('abuse-enforcers', enforcers, 5, 'No firewall agent has reported yet.');
        enforcers.forEach(r => {
            const row = document.createElement('tr');
            const age = (Date.now() - new Date(r.at)) / 1000;
            cell(row, r.name + ' on ' + r.host);
            cell(row, r.error ? 'Error: ' + r.error : age > 120 ? 'Not reporting' : r.mode === 'apply' ? 'Applying' : r.mode === 'log' ? 'Log only' : 'Off');
            cell(row, r.entries); cell(row, r.dropped); cell(row, when(r.at));
            body.appendChild(row);
        });
        el('abuse-firewall-note').textContent = policy.firewall === 'apply'
            ? 'Blocked addresses are dropped at the firewall, before they reach a service.'
            : policy.firewall === 'log'
                ? 'Log only: the entries column shows what would be dropped. Services still refuse these addresses themselves.'
                : 'Off: services still refuse blocked addresses themselves.';
    }

    // ---- graphs ----------------------------------------------------------

    const SVG = 'http://www.w3.org/2000/svg';
    function svg(tag, attrs, parent) {
        const n = document.createElementNS(SVG, tag);
        Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
        if (parent) parent.appendChild(n);
        return n;
    }
    function niceMax(value) {
        if (value <= 4) return 4;
        const power = Math.pow(10, Math.floor(Math.log10(value)));
        for (const step of [1, 2, 2.5, 5, 10]) if (step * power >= value) return step * power;
        return 10 * power;
    }
    function label(t, step) {
        const d = new Date(t);
        if (step >= 21600) return d.toLocaleDateString([], { weekday: 'short', hour: 'numeric' });
        return d.toLocaleTimeString([], { hour: 'numeric', minute: step < 3600 ? '2-digit' : undefined });
    }
    function legend(target, keys) {
        const box = el(target); box.replaceChildren();
        keys.forEach(([, name], i) => {
            const item = document.createElement('span');
            const swatch = document.createElement('i');
            swatch.className = 'abuse-swatch abuse-series-' + (i + 1);
            item.append(swatch, document.createTextNode(name));
            box.appendChild(item);
        });
    }
    // Stacked bars over time. Bars carry their own hover and keyboard focus,
    // and the table beneath holds every number, so nothing rests on colour or
    // on a pointer.
    function stacked(target, buckets, keys, values, step, emptyText) {
        const box = el(target); box.replaceChildren();
        const width = Math.max(box.clientWidth, 320), height = 200;
        const left = 40, right = 8, top = 10, bottom = 24;
        const plotW = width - left - right, plotH = height - top - bottom;
        const totals = buckets.map(b => keys.reduce((n, [k]) => n + (values(b)[k] || 0), 0));
        const peak = Math.max(0, ...totals);
        const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, width, height, role: 'img', 'aria-label': emptyText.replace('Nothing', 'Graph of') });
        const ceiling = niceMax(peak);
        for (let i = 0; i <= 4; i++) {
            const y = top + plotH - plotH * i / 4;
            svg('line', { x1: left, x2: width - right, y1: y, y2: y, class: i ? 'abuse-grid' : 'abuse-axis' }, root);
            const text = svg('text', { x: left - 6, y: y + 4, 'text-anchor': 'end', class: 'abuse-tick' }, root);
            text.textContent = Math.round(ceiling * i / 4).toLocaleString();
        }
        const band = plotW / buckets.length;
        const barW = Math.min(24, Math.max(3, band - 2));
        const every = Math.ceil(buckets.length / Math.max(2, Math.floor(plotW / 80)));
        buckets.forEach((b, i) => {
            const x = left + band * i + (band - barW) / 2;
            if ((buckets.length - 1 - i) % every === 0) {
                const text = svg('text', { x: x + barW / 2, y: height - 7, 'text-anchor': 'middle', class: 'abuse-tick' }, root);
                text.textContent = label(b.time, step);
            }
            let y = top + plotH;
            const parts = keys.map(([k], slot) => ({ n: values(b)[k] || 0, slot })).filter(p => p.n > 0);
            parts.forEach((p, index) => {
                const h = Math.max(index ? 4 : 2, plotH * p.n / ceiling);
                y -= h;
                const end = index === parts.length - 1, r = end ? Math.min(4, h, barW / 2) : 0;
                // A 2px surface gap between segments, rounded only at the data end.
                const inner = index ? 2 : 0;
                svg('path', {
                    d: `M${x} ${y + h - inner}V${y + r}Q${x} ${y} ${x + r} ${y}H${x + barW - r}Q${x + barW} ${y} ${x + barW} ${y + r}V${y + h - inner}Z`,
                    class: 'abuse-series-' + (p.slot + 1),
                }, root);
            });
            // The whole column is the hit target, wider than the mark.
            const hit = svg('rect', { x: left + band * i, y: top, width: band, height: plotH, class: 'abuse-hit', tabindex: totals[i] ? 0 : -1 }, root);
            const show = () => tooltip(box, b, keys, values, step, left + band * (i + .5), totals[i]);
            hit.addEventListener('pointerenter', show);
            hit.addEventListener('focus', show);
            hit.addEventListener('pointerleave', () => hideTip(box));
            hit.addEventListener('blur', () => hideTip(box));
        });
        box.appendChild(root);
        if (!peak) {
            const none = document.createElement('p');
            none.className = 'abuse-empty'; none.textContent = emptyText;
            box.appendChild(none);
        }
    }
    function tooltip(box, b, keys, values, step, x, total) {
        hideTip(box);
        const tip = document.createElement('div');
        tip.className = 'abuse-tip';
        const head = document.createElement('strong');
        head.textContent = new Date(b.time).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' }) + ': ' + total.toLocaleString();
        tip.appendChild(head);
        keys.forEach(([k, name], i) => {
            const n = values(b)[k] || 0;
            if (!n) return;
            const row = document.createElement('span');
            const swatch = document.createElement('i');
            swatch.className = 'abuse-swatch abuse-series-' + (i + 1);
            row.append(swatch, document.createTextNode(name + ' ' + n.toLocaleString()));
            tip.appendChild(row);
        });
        box.appendChild(tip);
        tip.style.left = Math.min(x + 12, box.clientWidth - tip.offsetWidth - 4) + 'px';
    }
    function hideTip(box) { box.querySelectorAll('.abuse-tip').forEach(n => n.remove()); }
    function fillTable(target, buckets, keys, values, step) {
        const shown = buckets.filter(b => keys.some(([k]) => values(b)[k]));
        const body = table(target, shown, keys.length + 1, 'Nothing in this range.');
        shown.slice().reverse().forEach(b => {
            const row = document.createElement('tr');
            cell(row, label(b.time, step));
            keys.forEach(([k]) => cell(row, values(b)[k] || 0));
            body.appendChild(row);
        });
    }
    function fillTiles(stats, active) {
        el('abuse-tile-failures').textContent = stats.failures.toLocaleString();
        el('abuse-tile-refused').textContent = stats.refused.toLocaleString();
        el('abuse-tile-blocks').textContent = stats.blocks.toLocaleString();
        el('abuse-tile-active').textContent = active.toLocaleString();
    }
    function fillTop(top) {
        const body = table('abuse-top', top, 3, 'No failed sign-ins in the last two hours.');
        top.forEach(o => {
            const row = document.createElement('tr');
            const button = document.createElement('button');
            button.type = 'button'; button.className = 'btn btn-secondary btn-sm'; button.textContent = 'Block';
            button.addEventListener('click', () => {
                el('abuse-block-address').value = o.network;
                el('abuse-block-reason').focus();
            });
            cell(row, o.network); cell(row, o.failures); cell(row, button);
            body.appendChild(row);
        });
    }
    let lastStats = null;
    function drawGraphs() {
        if (!lastStats) return;
        const s = lastStats;
        stacked('abuse-chart-failures', s.buckets, SERVICES, b => b.failures, s.step_seconds, 'Nothing failed in this range.');
        stacked('abuse-chart-refused', s.buckets, REASONS, b => b.refused, s.step_seconds, 'Nothing refused in this range.');
        fillTable('abuse-table-failures', s.buckets, SERVICES, b => b.failures, s.step_seconds);
        fillTable('abuse-table-refused', s.buckets, REASONS, b => b.refused, s.step_seconds);
    }
    async function refresh() {
        try {
            const [status, stats] = await Promise.all([call(''), call('/metrics?range=' + range)]);
            fillPolicy(status.policy); fillStatus(status); fillYou(status);
            fillBlocks(status.blocks || []); fillAccounts(status.accounts || []); fillEvents(status.events || []);
            fillEnforcers(status.enforcers || [], status.policy);
            lastStats = stats; fillTiles(stats, (status.blocks || []).length); fillTop(stats.top || []); drawGraphs();
        } catch (error) { notice(error.message, true); }
    }
    async function act(fn) {
        try { await fn(); await refresh(); } catch (error) { notice(error.message, true); }
    }
    window.refreshAbuse = () => {
        notice('');
        // Stays current while the page is open, and leaves the form alone
        // while someone is editing it.
        clearInterval(timer);
        timer = setInterval(() => {
            if (!view.classList.contains('active') || view.contains(document.activeElement) && document.activeElement.matches('input, select, textarea')) return;
            refresh();
        }, 30000);
        return refresh();
    };
    view.querySelectorAll('[data-abuse-range]').forEach(button => button.addEventListener('click', () => {
        range = button.dataset.abuseRange;
        view.querySelectorAll('[data-abuse-range]').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
        refresh();
    }));
    legend('abuse-legend-failures', SERVICES);
    legend('abuse-legend-refused', REASONS);
    window.addEventListener('resize', drawGraphs);

    el('abuse-policy-form').addEventListener('submit', event => {
        event.preventDefault();
        const policy = readPolicy();
        if (policy.mode === 'off' && !window.confirm('Turn abuse protection off? Nothing is blocked, and connection limits fall back to the configuration file.')) return;
        if (policy.firewall === 'apply' && !policy.allowlist.length && !window.confirm('Apply blocks at the firewall with an empty allowlist? A block could cut off your own network until it expires.')) return;
        act(async () => {
            const saved = await call('/policy', 'PUT', policy);
            notice(saved.published
                ? 'Saved. Every service applies it within a few seconds, with no restart.'
                : 'Saved, but it could not be published: other services apply it when Valkey returns.', !saved.published);
        });
    });
    el('abuse-block-form').addEventListener('submit', event => {
        event.preventDefault();
        act(async () => {
            const address = el('abuse-block-address').value.trim();
            const block = await call('/blocks', 'POST', { address, minutes: Number(el('abuse-block-minutes').value), reason: el('abuse-block-reason').value.trim() });
            el('abuse-block-address').value = ''; el('abuse-block-reason').value = '';
            notice(block.network + ' blocked. Every service applies it within a few seconds.');
        });
    });
    el('abuse-you-add').addEventListener('click', () => act(async () => {
        const policy = readPolicy();
        policy.allowlist = allowlist.concat(you);
        await call('/policy', 'PUT', policy);
        notice(you + ' added to the allowlist.');
    }));
})();
