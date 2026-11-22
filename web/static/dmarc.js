// The DMARC page (internal/api/dmarc_report.go). Reports are written by
// whoever mailed them: every string from one reaches the page only through
// textContent, and the chart is built node by node.
(function () {
    'use strict';
    const view = document.getElementById('report-dmarc');
    if (!view) return;
    const el = id => document.getElementById(id);
    const SVG = 'http://www.w3.org/2000/svg';
    const SOURCES_SHOWN = 50;
    let report = null, selected = '', days = 30, loading = 0, poll = null, allSources = false, drawnWidth = 0, editing = '';

    function node(tag, text, className) {
        const n = document.createElement(tag);
        if (text !== undefined) n.textContent = text;
        if (className) n.className = className;
        return n;
    }
    function shape(tag, attrs, parent) {
        const n = document.createElementNS(SVG, tag);
        for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
        if (parent) parent.appendChild(n);
        return n;
    }
    function count(n) { return Number(n).toLocaleString(); }
    function compact(n) { return n < 10000 ? count(n) : Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n); }
    // Rounded down: 99.96% isn't all of it.
    function percent(part, whole) { return whole ? (Math.floor(part / whole * 1000) / 10) + '%' : '—'; }
    function dayText(day) { return new Date(day + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' }); }
    function policyText(d) {
        if (!d.policy) return d.policy_checked ? 'No policy' : "Couldn't check";
        return 'p=' + d.policy + (d.policy_checked ? '' : ' (from reports)');
    }
    function notice(text, error) {
        el('dmarc-notice').textContent = text; el('dmarc-notice').hidden = !text;
        el('dmarc-notice').classList.toggle('dmarc-error', !!error);
    }
    async function request(path, method = 'GET', body) {
        const options = { method, headers: { Accept: 'application/json' } };
        if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await fetch('/api/provision/dmarc' + path, options);
        if (!response.ok) throw new Error((await response.text()).trim() || 'The request failed.');
        return response.json();
    }
    function current() { return report && report.domains.find(d => d.domain === selected); }
    function running(d) {
        const a = d.address;
        // A run a restart cut short stops counting as running after its limit.
        return !!(a && a.backfill_started && !a.backfill_finished && Date.now() - Date.parse(a.backfill_started) < 31 * 60000);
    }

    async function load() {
        const seq = ++loading;
        clearTimeout(poll);
        view.setAttribute('aria-busy', 'true');
        try {
            const next = await request('/report?days=' + days);
            if (seq !== loading) return;
            report = next;
            if (!current()) {
                const best = [...report.domains].sort((a, b) => b.messages - a.messages)[0];
                selected = best ? best.domain : '';
            }
            render();
            if (report.domains.some(running)) {
                poll = setTimeout(() => { if (shell.is('reports', 'dmarc')) load(); }, 3000);
            }
        } catch (error) {
            if (seq === loading) notice(error.message, true);
        } finally {
            if (seq === loading) view.removeAttribute('aria-busy');
        }
    }

    function table(body, rows, empty, columns) {
        body.replaceChildren();
        rows.forEach(values => {
            const tr = node('tr');
            values.forEach(v => { const td = node('td'); if (v instanceof Node) td.appendChild(v); else td.textContent = String(v); tr.appendChild(td); });
            body.appendChild(tr);
        });
        if (!rows.length) { const tr = node('tr'), td = node('td', empty); td.colSpan = columns; tr.appendChild(td); body.appendChild(tr); }
    }

    function render() {
        table(el('dmarc-domains'), report.domains.map(d => {
            const pick = node('button', d.domain, 'dmarc-pick');
            pick.type = 'button';
            pick.setAttribute('aria-pressed', String(d.domain === selected));
            pick.addEventListener('click', () => { selected = d.domain; allSources = false; notice(''); render(); });
            return [pick, policyText(d), compact(d.messages), percent(d.aligned, d.messages), d.reporters.length,
                d.last_report ? dayText(d.last_report) : (d.address ? 'None yet' : 'Not set up')];
        }), 'No domains.', 6);

        const d = current();
        el('dmarc-detail').hidden = !d;
        if (!d) return;
        el('dmarc-title').textContent = d.domain;
        el('dmarc-policy').textContent = policyText(d);
        el('dmarc-policy-from').textContent = d.policy_from && d.policy_from !== d.domain ? 'inherited from ' + d.policy_from : '';
        el('dmarc-volume').textContent = compact(d.messages);
        el('dmarc-aligned').textContent = percent(d.aligned, d.messages);
        el('dmarc-reporter-count').textContent = count(d.reporters.length);
        el('dmarc-last').textContent = d.last_report ? dayText(d.last_report) : 'None yet';

        el('dmarc-advice').replaceChildren(...d.advice.map(a => {
            const li = node('li', undefined, a.level === 'ok' ? 'dmarc-advice-ok' : 'dmarc-advice-warning');
            li.appendChild(node('strong', a.level === 'ok' ? '✓ Next step' : '! Check this'));
            li.appendChild(node('span', a.text));
            return li;
        }));
        renderSetup(d);
        draw();
        table(el('dmarc-daily'), d.daily.map(x => [dayText(x.day), count(x.aligned), count(x.failing)]).reverse(), 'No days.', 3);

        const shown = allSources ? d.sources : d.sources.slice(0, SOURCES_SHOWN);
        table(el('dmarc-sources'), shown.map(s => {
            const who = node('span', s.source_ip);
            if (s.place) who.appendChild(node('small', s.place, 'field-hint'));
            return [who, s.kind, count(s.messages), s.spf + (s.spf_domain ? ' · ' + s.spf_domain : ''),
                s.dkim + (s.dkim_domain ? ' · ' + s.dkim_domain : ''), s.header_from, s.disposition];
        }), 'No sources in this period.', 7);
        el('dmarc-more').hidden = shown.length === d.sources.length;
        el('dmarc-more').textContent = 'Show all ' + count(d.sources.length);
        el('dmarc-attribution').hidden = !d.sources.some(s => s.place);

        // The domain is checked; the name beside it is the reporter's claim.
        const reporter = r => {
            const who = node('span', r.sender || '(no sender)');
            if (r.org) who.appendChild(node('small', 'calls itself ' + r.org, 'field-hint'));
            return [who, count(r.reports), count(r.messages)];
        };
        table(el('dmarc-reporters'), d.reporters.map(reporter), 'No verified reports in this period.', 3);
        el('dmarc-unverified-section').hidden = !d.unverified.length;
        el('dmarc-unverified-summary').textContent = 'Unverified reports, not counted (' + count(d.unverified.reduce((n, r) => n + r.reports, 0)) + ')';
        table(el('dmarc-unverified'), d.unverified.map(reporter), 'None.', 3);
    }

    function renderSetup(d) {
        const a = d.address, manage = report.manage;
        el('dmarc-setup-status').textContent = a ? 'Reading reports sent to ' + a.address + '.'
            : manage ? "Reports for this domain aren't being read yet. Choose the address they're sent to."
                : "Reports for this domain aren't being read yet. A system administrator can set that up.";
        el('dmarc-setup-form').hidden = !manage;
        // A poll mustn't take away what is being typed.
        const input = el('dmarc-address');
        if (editing !== d.domain || document.activeElement !== input) {
            input.value = a ? a.address : (d.suggested || '');
            editing = d.domain;
        }
        el('dmarc-remove').hidden = !manage || !a;
        el('dmarc-backfill').hidden = !manage || !a;
        el('dmarc-backfill').disabled = running(d);
        let state = '';
        if (a && running(d)) state = 'Reading earlier reports…';
        else if (a && a.backfill_error) state = 'Reading earlier reports: ' + a.backfill_error + '.';
        else if (a && a.backfill_finished) {
            state = 'Earlier reports read: ' + count(a.backfill_read) + ' messages, ' + count(a.backfill_stored) + ' new reports.';
            if (a.backfill_unindexed) state += ' ' + count(a.backfill_unindexed) + " messages weren't indexed yet; read again later to include them.";
        }
        el('dmarc-backfill-state').textContent = state;
    }

    // Stacked daily bars, drawn at the width they are shown at so that the
    // text never scales.
    function draw() {
        const d = current(), box = el('dmarc-chart');
        if (!d || !shell.is('reports', 'dmarc')) return;
        const width = box.clientWidth;
        if (!width) return;
        drawnWidth = width;
        const height = 220, top = 10, bottom = 24;
        const largest = Math.max(0, ...d.daily.map(x => x.aligned + x.failing));
        const step = niceStep(largest / 4 || 1), max = Math.max(step, Math.ceil(largest / step) * step);
        const ticks = [];
        for (let t = 0; t <= max; t += step) ticks.push(t);
        const left = 12 + Math.max(...ticks.map(t => compact(t).length)) * 7;
        const plot = height - top - bottom, slot = (width - left - 4) / d.daily.length;
        const bar = Math.max(1, Math.min(24, slot - Math.max(1, Math.min(slot * .35, 8))));
        const y = v => top + plot - v / max * plot;

        const svg = shape('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', tabindex: '0' });
        svg.setAttribute('aria-label', `Mail per day for ${d.domain}: ${count(d.aligned)} passing and ${count(d.messages - d.aligned)} failing. Arrow keys read each day; the table below has the same numbers.`);
        ticks.forEach(t => {
            shape('line', { x1: left, x2: width - 4, y1: y(t), y2: y(t), class: t ? 'dmarc-grid' : 'dmarc-axis' }, svg);
            shape('text', { x: left - 6, y: y(t) + 4, class: 'dmarc-tick', 'text-anchor': 'end' }, svg).textContent = compact(t);
        });
        const every = Math.max(1, Math.ceil(d.daily.length / Math.max(2, Math.floor((width - left) / 64))));
        const hits = [];
        d.daily.forEach((x, i) => {
            const centre = left + slot * (i + .5), from = centre - bar / 2;
            const back = d.daily.length - 1 - i;
            hits.push(shape('rect', { x: left + slot * i, y: top, width: slot, height: plot, class: 'dmarc-hit' }, svg));
            let base = top + plot;
            const parts = [['dmarc-pass', x.aligned], ['dmarc-fail', x.failing]].filter(p => p[1] > 0);
            parts.forEach(([className, value], n) => {
                // A few failures among thousands still show.
                const h = Math.max(2, value / max * plot - (n ? 2 : 0));
                const end = base - h, r = n === parts.length - 1 ? Math.min(4, bar / 2, h) : 0;
                shape('path', { class: className, d: `M${from},${base}V${end + r}Q${from},${end} ${from + r},${end}H${from + bar - r}Q${from + bar},${end} ${from + bar},${end + r}V${base}Z` }, svg);
                base = end - 2;
            });
            if (back % every === 0 && centre > left + 18) {
                shape('text', { x: Math.min(centre, width - 22), y: height - 6, class: 'dmarc-tick', 'text-anchor': 'middle' }, svg).textContent = dayText(x.day);
            }
        });

        const tip = node('div', undefined, 'dmarc-tip');
        tip.hidden = true; tip.setAttribute('aria-live', 'polite');
        let at = -1;
        const show = i => {
            at = i;
            hits.forEach((h, n) => h.classList.toggle('dmarc-hit-on', n === i));
            if (i < 0) { tip.hidden = true; return; }
            const x = d.daily[i];
            tip.replaceChildren(node('strong', dayText(x.day)));
            [['dmarc-pass', 'Passing', x.aligned], ['dmarc-fail', 'Failing', x.failing]].forEach(([key, name, value]) => {
                const line = node('span');
                line.appendChild(node('i', undefined, 'dmarc-key ' + key));
                line.appendChild(document.createTextNode(name + ' ' + count(value)));
                tip.appendChild(line);
            });
            tip.hidden = false;
            const centre = left + slot * (i + .5);
            tip.style.left = Math.max(0, Math.min(width - tip.offsetWidth, centre - tip.offsetWidth / 2)) + 'px';
        };
        svg.addEventListener('pointermove', e => {
            const x = e.clientX - svg.getBoundingClientRect().left - left;
            show(x < 0 ? -1 : Math.min(d.daily.length - 1, Math.floor(x / slot)));
        });
        svg.addEventListener('pointerleave', () => show(-1));
        svg.addEventListener('focus', () => show(d.daily.length - 1));
        svg.addEventListener('blur', () => show(-1));
        svg.addEventListener('keydown', e => {
            if (e.key === 'ArrowLeft') show(Math.max(0, (at < 0 ? d.daily.length : at) - 1));
            else if (e.key === 'ArrowRight') show(Math.min(d.daily.length - 1, at + 1));
            else if (e.key === 'Escape') show(-1);
            else return;
            e.preventDefault();
        });
        box.replaceChildren(svg, tip);
        if (!largest) box.appendChild(node('p', 'No verified reports in this period.', 'dmarc-empty'));
    }
    function niceStep(v) {
        const power = Math.pow(10, Math.floor(Math.log10(v)));
        return Math.max(1, [1, 2, 5, 10].find(m => m * power >= v) * power);
    }

    async function change(button, work) {
        button.disabled = true;
        notice('');
        try { await work(); await load(); } catch (error) { notice(error.message, true); } finally {
            button.disabled = false;
            const d = current();
            if (d) el('dmarc-backfill').disabled = running(d);
        }
    }
    el('dmarc-setup-form').addEventListener('submit', event => {
        event.preventDefault();
        const domain = selected;
        change(el('dmarc-save'), async () => {
            await request('/addresses/' + encodeURIComponent(domain), 'PUT', { address: el('dmarc-address').value.trim() });
            editing = '';
            notice('Reports for ' + domain + ' will be read as they arrive.');
        });
    });
    el('dmarc-remove').addEventListener('click', () => {
        const domain = selected;
        if (!window.confirm('Stop reading DMARC reports for ' + domain + '? What was already read is kept.')) return;
        change(el('dmarc-remove'), async () => {
            await request('/addresses/' + encodeURIComponent(domain), 'DELETE');
            editing = '';
            notice('Reports for ' + domain + ' are no longer read.');
        });
    });
    el('dmarc-backfill').addEventListener('click', () => {
        const d = current(), domain = selected;
        if (!d || !d.address) return;
        if (!window.confirm('Read earlier reports from the mailbox that receives ' + d.address.address + '?\n\nOnly mail addressed to it is read, nothing is changed, and this is recorded in the audit log.')) return;
        change(el('dmarc-backfill'), async () => {
            await request('/addresses/' + encodeURIComponent(domain) + '/backfill', 'POST');
        });
    });
    el('dmarc-more').addEventListener('click', () => { allSources = true; render(); });
    view.querySelectorAll('[data-dmarc-days]').forEach(b => b.addEventListener('click', () => {
        days = Number(b.dataset.dmarcDays);
        view.querySelectorAll('[data-dmarc-days]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
        load();
    }));
    new ResizeObserver(() => { if (report && el('dmarc-chart').clientWidth !== drawnWidth) draw(); }).observe(el('dmarc-chart'));
    window.openDMARC = load;
})();
