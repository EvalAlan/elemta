// Abuse protection: the policy every service follows, and what it is doing
// (internal/abuse). Addresses, account names and reasons come from clients:
// they only ever reach the page through textContent.
(function () {
    'use strict';
    const view = document.getElementById('view-abuse');
    if (!view) return;
    const el = id => document.getElementById(id);
    let you = '', allowlist = [];

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
    async function refresh() {
        try {
            const status = await call('');
            fillPolicy(status.policy); fillStatus(status); fillYou(status);
            fillBlocks(status.blocks || []); fillAccounts(status.accounts || []); fillEvents(status.events || []);
        } catch (error) { notice(error.message, true); }
    }
    async function act(fn) {
        try { await fn(); await refresh(); } catch (error) { notice(error.message, true); }
    }
    window.refreshAbuse = () => { notice(''); return refresh(); };

    el('abuse-policy-form').addEventListener('submit', event => {
        event.preventDefault();
        const policy = readPolicy();
        if (policy.mode === 'off' && !window.confirm('Turn abuse protection off? Nothing is blocked, and connection limits fall back to the configuration file.')) return;
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
