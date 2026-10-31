// Abuse protection: the policy every service follows (internal/abuse). Values
// that came from clients, such as addresses and account names, are untrusted:
// they only ever reach the page through textContent.
(function () {
    'use strict';
    const view = document.getElementById('view-abuse');
    if (!view) return;
    const el = id => document.getElementById(id);

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
    function fillPolicy(p) {
        el('abuse-mode').value = p.mode;
        el('abuse-connections').value = p.connections_per_address;
        el('abuse-allowlist').value = (p.allowlist || []).join('\n');
    }
    function readPolicy() {
        return {
            mode: el('abuse-mode').value,
            connections_per_address: Number(el('abuse-connections').value),
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
    async function refresh() {
        try {
            const status = await call('');
            fillPolicy(status.policy); fillStatus(status); notice('');
        } catch (error) { notice(error.message, true); }
    }
    window.refreshAbuse = refresh;

    el('abuse-policy-form').addEventListener('submit', async event => {
        event.preventDefault();
        const policy = readPolicy();
        if (policy.mode === 'off' && !window.confirm('Turn abuse protection off? Connection limits fall back to the configuration file.')) return;
        try {
            const saved = await call('/policy', 'PUT', policy);
            fillPolicy(saved.policy); fillStatus(saved);
            notice(saved.published
                ? 'Saved. Every service applies it within a few seconds, with no restart.'
                : 'Saved, but it could not be published: other services apply it when Valkey returns.', !saved.published);
        } catch (error) { notice(error.message, true); }
    });
})();
