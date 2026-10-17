// The console uses the same provisioning service as the CLI. Never interpolate
// directory values into HTML or event handlers: display names are untrusted.
(function () {
    'use strict';
    const root = document.getElementById('view-mail-admin');
    if (!root) return;
    const el = id => document.getElementById(id);
    let accounts = [], domains = [], tab = 'accounts', domain = '', selected = null;
    let busy = false, limit = 250, sequence = 0;

    async function request(path, method = 'GET', body) {
        const options = { method, headers: { Accept: 'application/json' } };
        if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await fetch('/api/provision' + path, options);
        if (!response.ok) {
            if (response.status === 401) throw new Error('Your administrator session has ended. Sign in again.');
            if (response.status === 403) throw new Error('Mailbox administration requires an administrator account.');
            throw new Error((await response.text()).trim() || 'The directory request failed.');
        }
        return response.json();
    }
    function message(text, error = false) {
        const target = el(error ? 'ma-error' : 'ma-notice');
        el('ma-error').hidden = true; el('ma-notice').hidden = true;
        target.textContent = text; target.hidden = !text;
        if (el('ma-account-dialog').open) { el('ma-dialog-message').textContent = text; el('ma-dialog-message').hidden = !text; }
    }
    async function perform(fn) {
        if (busy) return;
        busy = true;
        const controls = Array.from(root.querySelectorAll('button, input, select'));
        const disabled = controls.map(c => c.disabled);
        controls.forEach(c => { c.disabled = true; });
        try { await fn(); } catch (error) { message(error.message, true); }
        finally { controls.forEach((c, i) => { c.disabled = disabled[i]; }); busy = false; }
    }
    function node(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
    function button(text, fn, className = 'btn btn-secondary btn-sm') { const b = node('button', text, className); b.type = 'button'; b.addEventListener('click', fn); return b; }
    function cell(row, value) { const c = node('td'); if (value instanceof Node) c.appendChild(value); else c.textContent = String(value); row.appendChild(c); }
    function quota(bytes) { if (!bytes) return 'Unlimited'; if (bytes % (1 << 30) === 0) return (bytes / (1 << 30)) + ' GiB'; if (bytes % (1 << 20) === 0) return (bytes / (1 << 20)) + ' MiB'; return bytes.toLocaleString() + ' B'; }
    function parseQuota(raw) { const m = /^(\d+)\s*(B|K|KB|KIB|M|MB|MIB|G|GB|GIB)?$/i.exec(raw.trim()); if (!m) throw new Error('Enter a quota such as 5G, or 0 for unlimited.'); const suffix = (m[2] || 'B').toUpperCase(); const n = Number(m[1]) * (suffix.startsWith('G') ? 2 ** 30 : suffix.startsWith('M') ? 2 ** 20 : suffix.startsWith('K') ? 1024 : 1); if (!Number.isSafeInteger(n) || n > 2 ** 50) throw new Error('Quota must be no more than 1 PiB.'); return n; }
    function accountPath() { return '/accounts/' + encodeURIComponent(selected.address); }
    function renderDomains() {
        const tree = el('ma-domain-tree'); tree.replaceChildren();
        const all = button('All domains', () => { domain = ''; limit = 250; renderDomains(); renderTable(); }, 'ma-domain-item');
        all.setAttribute('aria-current', String(!domain)); tree.appendChild(all);
        domains.forEach(d => {
            const b = button('', () => { domain = d.name; tab = 'accounts'; limit = 250; renderDomains(); renderTable(); }, 'ma-domain-item');
            b.appendChild(node('span', d.name)); b.appendChild(node('span', d.accounts)); b.setAttribute('aria-current', String(domain === d.name)); tree.appendChild(b);
        });
    }
    function renderTable() {
        root.querySelectorAll('[data-ma-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.maTab === tab)));
        el('ma-domain-form').hidden = tab !== 'domains'; el('ma-status').hidden = tab !== 'accounts';
        const head = el('ma-table-head'), body = el('ma-table-body'); head.replaceChildren(); body.replaceChildren();
        const headers = tab === 'accounts' ? ['Address', 'Display name', 'Status', 'Quota', 'Aliases'] : tab === 'aliases' ? ['Delivery alias', 'Mailbox account'] : ['Domain', 'Routing', 'Accounts', 'Aliases', ''];
        const heading = node('tr'); headers.forEach(label => heading.appendChild(node('th', label))); head.appendChild(heading);
        const query = el('ma-search').value.trim().toLowerCase();
        let rows = tab === 'domains' ? domains : tab === 'aliases' ? accounts.flatMap(a => a.aliases.map(alias => ({ alias, account: a.address }))) : accounts;
        rows = rows.filter(item => {
            const address = item.address || item.alias || item.name;
            if (tab !== 'domains' && domain && !address.endsWith('@' + domain)) return false;
            if (tab === 'accounts' && el('ma-status').value && item.status !== el('ma-status').value) return false;
            return [address, item.name, item.account].filter(Boolean).some(value => value.toLowerCase().includes(query));
        });
        rows.slice(0, limit).forEach(item => {
            const row = node('tr');
            if (tab === 'accounts') {
                cell(row, button(item.address, () => openAccount(item), 'ma-account-link')); cell(row, item.name);
                cell(row, node('span', item.status, 'ma-status ' + item.status)); cell(row, quota(item.quota_bytes)); cell(row, item.aliases.length);
            } else if (tab === 'aliases') {
                cell(row, item.alias); cell(row, button(item.account, () => openAccount(accounts.find(a => a.address === item.account)), 'ma-account-link'));
            } else {
                cell(row, item.name); cell(row, item.configured ? 'Configured' : 'Not configured'); cell(row, item.accounts); cell(row, item.aliases);
                const remove = button('Remove', () => perform(async () => { if (!window.confirm('Remove local domain ' + item.name + '? An SMTP restart is required.')) return; const result = await request('/domains', 'DELETE', { name: item.name }); message(result.status); await refresh(); }));
                remove.disabled = !item.configured || item.accounts > 0 || item.aliases > 0; cell(row, remove);
            }
            body.appendChild(row);
        });
        if (!rows.length) { const row = node('tr'), c = node('td', 'No matching directory objects.'); c.colSpan = headers.length; row.appendChild(c); body.appendChild(row); }
        el('ma-count').textContent = 'Showing ' + Math.min(limit, rows.length) + ' of ' + rows.length;
        el('ma-more').hidden = rows.length <= limit;
    }
    async function refresh() {
        const seq = ++sequence;
        const status = await request('/status');
        if (!status.available) throw new Error(status.reason);
        const [a, d] = await Promise.all([request('/accounts'), request('/domains')]);
        if (seq !== sequence) return;
        accounts = a.accounts; domains = d.domains;
        ['ma-initial-password', 'ma-password', 'ma-confirm-password'].forEach(id => { el(id).minLength = status.min_password_length || 10; });
        renderDomains(); renderTable();
    }
    function fillAccount(account) {
        selected = account || null;
        const editing = !!account;
        el('ma-account-title').textContent = editing ? account.address : 'Create account';
        el('ma-address').value = editing ? account.address : ''; el('ma-address').readOnly = editing;
        el('ma-name').value = editing ? account.name : '';
        el('ma-quota').value = editing ? String(account.quota_bytes) : '0';
        el('ma-account-status').value = editing ? account.status : 'active';
        el('ma-initial-password').value = ''; el('ma-initial-password').required = !editing;
        el('ma-initial-password').hidden = editing; el('ma-initial-label').hidden = editing;
        el('ma-account-status').hidden = !editing; el('ma-status-label').hidden = !editing;
        el('ma-delete').hidden = !editing; el('ma-account-extras').hidden = !editing;
        el('ma-password').value = ''; el('ma-confirm-password').value = ''; el('ma-alias').value = '';
        el('ma-dialog-message').hidden = true;
        const list = el('ma-alias-list'); list.replaceChildren();
        if (editing) {
            account.aliases.forEach(alias => {
                const li = node('li'); li.appendChild(node('span', alias));
                li.appendChild(button('Remove', () => perform(async () => { const updated = await request(accountPath() + '/aliases', 'DELETE', { alias }); fillAccount(updated); message('Delivery alias removed.'); await refresh(); })));
                list.appendChild(li);
            });
            if (!account.aliases.length) list.appendChild(node('li', 'No delivery aliases.'));
        }
    }
    function openAccount(account) { fillAccount(account); el('ma-account-dialog').showModal(); }
    window.refreshMailAdmin = function () { refresh().catch(error => message(error.message, true)); };
    el('ma-create').addEventListener('click', () => openAccount(null));
    el('ma-close').addEventListener('click', () => { if (!busy) el('ma-account-dialog').close(); });
    el('ma-account-dialog').addEventListener('cancel', event => { if (busy) event.preventDefault(); });
    el('ma-refresh').addEventListener('click', window.refreshMailAdmin);
    ['ma-search', 'ma-status'].forEach(id => el(id).addEventListener('input', () => { limit = 250; renderTable(); }));
    el('ma-more').addEventListener('click', () => { limit += 250; renderTable(); });
    root.querySelectorAll('[data-ma-tab]').forEach(b => b.addEventListener('click', () => { tab = b.dataset.maTab; limit = 250; renderTable(); }));
    el('ma-account-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const payload = { name: el('ma-name').value, quota_bytes: parseQuota(el('ma-quota').value) };
        if (selected) payload.status = el('ma-account-status').value;
        else { payload.address = el('ma-address').value; payload.password = el('ma-initial-password').value; }
        const updated = await request(selected ? accountPath() : '/accounts', selected ? 'PATCH' : 'POST', payload);
        fillAccount(updated); message('Account saved.'); await refresh();
    }); });
    el('ma-alias-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => { const updated = await request(accountPath() + '/aliases', 'POST', { alias: el('ma-alias').value }); fillAccount(updated); message('Delivery alias added.'); await refresh(); }); });
    el('ma-password-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        if (el('ma-password').value !== el('ma-confirm-password').value) throw new Error('The new passwords do not match.');
        const result = await request(accountPath() + '/password', 'POST', { password: el('ma-password').value }); el('ma-password').value = ''; el('ma-confirm-password').value = ''; message(result.status);
    }); });
    el('ma-delete').addEventListener('click', () => perform(async () => {
        const address = selected.address;
        if (window.prompt('Delete this account? Mailbox files will be retained. Type ' + address + ' to confirm:') !== address) return;
        const result = await request(accountPath(), 'DELETE', { confirm: address }); selected = null; el('ma-account-dialog').close(); message(result.status); await refresh();
    }));
    el('ma-domain-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => { const result = await request('/domains', 'POST', { name: el('ma-new-domain').value }); el('ma-new-domain').value = ''; message(result.status); await refresh(); }); });
}());
