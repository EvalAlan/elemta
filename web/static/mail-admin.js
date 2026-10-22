// The console uses the same provisioning service as the CLI. Never interpolate
// directory values into HTML or event handlers: display names are untrusted.
(function () {
    'use strict';
    const root = document.getElementById('view-mail-admin');
    if (!root) return;
    const el = id => document.getElementById(id);
    let accounts = [], domains = [], lists = [], classes = [], domainClasses = {}, tab = 'accounts', domain = '', selected = null;
    let busy = false, limit = 250, sequence = 0, mailboxAdmin = false, selectedList = null, selectedClass = null;
    // A domain administrator (scope.all false) sees only their domains, and
    // none of the system-wide controls; the server enforces the same.
    let scope = { all: true }, audit = [], auditDone = false;

    // Settings a class of service, or an account's overrides, can hold
    // (internal/mailpolicy). Sizes and counts take "0" for unlimited; blank
    // and "Inherit" leave the setting to the next layer.
    const LIMITS = [
        ['quota_bytes', 'Quota', 'size'], ['max_message_bytes', 'Largest message', 'size'], ['max_attachment_bytes', 'Largest attachment', 'size'],
        ['messages_per_hour', 'Messages sent per hour', 'count'], ['recipients_per_message', 'Recipients per message', 'count'], ['recipients_per_day', 'Recipients per day', 'count'],
    ];
    const PROTOCOLS = [['imap', 'IMAP'], ['pop3', 'POP3'], ['webmail', 'Webmail'], ['dav', 'Calendar and contact sync (DAV)'], ['submission', 'SMTP submission from mail apps']];
    const SWITCHES = [['external_forwarding', 'Forwarding outside the server'], ['filters', 'Filters and vacation replies'], ['require_app_passwords', 'Require app passwords'], ['require_two_factor', 'Require two-step verification']];
    const RETENTION = [['trash_days', 'Empty Trash after (days)', 'days'], ['junk_days', 'Empty Junk after (days)', 'days'], ['retention_days', 'Delete all mail older than (days)', 'days'], ['legal_hold', 'Legal hold (keep everything)', 'switch']];

    async function request(path, method = 'GET', body) {
        const options = { method, headers: { Accept: 'application/json' } };
        if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await fetch('/api/provision' + path, options);
        if (!response.ok) {
            if (response.status === 401) throw new Error('Your administrator session has ended. Sign in again.');
            if (response.status === 403) throw new Error((await response.text()).trim() || 'Mailbox administration requires an administrator account.');
            throw new Error((await response.text()).trim() || 'The directory request failed.');
        }
        return response.json();
    }
    function message(text, error = false) {
        const target = el(error ? 'ma-error' : 'ma-notice');
        el('ma-error').hidden = true; el('ma-notice').hidden = true;
        target.textContent = text; target.hidden = !text;
        [['ma-account-dialog', 'ma-dialog-message'], ['ma-list-dialog', 'ma-list-message'], ['ma-class-dialog', 'ma-class-message']].forEach(([dialog, line]) => {
            if (el(dialog).open) { el(line).textContent = text; el(line).hidden = !text; }
        });
    }
    async function perform(fn) {
        if (busy) return;
        busy = true;
        const controls = Array.from(root.querySelectorAll('button, input, select, textarea'));
        const disabled = controls.map(c => c.disabled);
        controls.forEach(c => { c.disabled = true; });
        try { await fn(); } catch (error) { message(error.message, true); }
        finally { controls.forEach((c, i) => { c.disabled = disabled[i]; }); busy = false; }
    }
    function node(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
    function button(text, fn, className = 'btn btn-secondary btn-sm') { const b = node('button', text, className); b.type = 'button'; b.addEventListener('click', fn); return b; }
    function option(value, text, selectedValue) { const o = node('option', text); o.value = value; o.selected = value === selectedValue; return o; }
    function cell(row, value) { const c = node('td'); if (value instanceof Node) c.appendChild(value); else c.textContent = String(value); row.appendChild(c); }
    function quota(bytes) { if (!bytes) return 'Unlimited'; if (bytes % (1 << 30) === 0) return (bytes / (1 << 30)) + ' GiB'; if (bytes % (1 << 20) === 0) return (bytes / (1 << 20)) + ' MiB'; if (bytes % 1024 === 0) return (bytes / 1024) + ' KiB'; return bytes.toLocaleString() + ' B'; }
    function sizeText(bytes) { if (!bytes) return '0'; if (bytes % (1 << 30) === 0) return (bytes / (1 << 30)) + 'G'; if (bytes % (1 << 20) === 0) return (bytes / (1 << 20)) + 'M'; if (bytes % 1024 === 0) return (bytes / 1024) + 'K'; return String(bytes); }
    function parseQuota(raw) { const m = /^(\d+)\s*(B|K|KB|KIB|M|MB|MIB|G|GB|GIB)?$/i.exec(raw.trim()); if (!m) throw new Error('Enter a size such as 5G, or 0 for unlimited.'); const suffix = (m[2] || 'B').toUpperCase(); const n = Number(m[1]) * (suffix.startsWith('G') ? 2 ** 30 : suffix.startsWith('M') ? 2 ** 20 : suffix.startsWith('K') ? 1024 : 1); if (!Number.isSafeInteger(n) || n > 2 ** 50) throw new Error('Sizes must be no more than 1 PiB.'); return n; }
    function accountPath() { return '/accounts/' + encodeURIComponent(selected.address); }
    function isInherit(raw) { return raw.trim() === '' || raw.trim().toLowerCase() === 'inherit'; }

    // A settings editor: one field per setting, filled from and read back
    // into a mailpolicy Settings object.
    function settingsEditor(container, prefix) {
        container.replaceChildren();
        const fields = {};
        const heading = text => container.appendChild(node('h5', text));
        const add = (key, label, kind) => {
            const id = prefix + '-' + key.replace('.', '-');
            const l = node('label', label); l.htmlFor = id; container.appendChild(l);
            let input;
            if (kind === 'switch') {
                input = node('select'); input.id = id;
                [['', 'Inherit'], ['on', 'On'], ['off', 'Off']].forEach(([v, t]) => input.appendChild(option(v, t)));
            } else {
                input = node('input'); input.id = id; input.type = 'text';
                input.placeholder = kind === 'size' ? 'Inherit (e.g. 25M, 0 = unlimited)' : kind === 'days' ? 'Inherit (0 = keep forever)' : 'Inherit (0 = unlimited)';
            }
            container.appendChild(input);
            fields[key] = { input, kind };
        };
        heading('Limits'); LIMITS.forEach(([k, l, kind]) => add(k, l, kind));
        heading('Protocols'); PROTOCOLS.forEach(([k, l]) => add('protocols.' + k, l, 'switch'));
        heading('Features'); SWITCHES.forEach(([k, l]) => add(k, l, 'switch'));
        heading('Retention'); RETENTION.forEach(([k, l, kind]) => add(k, l, kind));
        return {
            fill(settings) {
                settings = settings || {};
                Object.entries(fields).forEach(([key, f]) => {
                    const v = key.startsWith('protocols.') ? (settings.protocols || {})[key.slice(10)] : settings[key];
                    if (f.kind === 'switch') f.input.value = v === undefined ? '' : v ? 'on' : 'off';
                    else if (v === undefined) f.input.value = '';
                    else f.input.value = f.kind === 'size' ? sizeText(v) : String(v);
                });
            },
            read() {
                const out = {};
                Object.entries(fields).forEach(([key, f]) => {
                    const raw = f.input.value;
                    if (f.kind === 'switch') {
                        if (raw === '') return;
                        if (key.startsWith('protocols.')) { out.protocols = out.protocols || {}; out.protocols[key.slice(10)] = raw === 'on'; } else out[key] = raw === 'on';
                    } else if (!isInherit(raw)) {
                        if (f.kind === 'size') out[key] = parseQuota(raw);
                        else { if (!/^\d+$/.test(raw.trim())) throw new Error('Enter a whole number, 0 for unlimited, or leave it blank to inherit.'); out[key] = Number(raw.trim()); }
                    }
                });
                return out;
            },
        };
    }
    const classEditor = settingsEditor(el('ma-class-settings'), 'ma-class');
    const accountEditor = settingsEditor(el('ma-policy-settings'), 'ma-policy');

    function summary(settings) {
        const parts = [];
        if (settings.quota_bytes !== undefined) parts.push('quota ' + quota(settings.quota_bytes));
        if (settings.max_attachment_bytes !== undefined) parts.push('attachments ' + quota(settings.max_attachment_bytes));
        if (settings.messages_per_hour !== undefined) parts.push((settings.messages_per_hour || 'unlimited') + '/hour');
        const off = Object.entries(settings.protocols || {}).filter(([, on]) => !on).map(([p]) => p);
        if (off.length) parts.push('no ' + off.join(', '));
        return parts.join(' · ') || 'Inherits everything';
    }

    function renderDomains() {
        const tree = el('ma-domain-tree'); tree.replaceChildren();
        const all = button('All domains', () => { domain = ''; limit = 250; renderDomains(); renderTable(); }, 'ma-domain-item');
        all.setAttribute('aria-current', String(!domain)); tree.appendChild(all);
        domains.forEach(d => {
            const b = button('', () => { domain = d.name; tab = 'accounts'; limit = 250; renderDomains(); renderTable(); }, 'ma-domain-item');
            b.appendChild(node('span', d.name)); b.appendChild(node('span', d.alias_of ? '→ ' + d.alias_of : d.accounts)); b.setAttribute('aria-current', String(domain === d.name)); tree.appendChild(b);
        });
    }
    function domainClassSelect(d) {
        const select = node('select');
        select.setAttribute('aria-label', 'Default class for ' + d.name);
        select.appendChild(option('', 'default', domainClasses[d.name] || ''));
        classes.filter(c => c.name !== 'default').forEach(c => select.appendChild(option(c.name, c.name, domainClasses[d.name] || '')));
        select.addEventListener('change', () => perform(async () => { await request('/domains/' + encodeURIComponent(d.name) + '/class', 'PUT', { class: select.value }); message('Default class for ' + d.name + ' saved.'); await refresh(); }));
        return select;
    }
    function renderTable() {
        root.querySelectorAll('[data-ma-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.maTab === tab)));
        el('ma-domain-form').hidden = tab !== 'domains' || !scope.all; el('ma-alias-domain-form').hidden = tab !== 'domains' || !mailboxAdmin || !scope.all; el('ma-status').hidden = tab !== 'accounts';
        el('ma-create').hidden = tab === 'lists' || tab === 'classes' || tab === 'audit'; el('ma-create-list').hidden = tab !== 'lists'; el('ma-create-class').hidden = tab !== 'classes';
        if (tab === 'audit') { renderAudit(); return; }
        const head = el('ma-table-head'), body = el('ma-table-body'); head.replaceChildren(); body.replaceChildren();
        const headers = {
            accounts: ['Address', 'Display name', 'Status', 'Quota', 'Aliases'],
            aliases: ['Delivery alias', 'Mailbox account'],
            lists: ['List', 'Name', 'Members', 'Who may post', 'Owner'],
            classes: ['Class', 'Description', 'Accounts', 'Domains', 'Settings'],
            domains: mailboxAdmin ? ['Domain', 'Routing', 'Accounts', 'Aliases', 'Default class', 'Catch-all', ''] : ['Domain', 'Routing', 'Accounts', 'Aliases', ''],
        }[tab];
        const heading = node('tr'); headers.forEach(label => heading.appendChild(node('th', label))); head.appendChild(heading);
        const query = el('ma-search').value.trim().toLowerCase();
        let rows = { domains, lists, classes, aliases: accounts.flatMap(a => a.aliases.map(alias => ({ alias, account: a.address }))), accounts }[tab];
        rows = rows.filter(item => {
            const address = item.address || item.alias || item.name;
            if ((tab === 'accounts' || tab === 'aliases' || tab === 'lists') && domain && !address.endsWith('@' + domain)) return false;
            if (tab === 'accounts' && el('ma-status').value && item.status !== el('ma-status').value) return false;
            return [address, item.name, item.account, item.description].filter(Boolean).some(value => value.toLowerCase().includes(query));
        });
        rows.slice(0, limit).forEach(item => {
            const row = node('tr');
            if (tab === 'accounts') {
                cell(row, button(item.address, () => openAccount(item), 'ma-account-link')); cell(row, item.name);
                cell(row, node('span', item.status, 'ma-status ' + item.status)); cell(row, quota(item.quota_bytes)); cell(row, item.aliases.length);
            } else if (tab === 'aliases') {
                cell(row, item.alias); cell(row, button(item.account, () => openAccount(accounts.find(a => a.address === item.account)), 'ma-account-link'));
            } else if (tab === 'lists') {
                cell(row, button(item.address, () => perform(async () => openList(await request('/lists/' + encodeURIComponent(item.address)))), 'ma-account-link'));
                cell(row, item.name); cell(row, item.member_count); cell(row, item.posting); cell(row, item.owner || '—');
            } else if (tab === 'classes') {
                cell(row, button(item.name, () => openClass(item), 'ma-account-link')); cell(row, item.description); cell(row, item.accounts); cell(row, item.domains); cell(row, summary(item.settings || {}));
            } else {
                cell(row, item.name); cell(row, item.alias_of ? 'Alias of ' + item.alias_of : item.configured ? 'Configured' : 'Not configured'); cell(row, item.accounts); cell(row, item.aliases);
                if (mailboxAdmin) {
                    cell(row, item.configured && !item.alias_of ? (scope.all ? domainClassSelect(item) : (domainClasses[item.name] || 'default')) : '—');
                    const catchAll = button(item.catch_all || 'Set…', () => perform(async () => {
                        const target = window.prompt('Deliver mail for unknown names at ' + item.name + ' to which address? Leave empty to stop.', item.catch_all || '');
                        if (target === null) return;
                        await request('/domains/' + encodeURIComponent(item.name) + '/catch-all', 'PUT', { address: target.trim() });
                        message(target.trim() ? 'Catch-all for ' + item.name + ' set.' : 'Catch-all for ' + item.name + ' removed.'); await refresh();
                    }), 'ma-account-link');
                    cell(row, item.configured && !item.alias_of ? catchAll : '—');
                }
                const remove = button('Remove', () => perform(async () => {
                    if (!window.confirm('Remove ' + (item.alias_of ? 'alias domain ' : 'local domain ') + item.name + '? An SMTP restart is required.')) return;
                    const result = item.alias_of ? await request('/domain-aliases', 'DELETE', { alias: item.name }) : await request('/domains', 'DELETE', { name: item.name });
                    message(result.status); await refresh();
                }));
                remove.disabled = !item.configured || item.accounts > 0 || item.aliases > 0; cell(row, scope.all ? remove : '');
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
        mailboxAdmin = !!status.mailbox_admin;
        scope = status.scope || { all: true };
        const [a, d, l, c] = await Promise.all([request('/accounts'), request('/domains'), mailboxAdmin ? request('/lists') : null, mailboxAdmin ? request('/classes') : null]);
        if (seq !== sequence) return;
        accounts = a.accounts; domains = d.domains;
        lists = l ? l.lists : []; classes = c ? c.classes : [];
        domainClasses = {}; (c ? c.domains : []).forEach(x => { domainClasses[x.domain] = x.class; });
        root.querySelectorAll('[data-ma-needs-mailbox]').forEach(b => { b.hidden = !mailboxAdmin; });
        root.querySelectorAll('[data-ma-system]').forEach(b => { b.hidden = !scope.all || !mailboxAdmin; });
        el('ma-purge').hidden = !mailboxAdmin;
        el('ma-scope').hidden = scope.all; el('ma-scope').textContent = scope.all ? '' : 'You administer ' + (scope.domains || []).join(', ') + '.';
        if (!mailboxAdmin && (tab === 'lists' || tab === 'classes' || tab === 'audit')) tab = 'accounts';
        if (!scope.all && tab === 'classes') tab = 'accounts';
        if (tab === 'audit') await loadAudit(true);
        const target = el('ma-alias-target'); target.replaceChildren();
        domains.filter(x => x.configured && !x.alias_of).forEach(x => target.appendChild(option(x.name, x.name)));
        ['ma-initial-password', 'ma-password', 'ma-confirm-password'].forEach(id => { el(id).minLength = status.min_password_length || 10; });
        renderDomains(); renderTable();
    }

    // ---- accounts ------------------------------------------------------------
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
        el('ma-open-mailbox').hidden = !editing || !mailboxAdmin || (account.status !== 'active' && account.status !== 'suspended');
        el('ma-password').value = ''; el('ma-confirm-password').value = ''; el('ma-alias').value = '';
        el('ma-dialog-message').hidden = true;
        el('ma-account-policy').hidden = !editing || !mailboxAdmin;
        el('ma-policy-overrides').hidden = !scope.all;
        const list = el('ma-alias-list'); list.replaceChildren();
        if (editing) {
            account.aliases.forEach(alias => {
                const li = node('li'); li.appendChild(node('span', alias));
                li.appendChild(button('Remove', () => perform(async () => { const updated = await request(accountPath() + '/aliases', 'DELETE', { alias }); fillAccount(updated); message('Delivery alias removed.'); await refresh(); })));
                list.appendChild(li);
            });
            if (!account.aliases.length) list.appendChild(node('li', 'No delivery aliases.'));
        }
        el('ma-forward').value = editing ? (account.forward || []).join(', ') : '';
        el('ma-keep-copy').checked = editing && !!account.forward_keep_copy;
        el('ma-send-as').value = editing ? (account.send_as || []).join(', ') : '';
        const dirClass = el('ma-directory-class');
        dirClass.hidden = !(editing && account.directory_class);
        dirClass.textContent = dirClass.hidden ? '' : 'The directory assigns this account the class of service “' + account.directory_class + '”. A class chosen above takes precedence.';
    }
    const addressList = value => value.split(/[\s,;]+/).map(v => v.trim()).filter(Boolean);
    function effectiveValue(e, key) {
        if (key.startsWith('protocols.')) return (e.protocols || {})[key.slice(10)] === false ? 'Off' : 'On';
        const v = e[key];
        if (typeof v === 'boolean') return v ? 'On' : 'Off';
        if (key.endsWith('_bytes')) return quota(v);
        if (key.endsWith('_days')) return v ? v + ' days' : 'Never';
        return v ? String(v) : 'Unlimited';
    }
    function fillPolicy(view) {
        const own = view.policy.class || '';
        const select = el('ma-policy-class'); select.replaceChildren();
        select.appendChild(option('', 'Domain default', own));
        classes.forEach(c => select.appendChild(option(c.name, c.name, own)));
        accountEditor.fill(view.policy.settings);
        const body = el('ma-effective'); body.replaceChildren();
        const e = view.effective;
        [...LIMITS.map(([k, l]) => [k, l]), ...PROTOCOLS.map(([k, l]) => ['protocols.' + k, l]), ...SWITCHES, ...RETENTION.map(([k, l]) => [k, l])].forEach(([key, label]) => {
            const row = node('tr'); cell(row, label); cell(row, effectiveValue(e, key)); cell(row, (e.source || {})[key] || 'built-in'); body.appendChild(row);
        });
        const row = node('tr'); cell(row, 'Class in effect'); cell(row, e.class); cell(row, ''); body.prepend(row);
        if (view.held || e.legal_hold) { const held = node('tr'); cell(held, 'Messages on hold'); cell(held, view.held || 0); cell(held, 'export with provision export-held'); body.appendChild(held); }
    }
    async function openAccount(account) {
        fillAccount(account); el('ma-account-dialog').showModal();
        if (account && mailboxAdmin) {
            try { fillPolicy(await request(accountPath() + '/policy')); } catch (error) { message(error.message, true); }
        }
    }
    window.refreshMailAdmin = function () { refresh().catch(error => message(error.message, true)); };
    el('ma-create').addEventListener('click', () => openAccount(null));
    el('ma-close').addEventListener('click', () => { if (!busy) el('ma-account-dialog').close(); });
    ['ma-account-dialog', 'ma-list-dialog', 'ma-class-dialog'].forEach(id => el(id).addEventListener('cancel', event => { if (busy) event.preventDefault(); }));
    el('ma-refresh').addEventListener('click', window.refreshMailAdmin);
    el('ma-open-mailbox').addEventListener('click', () => {
        if (busy || !selected) return;
        const account = selected.address;
        const tab = window.open('about:blank', '_blank');
        if (!tab) { message('Allow pop-ups for this dashboard to open a mailbox.', true); return; }
        tab.opener = null;
        tab.name = 'elemta-mailbox-' + Math.random().toString(36).slice(2);
        perform(async () => {
            try {
                const access = await request('/accounts/' + encodeURIComponent(account) + '/access', 'POST');
                const form = document.createElement('form');
                form.method = 'POST'; form.action = access.webmail_url + '/login/admin'; form.target = tab.name;
                for (const [name, value] of Object.entries({ user: access.address, token: access.token })) {
                    const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.appendChild(input);
                }
                document.body.appendChild(form);
                try { form.submit(); } finally { form.remove(); }
                message('Opened ' + account + ' in webmail. Access expires in one hour.');
            } catch (error) { tab.close(); throw error; }
        });
    });
    ['ma-search', 'ma-status'].forEach(id => el(id).addEventListener('input', () => { limit = 250; renderTable(); }));
    el('ma-more').addEventListener('click', () => { if (tab === 'audit') { perform(() => loadAudit(false)); return; } limit += 250; renderTable(); });
    root.querySelectorAll('[data-ma-tab]').forEach(b => b.addEventListener('click', () => {
        tab = b.dataset.maTab; limit = 250;
        if (tab === 'audit') perform(() => loadAudit(true)); else renderTable();
    }));
    el('ma-account-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const payload = { name: el('ma-name').value, quota_bytes: parseQuota(el('ma-quota').value) };
        if (selected) payload.status = el('ma-account-status').value;
        else { payload.address = el('ma-address').value; payload.password = el('ma-initial-password').value; }
        const updated = await request(selected ? accountPath() : '/accounts', selected ? 'PATCH' : 'POST', payload);
        fillAccount(updated); message('Account saved.'); await refresh();
        if (mailboxAdmin) fillPolicy(await request(accountPath() + '/policy'));
    }); });
    el('ma-policy-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const view = await request(accountPath() + '/policy', 'PUT', { class: el('ma-policy-class').value, settings: accountEditor.read() });
        fillPolicy(view); message('Class of service saved. Mail apps pick it up when they next sign in.'); await refresh();
    }); });
    el('ma-mail-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const updated = await request(accountPath(), 'PATCH', { forward: addressList(el('ma-forward').value), forward_keep_copy: el('ma-keep-copy').checked, send_as: addressList(el('ma-send-as').value) });
        fillAccount(updated); message('Forwarding and sending saved.'); await refresh();
    }); });
    el('ma-alias-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => { const updated = await request(accountPath() + '/aliases', 'POST', { alias: el('ma-alias').value }); fillAccount(updated); el('ma-account-policy').hidden = !mailboxAdmin; message('Delivery alias added.'); await refresh(); }); });
    el('ma-password-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        if (el('ma-password').value !== el('ma-confirm-password').value) throw new Error('The new passwords do not match.');
        const result = await request(accountPath() + '/password', 'POST', { password: el('ma-password').value }); el('ma-password').value = ''; el('ma-confirm-password').value = ''; message(result.status);
    }); });
    el('ma-delete').addEventListener('click', () => perform(async () => {
        const address = selected.address;
        if (window.prompt('Delete this account? Type ' + address + ' to confirm:') !== address) return;
        const purge = mailboxAdmin && window.confirm('Also permanently remove its mail, folders, filters and settings?\n\nOK purges the mailbox. Cancel keeps it, so the account could be recreated with its mail.');
        const result = await request(accountPath(), 'DELETE', { confirm: address, purge }); selected = null; el('ma-account-dialog').close(); message(result.status); await refresh();
    }));
    el('ma-purge').addEventListener('click', () => perform(async () => {
        const address = (window.prompt('Purge the mailbox of an account that has already been deleted. This permanently removes its mail.\n\nAccount address:') || '').trim();
        if (!address) return;
        if (window.prompt('Type ' + address + ' again to purge its mailbox:') !== address) return;
        const result = await request('/purge', 'POST', { address, confirm: address });
        message('Purged ' + result.address + ': ' + result.messages + ' messages in ' + result.folders + ' folders.');
    }));
    el('ma-domain-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => { const result = await request('/domains', 'POST', { name: el('ma-new-domain').value }); el('ma-new-domain').value = ''; message(result.status); await refresh(); }); });
    el('ma-alias-domain-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const result = await request('/domain-aliases', 'POST', { alias: el('ma-alias-domain').value, target: el('ma-alias-target').value });
        el('ma-alias-domain').value = ''; message(result.status); await refresh();
    }); });

    // ---- audit log -----------------------------------------------------------
    // Newest first, a page at a time; "Show more" fetches older entries. The
    // server limits a domain administrator to their domains' entries.
    async function loadAudit(fresh) {
        const before = fresh || !audit.length ? '' : '&before=' + audit[audit.length - 1].id;
        const page = (await request('/audit?limit=200' + before)).entries;
        audit = fresh ? page : audit.concat(page);
        auditDone = page.length < 200;
        renderTable();
    }
    function renderAudit() {
        const head = el('ma-table-head'), body = el('ma-table-body'); head.replaceChildren(); body.replaceChildren();
        const headers = ['When', 'Who', 'Action', 'Target', 'Detail', 'From'];
        const heading = node('tr'); headers.forEach(label => heading.appendChild(node('th', label))); head.appendChild(heading);
        const query = el('ma-search').value.trim().toLowerCase();
        const rows = audit.filter(e => !query || [e.actor, e.action, e.target, e.detail].some(v => (v || '').toLowerCase().includes(query)));
        rows.forEach(e => {
            const row = node('tr');
            const when = node('time', new Date(e.at).toLocaleString()); when.dateTime = e.at;
            cell(row, when); cell(row, e.actor); cell(row, e.action); cell(row, e.target); cell(row, e.detail || '');
            cell(row, [e.source, e.client].filter(Boolean).join(' · '));
            body.appendChild(row);
        });
        if (!rows.length) { const row = node('tr'), c = node('td', audit.length ? 'No matching entries.' : 'No changes recorded yet.'); c.colSpan = headers.length; row.appendChild(c); body.appendChild(row); }
        el('ma-count').textContent = 'Showing ' + rows.length + ' of ' + audit.length + ' loaded entries';
        el('ma-more').hidden = auditDone;
    }

    // ---- distribution lists --------------------------------------------------
    function openList(list) {
        selectedList = list || null;
        const editing = !!list;
        el('ma-list-title').textContent = editing ? list.address : 'Create list';
        el('ma-list-address').value = editing ? list.address : ''; el('ma-list-address').readOnly = editing;
        el('ma-list-name').value = editing ? list.name : '';
        el('ma-list-description').value = editing ? list.description : '';
        el('ma-list-owner').value = editing ? (list.owner || '') : '';
        el('ma-list-posting').value = editing ? list.posting : 'anyone';
        el('ma-list-members').value = editing ? list.members.join('\n') : '';
        el('ma-list-delete').hidden = !editing;
        el('ma-list-message').hidden = true;
        if (!el('ma-list-dialog').open) el('ma-list-dialog').showModal();
    }
    el('ma-create-list').addEventListener('click', () => openList(null));
    el('ma-list-close').addEventListener('click', () => { if (!busy) el('ma-list-dialog').close(); });
    el('ma-list-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const payload = {
            address: el('ma-list-address').value.trim(), name: el('ma-list-name').value, description: el('ma-list-description').value,
            owner: el('ma-list-owner').value.trim(), posting: el('ma-list-posting').value,
            members: el('ma-list-members').value.split(/[\s,;]+/).map(m => m.trim()).filter(Boolean),
        };
        const saved = selectedList ? await request('/lists/' + encodeURIComponent(selectedList.address), 'PUT', payload) : await request('/lists', 'POST', payload);
        openList(saved); message('List saved with ' + saved.members.length + ' members.'); await refresh();
    }); });
    el('ma-list-delete').addEventListener('click', () => perform(async () => {
        if (!window.confirm('Delete the list ' + selectedList.address + '? Mail to it will be refused.')) return;
        const result = await request('/lists/' + encodeURIComponent(selectedList.address), 'DELETE'); el('ma-list-dialog').close(); message(result.status); await refresh();
    }));

    // ---- classes of service --------------------------------------------------
    function openClass(c) {
        selectedClass = c || null;
        const editing = !!c;
        el('ma-class-title').textContent = editing ? c.name : 'New class of service';
        el('ma-class-name').value = editing ? c.name : ''; el('ma-class-name').readOnly = editing;
        el('ma-class-description').value = editing ? c.description : '';
        classEditor.fill(editing ? c.settings : {});
        el('ma-class-delete').hidden = !editing || c.name === 'default';
        el('ma-class-message').hidden = true;
        if (!el('ma-class-dialog').open) el('ma-class-dialog').showModal();
    }
    el('ma-create-class').addEventListener('click', () => openClass(null));
    el('ma-class-close').addEventListener('click', () => { if (!busy) el('ma-class-dialog').close(); });
    el('ma-class-form').addEventListener('submit', event => { event.preventDefault(); perform(async () => {
        const name = el('ma-class-name').value.trim();
        const saved = await request('/classes/' + encodeURIComponent(name), 'PUT', { name, description: el('ma-class-description').value, settings: classEditor.read() });
        openClass(saved); message('Class ' + saved.name + ' saved. It applies at each account\'s next sign-in or delivery, and to sending within a minute.'); await refresh();
    }); });
    el('ma-class-delete').addEventListener('click', () => perform(async () => {
        if (!window.confirm('Delete the class ' + selectedClass.name + '?')) return;
        const result = await request('/classes/' + encodeURIComponent(selectedClass.name), 'DELETE'); el('ma-class-dialog').close(); message(result.status); await refresh();
    }));
}());
