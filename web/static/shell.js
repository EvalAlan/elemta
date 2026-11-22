// The console's frame: which pages exist, who sees them, where they are in
// the sidebar and the address, and how to jump to one. Pages load their own
// data (loadPage in app.js); this only decides what is on screen.
//
// An address is #/page or #/page/section, so a reload, the Back button and a
// pasted link all land in the same place.
const shell = (function () {
    'use strict';

    const can = {
        any: () => true,
        // Without sign-in configured the console is open, as the API is.
        read: a => !a.isLoggedIn || has(a, 'api:read'),
        queue: a => !a.isLoggedIn || has(a, 'queue:manage'),
        configure: a => !a.isLoggedIn || has(a, 'system:config'),
        admin: a => !a.isLoggedIn || has(a, 'system:admin'),
        signedIn: a => a.isLoggedIn,
        mail: a => a.isLoggedIn && (has(a, 'system:admin') || has(a, 'mail:domain-admin')),
        compliance: a => a.isLoggedIn && has(a, 'mail:compliance'),
        protect: a => a.isLoggedIn && has(a, 'system:config'),
        users: a => a.isLoggedIn && has(a, 'user:view'),
    };
    function has(auth, permission) { return (auth.permissions || []).includes(permission); }

    const PAGES = {
        dashboard: { title: 'Dashboard', see: can.read, words: 'home overview status attention' },
        reports: {
            title: 'Reports', see: a => can.read(a) || can.mail(a),
            sections: {
                delivery: { title: 'Delivery', see: can.read, words: 'statistics errors trends' },
                senders: { title: 'Senders & destinations', see: can.read, words: 'reputation pool domains providers' },
                dmarc: { title: 'DMARC', see: can.mail, words: 'spf dkim forgery alignment rua' },
                abuse: { title: 'Abuse', see: can.protect, plugin: 'abuse', words: 'blocked attacks sign-ins holds firewall unblock' },
            },
        },
        'mail-admin': { title: 'Accounts & domains', see: can.mail, words: 'mailboxes aliases lists classes audit dkim password quota' },
        queues: { title: 'Queues', see: can.read, words: 'deferred failed hold retry messages' },
        campaigns: { title: 'Mass Mailer', see: can.read, plugin: 'mass_mailer', words: 'campaigns bulk suppression' },
        tracing: { title: 'Message trace', see: can.read, words: 'find track where is message' },
        logs: { title: 'Logs', see: can.read, words: 'errors events search' },
        compliance: { title: 'Compliance', see: can.compliance, words: 'legal hold export investigation' },
        health: { title: 'Health', see: can.read, words: 'backups dns memory uptime version' },
        certificates: { title: 'Certificates', see: can.read, words: 'tls ssl lets encrypt' },
        settings: {
            title: 'Settings', see: can.any,
            sections: {
                ui: { title: 'Preferences', see: can.any, words: 'theme refresh appearance' },
                account: { title: 'Password & two-step', see: can.signedIn, words: 'passkey authenticator security' },
                server: { title: 'Mail server', see: can.configure, words: 'hostname size limit retention' },
                notifications: { title: 'Alert emails', see: can.protect, words: 'notifications alerts' },
                users: { title: 'Console users', see: can.users, words: 'roles administrators' },
                plugins: { title: 'Plugins', see: can.configure, words: 'enable disable' },
                system: { title: 'Maintenance', see: can.admin, words: 'restart about version' },
            },
        },
    };
    // Sections that used to be pages of their own.
    const MOVED = { abuse: ['reports', 'abuse'], dmarc: ['reports', 'dmarc'] };

    let auth = { isLoggedIn: false, permissions: [] };
    let plugins = null; // until the first answer
    let ready = false;
    let page = '', section = '';
    const lastSection = {};

    function pluginOn(name) { return plugins !== null && plugins.some(p => p.name === name && p.enabled); }

    function pageVisible(name) {
        const p = PAGES[name];
        return !!p && p.see(auth) && (!p.plugin || pluginOn(p.plugin));
    }
    function sectionVisible(pageName, name) {
        const p = PAGES[pageName];
        if (!p || !p.sections) return false;
        // A plugin's settings tab is made from the plugin list (app.js).
        if (pageName === 'settings' && name.startsWith('plugin-')) {
            return can.configure(auth) && !!document.querySelector(`.settings-tab[data-tab="${CSS.escape(name)}"]`);
        }
        const s = p.sections[name];
        return !!s && s.see(auth) && (!s.plugin || pluginOn(s.plugin));
    }
    function firstSection(pageName) {
        const wanted = lastSection[pageName];
        if (wanted && sectionVisible(pageName, wanted)) return wanted;
        return Object.keys(PAGES[pageName].sections).find(s => sectionVisible(pageName, s)) || '';
    }
    function home() { return ['dashboard', 'mail-admin', 'compliance', 'settings'].find(pageVisible) || 'settings'; }

    function resolve(wantPage, wantSection) {
        let p = wantPage, s = wantSection || '';
        if (Object.hasOwn(MOVED, p)) [p, s] = MOVED[p];
        if (!Object.hasOwn(PAGES, p) || !pageVisible(p)) return [home(), ''];
        if (!PAGES[p].sections) return [p, ''];
        return [p, s && sectionVisible(p, s) ? s : firstSection(p)];
    }

    function parse() {
        const parts = location.hash.replace(/^#\/?/, '').split('/');
        return [parts[0] || '', parts[1] || ''];
    }
    function address(p, s) { return '#/' + p + (s ? '/' + s : ''); }

    function show(wantPage, wantSection, history = 'push') {
        const [p, s] = resolve(wantPage, wantSection);
        const moved = p !== page || s !== section;
        page = p; section = s;
        if (s) lastSection[p] = s;

        document.querySelectorAll('.nav-item[data-view]').forEach(item => {
            const here = item.dataset.view === p;
            item.classList.toggle('active', here);
            if (here) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
        });
        document.querySelectorAll('.view').forEach(view => view.classList.toggle('active', view.id === 'view-' + p));
        document.querySelectorAll('.section-tab').forEach(tab => {
            const here = p === 'reports' && tab.dataset.section === s;
            tab.classList.toggle('active', here);
            if (here) tab.setAttribute('aria-current', 'page'); else tab.removeAttribute('aria-current');
        });
        document.querySelectorAll('.report-panel').forEach(panel => panel.classList.toggle('active', p === 'reports' && panel.dataset.section === s));
        if (p === 'settings') {
            document.querySelectorAll('.settings-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === s));
            document.querySelectorAll('.settings-panel').forEach(panel => panel.classList.toggle('active', panel.id === 'settings-' + s));
            fillSettingsPicker();
        }

        const title = PAGES[p].title, sub = sectionTitle(p, s);
        document.getElementById('page-title').textContent = title;
        document.getElementById('page-section').textContent = sub;
        document.title = (sub ? sub + ' · ' : '') + title + ' · Elemta';
        closeMenu();

        if (history !== 'none' && location.hash !== address(p, s)) {
            const url = location.pathname + location.search + address(p, s);
            if (history === 'replace') window.history.replaceState(null, '', url); else window.history.pushState(null, '', url);
        }
        if (moved) {
            document.getElementById('view-' + p).scrollTop = 0;
            // On a phone the row of sections scrolls; keep the open one in it.
            const tab = document.querySelector('.section-tab.active');
            if (tab) tab.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        }
        loadPage(p, s);
    }

    function sectionTitle(p, s) {
        if (!s) return '';
        const known = PAGES[p].sections[s];
        if (known) return known.title;
        const tab = document.querySelector(`.settings-tab[data-tab="${CSS.escape(s)}"]`);
        return tab ? tab.textContent : '';
    }

    // Everything that depends on who this is and which plugins are on.
    function apply() {
        document.querySelectorAll('.nav-item[data-view]').forEach(item => { item.hidden = !pageVisible(item.dataset.view); });
        document.querySelectorAll('.nav-group').forEach(group => { group.hidden = !group.querySelector('.nav-item:not([hidden])'); });
        document.querySelectorAll('.section-tab').forEach(tab => { tab.hidden = !sectionVisible('reports', tab.dataset.section); });
        document.querySelectorAll('.settings-tab[data-tab]').forEach(tab => { tab.hidden = !sectionVisible('settings', tab.dataset.tab); });
        document.querySelectorAll('.settings-group').forEach(group => { group.hidden = !group.querySelector('.settings-tab:not([hidden])'); });
        document.querySelectorAll('[data-needs]').forEach(el => { el.hidden = !can[el.dataset.needs](auth); });
        fillSettingsPicker();
    }

    function setAuth(next) {
        auth = { isLoggedIn: !!next.isLoggedIn, permissions: next.permissions || [] };
        apply();
    }
    function setPlugins(list) {
        plugins = list || [];
        apply();
        if (!ready) return;
        // The page someone stands on may just have been switched off, and a
        // plugin's settings asked for by address exist only from now.
        const [wantPage, wantSection] = parse();
        if (wantPage === 'settings' && wantSection.startsWith('plugin-') && section !== wantSection && sectionVisible('settings', wantSection)) {
            show(wantPage, wantSection, 'none');
        } else if (page && (!pageVisible(page) || section && !sectionVisible(page, section))) {
            show(page === 'settings' ? 'settings' : pageVisible(page) ? page : home(), page === 'settings' ? 'plugins' : '', 'replace');
        }
    }

    // ---- menu --------------------------------------------------------------
    function openMenu() {
        document.getElementById('sidebar').classList.add('open');
        document.getElementById('sidebar-scrim').hidden = false;
        document.getElementById('mobile-menu-toggle').setAttribute('aria-expanded', 'true');
    }
    function closeMenu() {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebar-scrim').hidden = true;
        document.getElementById('mobile-menu-toggle').setAttribute('aria-expanded', 'false');
    }

    // On a phone the settings list becomes one select.
    function fillSettingsPicker() {
        const picker = document.getElementById('settings-picker');
        if (!picker) return;
        picker.replaceChildren();
        document.querySelectorAll('.settings-group').forEach(group => {
            const tabs = [...group.querySelectorAll('.settings-tab:not([hidden])')];
            if (!tabs.length) return;
            const set = document.createElement('optgroup');
            set.label = group.dataset.label;
            tabs.forEach(tab => {
                const option = document.createElement('option');
                option.value = tab.dataset.tab;
                option.textContent = tab.textContent;
                option.selected = tab.dataset.tab === section;
                set.appendChild(option);
            });
            picker.appendChild(set);
        });
    }

    // ---- jump to -----------------------------------------------------------
    let choices = [], found = [], picked = 0, jumpOpenings = 0;

    function pageChoices() {
        const out = [];
        for (const [name, p] of Object.entries(PAGES)) {
            if (!pageVisible(name)) continue;
            if (!p.sections) { out.push({ label: p.title, kind: 'Page', words: p.words, go: () => show(name) }); continue; }
            for (const [key, s] of Object.entries(p.sections)) {
                if (sectionVisible(name, key)) out.push({ label: s.title, kind: p.title, words: s.words + ' ' + p.title, go: () => show(name, key) });
            }
        }
        document.querySelectorAll('.settings-tab[data-plugin-tab]:not([hidden])').forEach(tab => {
            out.push({ label: tab.textContent, kind: 'Plugin settings', words: tab.dataset.pluginTab, go: () => show('settings', tab.dataset.tab) });
        });
        return out;
    }

    async function openJump() {
        const dialog = document.getElementById('jump');
        if (dialog.open || document.querySelector('dialog[open]')) return;
        const opening = ++jumpOpenings, input = document.getElementById('jump-input');
        choices = pageChoices();
        input.value = '';
        dialog.showModal();
        input.focus();
        renderJump();
        if (!can.mail(auth)) return;
        try {
            const response = await fetch('/api/provision/accounts');
            if (!response.ok || opening !== jumpOpenings) return;
            for (const account of (await response.json()).accounts || []) {
                choices.push({
                    label: account.address, kind: 'Account', words: account.name || '', searchOnly: true,
                    go: () => {
                        show('mail-admin');
                        document.querySelector('[data-ma-tab="accounts"]').click();
                        const search = document.getElementById('ma-search');
                        search.value = account.address;
                        search.dispatchEvent(new Event('input', { bubbles: true }));
                    },
                });
            }
            renderJump();
        } catch (error) {
            // The pages are still listed; accounts are the extra.
            console.error('Jump list: accounts unavailable:', error);
        }
    }

    function renderJump() {
        const query = document.getElementById('jump-input').value.trim().toLowerCase();
        const terms = query.split(/\s+/).filter(Boolean);
        found = choices.filter(c => {
            if (!terms.length) return !c.searchOnly;
            const text = (c.label + ' ' + c.words).toLowerCase();
            return terms.every(term => text.includes(term));
        });
        found.sort((a, b) => Number(!a.label.toLowerCase().startsWith(query)) - Number(!b.label.toLowerCase().startsWith(query)));
        if (query && can.read(auth)) {
            found = found.slice(0, 11);
            found.push({
                label: 'Trace "' + query + '"', kind: 'Message trace',
                go: () => {
                    show('tracing');
                    document.getElementById('trace-query').value = query;
                    searchMessages();
                },
            });
        }
        picked = Math.min(picked, Math.max(0, found.length - 1));
        const list = document.getElementById('jump-list');
        list.replaceChildren();
        found.slice(0, 24).forEach((choice, i) => {
            const row = document.createElement('li');
            row.id = 'jump-choice-' + i;
            row.setAttribute('role', 'option');
            row.setAttribute('aria-selected', String(i === picked));
            const label = document.createElement('span'), kind = document.createElement('small');
            label.textContent = choice.label;
            kind.textContent = choice.kind;
            row.append(label, kind);
            row.addEventListener('click', () => choose(i));
            list.appendChild(row);
        });
        if (!found.length) {
            const row = document.createElement('li');
            row.className = 'jump-none';
            row.textContent = 'Nothing matches.';
            list.appendChild(row);
        }
        document.getElementById('jump-input').setAttribute('aria-activedescendant', found.length ? 'jump-choice-' + picked : '');
    }

    function choose(i) {
        const choice = found[i];
        document.getElementById('jump').close();
        if (choice) choice.go();
    }

    function initialize() {
        document.querySelectorAll('.nav-item[data-view]').forEach(item => item.addEventListener('click', event => {
            if (event.metaKey || event.ctrlKey || event.shiftKey) return; // a new tab, by the link's address
            event.preventDefault();
            show(item.dataset.view);
        }));
        document.querySelectorAll('[data-go]').forEach(item => item.addEventListener('click', event => {
            event.preventDefault();
            const [p, s] = item.dataset.go.split('/');
            show(p, s);
        }));
        document.querySelectorAll('.section-tab').forEach(tab => tab.addEventListener('click', () => show('reports', tab.dataset.section)));
        document.getElementById('settings-nav').addEventListener('click', event => {
            const tab = event.target.closest('.settings-tab[data-tab]');
            if (tab) show('settings', tab.dataset.tab);
        });
        document.getElementById('settings-picker').addEventListener('change', event => show('settings', event.target.value));
        document.getElementById('mobile-menu-toggle').addEventListener('click', openMenu);
        document.getElementById('sidebar-scrim').addEventListener('click', closeMenu);

        const sidebar = document.getElementById('sidebar'), collapse = document.getElementById('sidebar-toggle');
        const setCollapsed = on => {
            sidebar.classList.toggle('collapsed', on);
            collapse.setAttribute('aria-expanded', String(!on));
        };
        setCollapsed(localStorage.getItem('elemta-sidebar') === 'collapsed');
        collapse.addEventListener('click', () => {
            if (sidebar.classList.contains('open')) { closeMenu(); return; }
            const on = !sidebar.classList.contains('collapsed');
            setCollapsed(on);
            localStorage.setItem('elemta-sidebar', on ? 'collapsed' : 'open');
        });

        // Back, Forward and an edited address; show() itself doesn't raise these.
        const follow = () => {
            if (!ready) return;
            const [p, s] = parse();
            if (p !== page || s !== section) show(p || home(), s, 'replace');
        };
        window.addEventListener('popstate', follow);
        window.addEventListener('hashchange', follow);

        const input = document.getElementById('jump-input');
        document.getElementById('jump-open').addEventListener('click', openJump);
        document.getElementById('jump').addEventListener('click', event => { if (event.target.id === 'jump') event.target.close(); });
        input.addEventListener('input', () => { picked = 0; renderJump(); });
        input.addEventListener('keydown', event => {
            const last = Math.min(found.length, 24) - 1;
            if (event.key === 'ArrowDown') picked = Math.min(last, picked + 1);
            else if (event.key === 'ArrowUp') picked = Math.max(0, picked - 1);
            else if (event.key === 'Enter') { event.preventDefault(); choose(picked); return; }
            else return;
            event.preventDefault();
            renderJump();
            document.getElementById('jump-choice-' + picked)?.scrollIntoView({ block: 'nearest' });
        });
        document.addEventListener('keydown', event => {
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && !event.target.closest?.('[contenteditable]')) {
                event.preventDefault();
                openJump();
            } else if (event.key === 'Escape') {
                closeMenu();
            }
        });
    }

    async function start() {
        if (can.read(auth)) {
            try {
                const response = await fetch('/api/config/plugins');
                if (response.ok) setPlugins((await response.json()).plugins);
            } catch (error) {
                console.error('Plugin list unavailable:', error);
            }
        }
        apply();
        const [p, s] = parse();
        // Someone may have clicked while this was loading.
        ready = true;
        if (page) show(page, section, 'replace'); else show(p || home(), s, 'replace');
    }

    return {
        initialize, start, show, setAuth, setPlugins, refresh: apply,
        allowed: name => can[name](auth),
        pluginOn,
        is: (p, s) => page === p && (!s || section === s),
    };
})();

function switchView(page, section) { shell.show(page, section); }
function switchSettingsTab(tab) { shell.show('settings', tab); }
