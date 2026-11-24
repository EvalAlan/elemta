// Settings > Log shipping. The saved credential never comes back from the
// server, and what the destination said is shown only through textContent.
(function () {
    'use strict';
    const el = id => document.getElementById(id);
    const VARIABLE = 'ELEMTA_LOG_SHIP_DESTINATIONS';
    let timer = null, savedOrigin = '', credentialSet = false;

    async function call(path, method = 'GET', body) {
        const options = { method };
        if (body) {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(body);
        }
        const response = await fetch('/api/log-shipping' + path, options);
        if (!response.ok) throw new Error((await response.text()).trim() || 'HTTP ' + response.status);
        return response.json();
    }
    function origin(text) {
        try { return new URL(text.trim()).origin; } catch { return ''; }
    }

    function syncFields() {
        const url = el('logship-url').value, auth = el('logship-auth');
        const keep = auth.querySelector('[value="keep"]');
        // A saved credential is only ever sent where it was given for.
        keep.hidden = keep.disabled = !credentialSet || origin(url) !== savedOrigin;
        if (keep.disabled && auth.value === 'keep') auth.value = 'none';
        el('logship-key-field').hidden = auth.value !== 'key';
        el('logship-user-field').hidden = el('logship-password-field').hidden = auth.value !== 'basic';
        el('logship-plain').hidden = !/^\s*http:/i.test(url);
        el('logship-test').disabled = !url;
        // Logstash installs its own template from a file, so the policy would go nowhere.
        el('logship-policy-field').hidden = el('logship-policy-hint').hidden = el('logship-kind').value !== 'elasticsearch';
    }

    function fillDestinations(allowed, saved) {
        const select = el('logship-url');
        select.replaceChildren(new Option(allowed.length ? 'Choose one' : 'None allowed yet', ''));
        allowed.forEach(url => select.add(new Option(url, url)));
        if (saved && !allowed.includes(saved)) select.add(new Option(saved + ' (not allowed)', saved));
        select.value = saved;
        el('logship-allowed').textContent = allowed.length
            ? 'To allow another, add it to ' + VARIABLE + " in the admin console's environment and restart it."
            : "The server's operator lists where logs may go: set " + VARIABLE + " in the admin console's environment, for example https://elasticsearch.example.com:9200, and restart it.";
    }

    function fillStatus(data) {
        const s = data.status, on = data.settings.enabled;
        let state = 'Off', detail = '';
        if (!s.available) {
            state = 'Unavailable';
            detail = "Valkey carries the logs from each service, and it isn't answering or isn't configured.";
        } else if (on && s.last_error) {
            state = 'Failing';
            detail = s.last_error;
        } else if (on) {
            state = s.last_success ? 'Working' : 'Starting';
            if (s.last_success) detail = 'Last sent ' + new Date(s.last_success).toLocaleString() + '.';
        }
        if (s.reject_reason) detail += ' Last refusal: ' + s.reject_reason;
        el('logship-state').textContent = state;
        el('logship-detail').textContent = detail;
        const count = value => s.available ? Number(value).toLocaleString() : '—';
        el('logship-sent').textContent = count(s.sent);
        el('logship-waiting').textContent = count(s.waiting);
        el('logship-lost').textContent = count(s.dropped + s.rejected);
    }

    function fillForm(data) {
        const s = data.settings;
        el('logship-enabled').checked = s.enabled;
        el('logship-kind').value = s.kind;
        fillDestinations(data.destinations, s.url);
        el('logship-index').value = s.index;
        el('logship-policy').value = s.lifecycle_policy || '';
        el('logship-level').value = s.min_level;
        el('logship-subjects').checked = s.include_subjects;
        savedOrigin = origin(s.url);
        credentialSet = data.status.credential_set;
        ['logship-key', 'logship-user', 'logship-password'].forEach(id => { el(id).value = ''; });
        el('logship-auth').value = credentialSet ? 'keep' : 'none';
        syncFields();
    }

    function request() {
        const body = {
            settings: {
                enabled: el('logship-enabled').checked,
                kind: el('logship-kind').value,
                url: el('logship-url').value.trim(),
                index: el('logship-index').value.trim(),
                lifecycle_policy: el('logship-policy').value.trim(),
                min_level: el('logship-level').value,
                include_subjects: el('logship-subjects').checked,
            },
        };
        const auth = el('logship-auth').value;
        if (auth === 'none') body.credential = {};
        if (auth === 'key') body.credential = { api_key: el('logship-key').value.trim() };
        if (auth === 'basic') body.credential = { username: el('logship-user').value.trim(), password: el('logship-password').value };
        return body;
    }

    function watch() {
        clearTimeout(timer);
        timer = setTimeout(async () => {
            if (!shell.is('settings', 'plugin-log_shipping')) return;
            // Only the figures: a refresh mustn't wipe what is being typed.
            try { fillStatus(await call('')); } catch (error) { el('logship-detail').textContent = error.message; }
            watch();
        }, 5000);
    }

    window.refreshLogShipping = async function () {
        el('logship-result').textContent = '';
        try {
            const data = await call('');
            fillForm(data);
            fillStatus(data);
        } catch (error) {
            el('logship-detail').textContent = error.message;
        }
        watch();
    };

    document.addEventListener('DOMContentLoaded', () => {
        const form = el('logship-form'), result = el('logship-result'), test = el('logship-test');
        form.addEventListener('input', syncFields);
        form.addEventListener('change', syncFields);
        form.addEventListener('submit', async event => {
            event.preventDefault();
            result.textContent = 'Saving…';
            try {
                const saved = await call('', 'PUT', request());
                const data = await call('');
                fillForm(data);
                fillStatus(data);
                result.textContent = saved.message + '.';
                refreshPlugins();
            } catch (error) {
                result.textContent = error.message;
            }
        });
        test.addEventListener('click', async () => {
            test.disabled = true;
            result.textContent = 'Sending…';
            try {
                await call('/test', 'POST', request());
                result.textContent = 'The destination took a test line. Nothing is saved until you press Save.';
            } catch (error) {
                result.textContent = error.message;
            }
            syncFields();
        });
    });
})();
