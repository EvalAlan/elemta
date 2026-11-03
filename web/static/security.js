// Two-step sign-in for the signed-in console user (internal/api/mfa.go):
// an authenticator app with recovery codes, and passkeys.
(function () {
    'use strict';
    const card = document.getElementById('tf-card');
    if (!card) return;
    const el = id => document.getElementById(id);
    const supported = !!(window.PublicKeyCredential && window.isSecureContext);

    // WebAuthn wants binary where the server sends base64url.
    const toBytes = s => {
        const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
        const out = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
        return out.buffer;
    };
    const toText = buf => {
        const bytes = new Uint8Array(buf);
        let b = '';
        for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
        return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    function notice(text, error = false) {
        const line = el('tf-notice');
        line.textContent = text; line.hidden = !text;
        line.classList.toggle('abuse-error', error);
    }

    async function call(path, body) {
        const options = { method: body === undefined ? 'GET' : 'POST', headers: { Accept: 'application/json' } };
        if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await fetch('/auth/security' + path, options);
        if (!response.ok) throw new Error((await response.text()).trim() || 'The request failed.');
        return response.json();
    }

    function password() {
        const value = el('tf-password').value;
        if (!value) {
            el('tf-password').focus();
            throw new Error('Enter your password first.');
        }
        return value;
    }

    function when(value) { return value ? new Date(value).toLocaleString() : 'Never'; }

    function show(st) {
        card.hidden = false;
        el('tf-totp-state').textContent = st.totp
            ? `On. ${st.recovery_left} recovery code${st.recovery_left === 1 ? '' : 's'} left.`
            : 'Off.';
        el('tf-totp-on').hidden = st.totp;
        el('tf-totp-off').hidden = !st.totp;
        el('tf-totp-codes').hidden = !st.totp;
        const body = el('tf-passkeys');
        body.replaceChildren();
        if (!st.passkeys.length) {
            const row = document.createElement('tr'), td = document.createElement('td');
            td.colSpan = 5; td.textContent = 'No passkeys yet.';
            row.appendChild(td); body.appendChild(row);
        }
        for (const p of st.passkeys) {
            const row = document.createElement('tr');
            for (const value of [p.name, p.host, when(p.created), when(p.last_used)]) {
                const td = document.createElement('td');
                td.textContent = value;
                row.appendChild(td);
            }
            const td = document.createElement('td'), remove = document.createElement('button');
            remove.className = 'btn btn-danger btn-sm'; remove.type = 'button'; remove.textContent = 'Remove';
            remove.addEventListener('click', () => removePasskey(p));
            td.appendChild(remove); row.appendChild(td); body.appendChild(row);
        }
        el('tf-passkey-form').hidden = !supported;
        el('tf-passkey-unsupported').hidden = supported;
    }

    async function refresh() {
        try {
            show(await call(''));
        } catch (error) {
            // Not available (no users file) or not a console session.
            card.hidden = true;
        }
    }
    window.refreshTwoFactor = refresh;

    // After a change, the users list's Two-step column too; it refreshes
    // this card as it goes.
    async function reload() {
        if (typeof refreshUsers === 'function') await refreshUsers();
        else await refresh();
    }

    function act(button, fn) {
        el(button).addEventListener('click', async () => {
            el(button).disabled = true;
            notice('');
            try {
                await fn();
            } catch (error) {
                if (error && error.name === 'NotAllowedError') notice('');
                else if (error && error.name === 'InvalidStateError') notice('This device already has a passkey for you.', true);
                else notice(error.message || 'Something went wrong.', true);
            } finally {
                el(button).disabled = false;
            }
        });
    }

    function showCodes(codes) {
        el('tf-codes-list').textContent = codes.join('\n');
        el('tf-codes').hidden = false;
    }

    act('tf-totp-on', async () => {
        const begun = await call('/totp/begin', { password: password() });
        el('tf-qr').src = begun.qr;
        el('tf-secret').textContent = begun.secret;
        el('tf-codes').hidden = true;
        el('tf-setup').hidden = false;
        el('tf-code').value = '';
        el('tf-code').focus();
    });
    act('tf-confirm', async () => {
        const done = await call('/totp/confirm', { code: el('tf-code').value });
        el('tf-setup').hidden = true;
        el('tf-password').value = '';
        showCodes(done.recovery_codes);
        notice('Two-step sign-in is on. The console will ask for a code next time you sign in.');
        await reload();
    });
    act('tf-totp-codes', async () => {
        const done = await call('/recovery', { password: password() });
        el('tf-password').value = '';
        showCodes(done.recovery_codes);
        notice('New recovery codes. The old ones no longer work.');
        await reload();
    });
    act('tf-totp-off', async () => {
        const pw = password();
        if (!confirm('Turn off the authenticator app? Your recovery codes stop working too.')) return;
        await call('/totp/disable', { password: pw });
        el('tf-password').value = '';
        el('tf-codes').hidden = true;
        notice('The authenticator app is off.');
        await reload();
    });

    act('tf-passkey-add', async () => {
        const name = el('tf-passkey-name').value.trim();
        if (!name) { el('tf-passkey-name').focus(); throw new Error('Give the passkey a name, such as the device it is on.'); }
        const begun = await call('/passkeys/begin', { password: password() });
        const options = begun.options.publicKey;
        options.challenge = toBytes(options.challenge);
        options.user.id = toBytes(options.user.id);
        (options.excludeCredentials || []).forEach(c => { c.id = toBytes(c.id); });
        const cred = await navigator.credentials.create({ publicKey: options });
        await call('/passkeys/finish', {
            challenge: begun.challenge, name,
            response: {
                id: cred.id, rawId: toText(cred.rawId), type: cred.type,
                response: {
                    clientDataJSON: toText(cred.response.clientDataJSON),
                    attestationObject: toText(cred.response.attestationObject),
                    transports: cred.response.getTransports ? cred.response.getTransports() : []
                }
            }
        });
        el('tf-password').value = '';
        el('tf-passkey-name').value = '';
        notice(`Passkey "${name}" added. You can sign in with it alone, or use it after your password.`);
        await reload();
    });

    async function removePasskey(p) {
        notice('');
        try {
            const pw = password();
            if (!confirm(`Remove the passkey "${p.name}"?`)) return;
            await call(`/passkeys/${encodeURIComponent(p.id)}/delete`, { password: pw });
            el('tf-password').value = '';
            notice(`Passkey "${p.name}" removed.`);
            await reload();
        } catch (error) {
            notice(error.message, true);
        }
    }
})();
