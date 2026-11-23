// Sign-in, in one or two steps: a password, then a code or a passkey
// for users with two-step sign-in (internal/api/mfa.go). A passkey
// alone also signs in.
const passkeys = !!(window.PublicKeyCredential && window.isSecureContext);
let pendingToken = '';

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

async function post(url, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!response.ok) {
        const text = (await response.text()).trim();
        throw new Error(text || (response.status === 401 ? 'Invalid username or password' : 'Sign-in failed'));
    }
    return response.json();
}

function showError(id, text) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.style.display = text ? 'block' : 'none';
}

function signedIn(data) {
    const ok = document.getElementById('success-message');
    ok.textContent = `Welcome, ${data.username}! Redirecting...`;
    ok.style.display = 'block';
    setTimeout(() => { window.location.href = '/'; }, 500);
}

function secondStep(data) {
    pendingToken = data.token;
    document.getElementById('login-form').hidden = true;
    document.getElementById('passkey-btn').hidden = true;
    document.getElementById('second-form').hidden = false;
    const hasCode = data.methods.includes('totp');
    document.getElementById('code-group').hidden = !hasCode;
    document.getElementById('code-btn').hidden = !hasCode;
    document.querySelector('.second-intro').textContent = hasCode
        ? 'Enter the code from your authenticator app, or one of your recovery codes.'
        : 'Confirm it is you with your passkey.';
    document.getElementById('second-passkey-btn').hidden = !(passkeys && data.methods.includes('passkey'));
    document.getElementById('second-passkey-btn').textContent = hasCode ? 'Use a passkey instead' : 'Use my passkey';
    if (hasCode) document.getElementById('code').focus();
}

function restart() {
    pendingToken = '';
    document.getElementById('second-form').hidden = true;
    document.getElementById('login-form').hidden = false;
    document.getElementById('passkey-btn').hidden = !passkeys;
    document.getElementById('password').value = '';
    document.getElementById('code').value = '';
    showError('second-error', '');
    document.getElementById('password').focus();
}

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('login-btn');
    const btnText = document.getElementById('btn-text');
    showError('error-message', '');
    document.getElementById('success-message').style.display = 'none';
    loginBtn.disabled = true;
    btnText.textContent = 'Signing in...';
    try {
        const data = await post('/auth/login', { username, password });
        if (data.status === 'second_factor') secondStep(data);
        else signedIn(data);
    } catch (error) {
        showError('error-message', error.message === 'Failed to fetch' ? 'Login failed. Server may be unavailable.' : error.message);
    } finally {
        loginBtn.disabled = false;
        btnText.textContent = 'Login';
    }
}

async function submitCode(event) {
    event.preventDefault();
    showError('second-error', '');
    const btn = document.getElementById('code-btn');
    btn.disabled = true;
    try {
        signedIn(await post('/auth/login/code', { token: pendingToken, code: document.getElementById('code').value }));
    } catch (error) {
        showError('second-error', error.message);
        if (/start again/i.test(error.message)) setTimeout(restart, 1500);
    } finally {
        btn.disabled = false;
    }
}

// With a token, the passkey is the second step after the password;
// without, it signs in on its own.
async function usePasskey(errorId) {
    showError(errorId, '');
    try {
        const begun = await post('/auth/login/passkey/begin', { token: pendingToken });
        const options = begun.options.publicKey;
        options.challenge = toBytes(options.challenge);
        (options.allowCredentials || []).forEach(c => { c.id = toBytes(c.id); });
        const cred = await navigator.credentials.get({ publicKey: options });
        signedIn(await post('/auth/login/passkey/finish', {
            token: pendingToken, challenge: begun.challenge,
            response: {
                id: cred.id, rawId: toText(cred.rawId), type: cred.type,
                response: {
                    clientDataJSON: toText(cred.response.clientDataJSON),
                    authenticatorData: toText(cred.response.authenticatorData),
                    signature: toText(cred.response.signature),
                    userHandle: cred.response.userHandle ? toText(cred.response.userHandle) : ''
                }
            }
        }));
    } catch (error) {
        // Dismissing the browser's prompt isn't a problem to report.
        if (error && error.name === 'NotAllowedError') return;
        showError(errorId, error && error.name && error.name !== 'Error' ? 'Your browser couldn\'t use a passkey here.' : error.message);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('second-form').addEventListener('submit', submitCode);
    document.getElementById('restart-btn').addEventListener('click', restart);
    document.getElementById('passkey-btn').addEventListener('click', () => usePasskey('error-message'));
    document.getElementById('second-passkey-btn').addEventListener('click', () => usePasskey('second-error'));
    document.getElementById('passkey-btn').hidden = !passkeys;
    document.getElementById('username').focus();
});
