// ============================================================================
// Dashboard user management (Settings > Users)
//
// Backed by /api/users, which edits the same users file as `elemta user`.
// The server enforces every rule (permissions, last admin, password length);
// the checks here only save a round trip.
// ============================================================================

async function usersRequest(method, path, body) {
    const options = { method, headers: { 'Accept': 'application/json' } };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }
    const response = await fetch(`${API_BASE}${path}`, options);
    if (!response.ok) {
        const text = (await response.text()).trim();
        throw new Error(text || `HTTP ${response.status}`);
    }
    return response.status === 204 ? null : response.json();
}

async function refreshUsers() {
    const listEl = document.getElementById('users-list');
    const card = document.getElementById('users-card');
    if (!listEl) return;

    try {
        const response = await fetch(`${API_BASE}/users`, { headers: { 'Accept': 'application/json' } });
        if (response.status === 403) {
            // A non-admin still gets the "Change my password" card.
            card.style.display = 'none';
            return;
        }
        if (response.status === 404) {
            card.style.display = 'none';
            return;
        }
        if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`);
        card.style.display = '';
        const data = await response.json();
        const roles = (data.roles || []).map(r => r.name);
        fillRoleSelect(document.getElementById('new-user-role'), data.roles || []);

        if (!data.users || data.users.length === 0) {
            listEl.innerHTML = '<div class="field-hint">No users yet.</div>';
            return;
        }

        listEl.innerHTML = `
            <table class="messages-table">
                <thead><tr><th>User</th><th>Role</th><th>Domains</th><th></th></tr></thead>
                <tbody>
                    ${data.users.map(u => {
                        const isMe = u.username === data.current_user;
                        const current = (u.roles && u.roles[0]) || 'user';
                        const name = escapeJsArg(u.username);
                        return `
                        <tr>
                            <td>${escapeHtml(u.username)}${isMe ? ' <span class="field-hint">(you)</span>' : ''}</td>
                            <td>
                                <select class="users-role-select" onchange="setUserRole('${name}', this.value, this)" data-current="${escapeHtml(current)}">
                                    ${roles.map(r => `<option value="${escapeHtml(r)}"${r === current ? ' selected' : ''}>${escapeHtml(r)}</option>`).join('')}
                                </select>
                            </td>
                            <td>${current === 'domain-admin'
                                ? `<button class="btn btn-secondary btn-sm" onclick="setUserRole('${name}', 'domain-admin', null, '${escapeJsArg((u.domains || []).join(', '))}')">${escapeHtml((u.domains || []).join(', ') || 'none')}</button>`
                                : '<span class="field-hint">all</span>'}</td>
                            <td style="white-space: nowrap;">
                                <button class="btn btn-secondary btn-sm" onclick="resetUserPassword('${name}')">Set password</button>
                                ${isMe ? '' : `<button class="btn btn-danger btn-sm" onclick="deleteUser('${name}')">Remove</button>`}
                            </td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>
            <div class="field-hint">${data.users.length} user${data.users.length === 1 ? '' : 's'}.</div>`;
    } catch (error) {
        console.error('User list failed:', error);
        listEl.innerHTML = `<div class="error-message">Could not load users: ${escapeHtml(error.message)}</div>`;
    }
}

// The roles come from the server, so a role added there shows up here without
// touching this file. "user" stays the default for a new account.
function fillRoleSelect(selectEl, roles) {
    if (!selectEl || roles.length === 0) return;
    const chosen = selectEl.value || 'user';
    selectEl.innerHTML = roles.map(r =>
        `<option value="${escapeHtml(r.name)}" title="${escapeHtml(r.description || '')}">${escapeHtml(r.name)}</option>`
    ).join('');
    selectEl.value = roles.some(r => r.name === chosen) ? chosen : 'user';
}

// askDomains asks which domains a domain administrator manages. null means
// the operator cancelled.
function askDomains(username, current) {
    const answer = prompt(`Domains ${username} administers, separated by commas:`, current || '');
    if (answer === null) return null;
    return answer.split(/[\s,;]+/).map(d => d.trim()).filter(Boolean);
}

async function createUser() {
    const nameEl = document.getElementById('new-user-name');
    const passEl = document.getElementById('new-user-password');
    const role = document.getElementById('new-user-role').value;
    const username = nameEl.value.trim();
    const password = passEl.value;

    if (!username) { showToast('Enter a username', 'error'); return; }
    if (password.length < 12) { showToast('Passwords need at least 12 characters', 'error'); return; }

    let domains;
    if (role === 'domain-admin') {
        domains = askDomains(username, '');
        if (domains === null) return;
    }

    try {
        await usersRequest('POST', '/users', { username, password, role, domains });
        nameEl.value = '';
        passEl.value = '';
        showToast(`Added ${username} as ${role}`, 'success');
        refreshUsers();
    } catch (error) {
        showToast(`Could not add user: ${error.message}`, 'error');
    }
}

async function setUserRole(username, role, selectEl, currentDomains) {
    let domains;
    if (role === 'domain-admin') {
        domains = askDomains(username, currentDomains);
        if (domains === null) {
            if (selectEl) selectEl.value = selectEl.dataset.current;
            return;
        }
    }
    try {
        await usersRequest('PUT', `/users/${encodeURIComponent(username)}/role`, { role, domains });
        if (selectEl) selectEl.dataset.current = role;
        showToast(`${username} is now ${role}${domains ? ' for ' + domains.join(', ') : ''}`, 'success');
        refreshUsers();
        if (username === authState.username) checkAuthStatus();
    } catch (error) {
        // Put the select back to what the server still has.
        if (selectEl) selectEl.value = selectEl.dataset.current;
        showToast(`Could not change role: ${error.message}`, 'error');
    }
}

async function resetUserPassword(username) {
    const password = prompt(`New password for ${username} (12+ characters). Their sessions will be signed out.`);
    if (password === null) return;
    if (password.length < 12) { showToast('Passwords need at least 12 characters', 'error'); return; }
    try {
        await usersRequest('PUT', `/users/${encodeURIComponent(username)}/password`, { password });
        showToast(`Password set for ${username}`, 'success');
    } catch (error) {
        showToast(`Could not set password: ${error.message}`, 'error');
    }
}

async function deleteUser(username) {
    if (!confirm(`Remove ${username}? They will be signed out immediately.`)) return;
    try {
        await usersRequest('DELETE', `/users/${encodeURIComponent(username)}`);
        showToast(`Removed ${username}`, 'success');
        refreshUsers();
    } catch (error) {
        showToast(`Could not remove user: ${error.message}`, 'error');
    }
}

async function changeOwnPassword() {
    const currentEl = document.getElementById('own-current-password');
    const newEl = document.getElementById('own-new-password');
    if (newEl.value.length < 12) { showToast('Passwords need at least 12 characters', 'error'); return; }
    try {
        await usersRequest('POST', '/account/password', {
            current_password: currentEl.value,
            new_password: newEl.value,
        });
        currentEl.value = '';
        newEl.value = '';
        showToast('Password changed', 'success');
    } catch (error) {
        showToast(`Could not change password: ${error.message}`, 'error');
    }
}
