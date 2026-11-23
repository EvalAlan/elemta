// Wires the console's controls to their functions without inline handlers.
//
// The page's Content-Security-Policy allows scripts only from files on this
// server (script-src 'self'), and that also forbids inline onclick attributes:
// to the browser they are inline script. So the markup names what to call
// instead:
//
//	<button data-click="refreshQueue">
//	<button data-click="retryQueue" data-args='["deferred"]'>
//	<select data-change="setUserRole" data-args='["ann", {"$":"value"}, {"$":"this"}]'>
//
// data-click, data-change, data-input and data-submit name a function, and
// data-args is a JSON array of its arguments. An argument {"$": name} stands
// for what an inline handler could reach: "value" and "checked" (the
// control's), "this" (the control) and "event". They are objects rather than
// marker strings so that no address or message id, however odd, is mistaken
// for one.
//
// Only the names below can be called. Markup built from server data goes
// through innerHTML in places, and with a lookup on window alone, a string
// that slipped through escaping as a data-click attribute could call any
// global function. The browser tests check that every name used is listed.
(function () {
    'use strict';

    // Small things the inline handlers did themselves.
    const builtins = {
        // A dismissable banner or toast: remove the control's parent.
        dismiss: el => el.parentElement && el.parentElement.remove(),
        // An editor row's own Remove button.
        removeRow: el => { const row = el.closest('.rows-editor-row'); if (row) row.remove(); },
        // A styled button standing in for a hidden file input.
        openFilePicker: (el, id) => { const input = document.getElementById(id); if (input) input.click(); },
    };

    const allowed = new Set([
        'addPluginRow', 'campaignAction', 'changeOwnPassword', 'changeTimeScale',
        'checkMailAuthPlugin', 'clearSelection', 'closeAPIKeysModal', 'closeCampaignEditor',
        'closeLoginModal', 'closeModal', 'closeTrace', 'copyMessageId', 'createAPIKey',
        'createUser', 'deleteCampaign', 'deleteCurrentMessage', 'deleteMessage',
        'deleteSelected', 'deleteUser', 'drilldownConnectionCloseLogs',
        'drilldownLogsBySearch', 'drilldownQueueRiskLogs', 'drilldownTimeoutLogs',
        'editCampaign', 'generatePlainText', 'goToPage', 'handleLogin', 'handleLogout',
        'holdMessage', 'importDirectoryRecipients', 'newCampaign', 'refreshAbuse',
        'refreshBackupStatus', 'refreshCampaigns', 'refreshCertificate',
        'refreshCertificates', 'refreshDnsHealth', 'refreshDomainStats', 'refreshHealth',
        'refreshLogs', 'refreshPlugins', 'refreshQueue', 'refreshReports',
        'refreshSenderStats', 'refreshServerConfig', 'refreshSuppression', 'refreshUsers',
        'releaseMessageClaim', 'resetSecondFactor', 'resetUserPassword', 'restartServer',
        'retryCurrentMessage', 'retryCurrentQueue', 'retryMessage', 'retryQueue',
        'retrySelected', 'revokeAPIKey', 'saveCampaign', 'savePluginSettings',
        'saveServerConfig', 'searchMessages', 'sendCampaignTest', 'setEditorMode',
        'setTheme', 'setUserRole', 'showAPIKeysModal', 'showLoginModal', 'startCampaign',
        'suppressAddress', 'switchModalTab', 'switchSettingsTab', 'syncCertificates',
        'toggleAutoRefreshPause', 'toggleMessageSelection', 'togglePlugin',
        'toggleSelectAll', 'toggleUserMenu', 'traceMessage', 'unsuppressAddress',
        'updateDefaultPageSize', 'updateRefreshInterval', 'viewMessage',
    ]);

    function resolve(name) {
        if (Object.prototype.hasOwnProperty.call(builtins, name)) return builtins[name];
        if (allowed.has(name) && typeof window[name] === 'function') return window[name];
        return null;
    }

    function argsFor(el, event) {
        let args = [];
        const raw = el.getAttribute('data-args');
        if (raw) {
            try {
                args = JSON.parse(raw);
            } catch (err) {
                console.error('data-args is not JSON:', raw);
                return null;
            }
            if (!Array.isArray(args)) return null;
        }
        return args.map(a => {
            if (a === null || typeof a !== 'object' || Array.isArray(a)) return a;
            switch (a.$) {
                case 'value': return el.value;
                case 'checked': return el.checked;
                case 'this': return el;
                case 'event': return event;
                default: return a;
            }
        });
    }

    // Every element from the target up that names a handler gets it, inner
    // first, as inline handlers did by bubbling.
    function dispatch(event) {
        const attr = 'data-' + event.type;
        for (let el = event.target; el && el !== document; el = el.parentElement) {
            if (!el.hasAttribute || !el.hasAttribute(attr)) continue;
            const name = el.getAttribute(attr);
            const fn = resolve(name);
            if (!fn) {
                console.error('No console action named', name);
                continue;
            }
            const args = argsFor(el, event);
            if (args === null) continue;
            // A link that runs an action must not also follow its href.
            if (event.type === 'click' && el.tagName === 'A') event.preventDefault();
            if (fn === builtins[name]) fn(el, ...args);
            else fn.apply(el, args);
        }
    }

    ['click', 'change', 'input', 'submit'].forEach(type => document.addEventListener(type, dispatch));

    // actionArgs builds a data-args attribute value for markup made in
    // script, already escaped for a quoted attribute.
    window.actionArgs = function (...args) {
        return JSON.stringify(args)
            .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
            .replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };
})();
