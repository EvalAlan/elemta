// Compliance search across every mailbox (internal/api/compliance.go). What
// comes back is other people's mail, from anyone: it only ever reaches the
// page through textContent.
(function () {
    'use strict';
    const view = document.getElementById('view-compliance');
    if (!view) return;
    const el = id => document.getElementById(id);
    let lastQuery = null;

    function notice(text, error = false) {
        const line = el('compliance-notice');
        line.textContent = text; line.hidden = !text;
        line.classList.toggle('abuse-error', error);
    }

    // The form as the API's query. Dates are the user's own days: "on or
    // before" a day means before the start of the next.
    function readQuery() {
        const q = {};
        const accounts = el('compliance-accounts').value.split(/[\s,;]+/).map(a => a.trim()).filter(Boolean);
        if (accounts.length) q.accounts = accounts;
        for (const [field, id] of [['from', 'compliance-from'], ['to', 'compliance-to'], ['subject', 'compliance-subject'], ['text', 'compliance-text']]) {
            const v = el(id).value.trim();
            if (v) q[field] = v;
        }
        const since = el('compliance-since').value, until = el('compliance-until').value;
        if (since) q.since = new Date(since + 'T00:00:00').toISOString();
        if (until) {
            const end = new Date(until + 'T00:00:00');
            end.setDate(end.getDate() + 1);
            q.before = end.toISOString();
        }
        if (!el('compliance-held').checked) q.exclude_held = true;
        return q;
    }

    function size(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return Math.round(bytes / 1024) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function cell(row, value, title) {
        const td = document.createElement('td');
        if (value instanceof Node) td.appendChild(value); else td.textContent = value || '';
        if (title) td.title = title;
        row.appendChild(td);
    }

    function show(result) {
        const hits = result.hits || [];
        el('compliance-results-card').hidden = false;
        el('compliance-summary').textContent = result.total === 0 ? 'Nothing found'
            : result.total > hits.length ? `${result.total.toLocaleString()} found, newest ${hits.length} shown`
            : `${result.total.toLocaleString()} found`;
        el('compliance-export').disabled = result.total === 0;
        const unindexed = el('compliance-unindexed');
        unindexed.hidden = !result.unindexed;
        unindexed.textContent = result.unindexed
            ? `${result.unindexed.toLocaleString()} messages in these mailboxes and dates haven't been indexed yet, so this search couldn't see them. The index catches up on its own; search again later for a complete answer.`
            : '';
        const body = el('compliance-hits');
        body.replaceChildren();
        if (!hits.length) {
            const row = document.createElement('tr'), td = document.createElement('td');
            td.colSpan = 8; td.textContent = 'No messages match.';
            row.appendChild(td); body.appendChild(row);
            return;
        }
        for (const h of hits) {
            const row = document.createElement('tr');
            const received = new Date(h.date);
            cell(row, received.toLocaleString());
            cell(row, h.account);
            const folder = h.held ? `${h.folder} (deleted, held)` : h.folder;
            cell(row, folder, h.held && h.held_at ? 'Deleted ' + new Date(h.held_at).toLocaleString() : '');
            cell(row, h.from);
            cell(row, h.to);
            cell(row, h.subject || '(no subject)');
            cell(row, size(h.size || 0));
            const link = document.createElement('a');
            link.href = '/api/compliance/message?' + new URLSearchParams({ ref: h.ref });
            link.textContent = 'Download';
            link.title = 'Download this message as an .eml file; recorded in the audit log';
            cell(row, link);
            body.appendChild(row);
        }
    }

    el('compliance-form').addEventListener('submit', async event => {
        event.preventDefault();
        const query = readQuery();
        const button = event.submitter || el('compliance-form').querySelector('button[type=submit]');
        button.disabled = true;
        notice('Searching…');
        try {
            const response = await fetch('/api/compliance/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify(query)
            });
            if (response.status === 401) throw new Error('Your session has ended. Sign in again.');
            if (response.status === 403) throw new Error('Compliance search needs an administrator or compliance account.');
            if (!response.ok) throw new Error((await response.text()).trim() || 'The search failed.');
            lastQuery = query;
            show(await response.json());
            notice('');
        } catch (error) {
            notice(error.message, true);
        } finally {
            button.disabled = false;
        }
    });

    // The browser downloads the export itself, so a large one streams to
    // disk instead of being held in the page. It goes to a hidden frame: a
    // download leaves the frame alone, and a refusal loads into it, where
    // it can be read and shown here instead of replacing the console.
    el('compliance-download').addEventListener('load', () => {
        let text = '';
        try { text = (el('compliance-download').contentDocument.body.textContent || '').trim(); } catch (error) { /* not ours */ }
        if (text) notice('The export failed: ' + text, true);
    });
    el('compliance-export').addEventListener('click', () => {
        if (!lastQuery) return;
        const form = el('compliance-export-form');
        form.elements.query.value = JSON.stringify(lastQuery);
        form.submit();
        notice('The export is downloading. A large one can take several minutes to start.');
    });

    window.openCompliance = function () {
        el('compliance-accounts').focus();
    };
})();
