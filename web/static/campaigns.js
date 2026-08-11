// Mass mailer: campaign list, message editor and send controls.
//
// Kept out of app.js because it is a section of its own rather than another
// panel, and because most installations never turn it on.

const campaignState = {
    // The campaign being edited, or null for a new one. Only the id is held:
    // the fields live in the form, which is the thing the operator edits.
    editingId: null,
    editingState: null,
    // Server-parsed recipients for the campaign being edited, so the summary
    // reports what the server actually accepted rather than what the textarea
    // looks like.
    recipientSummary: null,
    // True when the server sent only part of the stored recipient list. Saving
    // must then leave the list alone rather than replace it with the fragment
    // on screen.
    recipientsTruncated: false,
    pollTimer: null,
    editorMode: 'rich',
    // Set while the editor has changes that have not been saved, so leaving it
    // can say so instead of discarding them without a word.
    dirty: false,
};

// ============================================================================
// Visibility
// ============================================================================

// applyMassMailerVisibility shows the nav item only while the plugin is on.
// A section that answers every click with "not enabled" is worse than one that
// is not there at all.
function applyMassMailerVisibility(plugins) {
    const nav = document.getElementById('nav-campaigns');
    if (!nav) return;

    const plugin = (plugins || []).find(p => p.name === 'mass_mailer');
    const enabled = !!(plugin && plugin.enabled);
    nav.style.display = enabled ? '' : 'none';

    // If the operator turns the plugin off while standing in the section, move
    // them somewhere that still works rather than leaving a dead view up.
    if (!enabled && document.getElementById('view-campaigns')?.classList.contains('active')) {
        switchView('dashboard');
    }
}

// refreshMassMailerVisibility asks the server directly, for page load and for
// the case where the plugin list is not otherwise being fetched.
async function refreshMassMailerVisibility() {
    try {
        const response = await fetch(`${API_BASE}/config/plugins`);
        if (!response.ok) return;
        const data = await response.json();
        applyMassMailerVisibility(data.plugins || []);
    } catch (error) {
        // Not being able to ask is not a reason to show a section that may not
        // work; leaving it hidden is the safe direction.
        console.debug('mass mailer visibility check failed:', error);
    }
}

// ============================================================================
// Campaign list
// ============================================================================

async function refreshCampaigns() {
    const loadingEl = document.getElementById('campaigns-loading');
    const listEl = document.getElementById('campaigns-list');
    if (!listEl) return;

    try {
        const response = await fetch(`${API_BASE}/campaigns`);
        if (response.status === 503) {
            loadingEl.textContent = 'The mass mailer is turned off. Enable it under Settings › Plugins.';
            listEl.innerHTML = '';
            return;
        }
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);

        const data = await response.json();
        const campaigns = data.campaigns || [];

        loadingEl.style.display = 'none';
        if (campaigns.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <p>No campaigns yet.</p>
                    <button class="btn btn-primary" onclick="newCampaign()">New Campaign</button>
                </div>`;
        } else {
            listEl.innerHTML = campaigns.map(renderCampaignRow).join('');
        }

        scheduleCampaignPoll(campaigns);
    } catch (error) {
        console.error('Error loading campaigns:', error);
        loadingEl.style.display = 'block';
        loadingEl.innerHTML = `<div class="error-message">Failed to load campaigns: ${escapeHtml(error.message)}</div>`;
    }
}

function renderCampaignRow(c) {
    const total = c.total || 0;
    // Skipped counts as done: those recipients have been dealt with, and a
    // progress bar that never reaches the end because a third of the list was
    // suppressed reads as a stuck campaign.
    const done = (c.sent || 0) + (c.failed || 0) + (c.skipped || 0);
    const percent = total > 0 ? Math.round((done / total) * 100) : 0;
    const id = escapeJsArg(c.id);

    // Actions follow the state machine rather than being greyed out: a button
    // that is present but refuses is a button people click twice.
    let actions = '';
    switch (c.state) {
        case 'running':
            actions = `
                <button class="btn btn-secondary btn-sm" onclick="campaignAction('${id}','pause')">Pause</button>
                <button class="btn btn-danger btn-sm" onclick="campaignAction('${id}','cancel')">Cancel</button>`;
            break;
        case 'paused':
            actions = `
                <button class="btn btn-primary btn-sm" onclick="campaignAction('${id}','start')">Resume</button>
                <button class="btn btn-danger btn-sm" onclick="campaignAction('${id}','cancel')">Cancel</button>
                <button class="btn btn-secondary btn-sm" onclick="editCampaign('${id}')">Edit</button>`;
            break;
        case 'draft':
            actions = `
                <button class="btn btn-primary btn-sm" onclick="editCampaign('${id}')">Open</button>
                <button class="btn btn-danger btn-sm" onclick="deleteCampaign('${id}')">Delete</button>`;
            break;
        default:
            actions = `
                <button class="btn btn-secondary btn-sm" onclick="editCampaign('${id}')">View</button>
                <button class="btn btn-danger btn-sm" onclick="deleteCampaign('${id}')">Delete</button>`;
    }

    const failed = c.failed > 0
        ? `<span class="campaign-failed">${c.failed} failed</span>`
        : '';
    // Shown apart from failed: an address passed over because it is suppressed
    // is not a delivery problem to investigate.
    const skipped = c.skipped > 0
        ? `<span class="campaign-skipped" title="on the suppression list">${c.skipped} skipped</span>`
        : '';
    const lastError = c.last_error
        ? `<div class="campaign-error">${escapeHtml(c.last_error)}</div>`
        : '';

    return `
        <div class="campaign-row">
            <div class="campaign-main">
                <div class="campaign-title">
                    <span class="campaign-name">${escapeHtml(c.name || '(unnamed)')}</span>
                    <span class="campaign-state ${escapeHtml(c.state)}">${escapeHtml(c.state)}</span>
                </div>
                <div class="campaign-subject">${escapeHtml(c.subject || '')}</div>
                <div class="campaign-meta">
                    ${escapeHtml(c.from || '')} &middot; ${total} recipient${total === 1 ? '' : 's'}
                    ${c.rate_per_minute ? ` &middot; ${c.rate_per_minute}/min` : ''}
                    &middot; updated ${escapeHtml(formatTimeAgo(c.updated_at))}
                </div>
                ${lastError}
            </div>
            <div class="campaign-progress">
                <div class="progress-bar"><div class="progress-fill ${escapeHtml(c.state)}" style="width: ${percent}%"></div></div>
                <div class="progress-label">${c.sent || 0} / ${total} sent ${failed} ${skipped}</div>
            </div>
            <div class="campaign-actions">${actions}</div>
        </div>`;
}

// scheduleCampaignPoll refreshes while something is sending and stops when
// nothing is. Polling a page of finished campaigns forever is how a dashboard
// ends up being the busiest client of its own API.
function scheduleCampaignPoll(campaigns) {
    clearTimeout(campaignState.pollTimer);
    campaignState.pollTimer = null;

    const active = (campaigns || []).some(c => c.state === 'running');
    if (!active) return;
    if (!document.getElementById('view-campaigns')?.classList.contains('active')) return;
    campaignState.pollTimer = setTimeout(refreshCampaigns, 3000);
}

function stopCampaignPolling() {
    clearTimeout(campaignState.pollTimer);
    campaignState.pollTimer = null;
}

// ============================================================================
// Editor
// ============================================================================

function newCampaign() {
    campaignState.editingId = null;
    campaignState.editingState = 'draft';
    campaignState.recipientSummary = null;
    campaignState.recipientsTruncated = false;
    campaignState.dirty = false;
    document.getElementById('campaign-recipients').readOnly = false;

    setField('campaign-name', '');
    setField('campaign-from', '');
    setField('campaign-reply-to', '');
    setField('campaign-subject', '');
    setField('campaign-rate', '');
    setField('campaign-text', '');
    setField('campaign-recipients', '');
    setField('campaign-html-source', '');
    document.getElementById('campaign-html').innerHTML = '';
    document.getElementById('campaign-recipients-summary').innerHTML = '';
    document.getElementById('campaign-editor-notice').innerHTML = '';
    setCampaignStatus('', '');

    document.getElementById('campaign-editor-title').textContent = 'New Campaign';
    showCampaignEditor(true);
    setEditorMode('rich');
    updateMergeFields();
}

async function editCampaign(id) {
    try {
        const response = await fetch(`${API_BASE}/campaigns/${encodeURIComponent(id)}`);
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);
        const c = await response.json();

        campaignState.editingId = c.id;
        campaignState.editingState = c.state;
        campaignState.recipientsTruncated = false;
        campaignState.dirty = false;

        setField('campaign-name', c.name || '');
        setField('campaign-from', c.from || '');
        setField('campaign-reply-to', c.reply_to || '');
        setField('campaign-subject', c.subject || '');
        setField('campaign-rate', c.rate_per_minute || '');
        setField('campaign-text', c.text_body || '');
        setField('campaign-html-source', c.html_body || '');
        // Sanitised on the way in: the stored HTML may have been pasted from
        // anywhere, and it is about to live inside the admin page.
        document.getElementById('campaign-html').innerHTML = sanitizeEmailHTML(c.html_body || '');

        document.getElementById('campaign-editor-title').textContent = c.name || 'Campaign';
        document.getElementById('campaign-editor-notice').innerHTML = '';
        setCampaignStatus('', '');
        showCampaignEditor(true);
        setEditorMode('rich');

        await loadCampaignRecipients(c.id);
        updateMergeFields();
    } catch (error) {
        console.error('Error opening campaign:', error);
        showToast(`Failed to open campaign: ${error.message}`, 'error');
    }
}

function closeCampaignEditor() {
    if (campaignState.dirty &&
        !confirm('This campaign has unsaved changes. Leave without saving?')) {
        return;
    }
    campaignState.dirty = false;
    showCampaignEditor(false);
    refreshCampaigns();
}

function showCampaignEditor(show) {
    document.getElementById('campaign-list-screen').style.display = show ? 'none' : '';
    document.getElementById('campaign-editor-screen').style.display = show ? '' : 'none';

    const stateEl = document.getElementById('campaign-editor-state');
    const state = campaignState.editingState;
    stateEl.textContent = show && state ? state : '';
    stateEl.className = `campaign-state ${show && state ? state : ''}`;

    // A campaign that has finished, or is mid-flight, is shown rather than
    // edited: changing it now would mean the copies already delivered differ
    // from the rest with nothing to say so.
    const readOnly = show && state && state !== 'draft' && state !== 'paused';
    document.querySelectorAll('#campaign-editor-screen input, #campaign-editor-screen textarea')
        .forEach(el => { el.disabled = !!readOnly; });
    document.getElementById('campaign-html').contentEditable = readOnly ? 'false' : 'true';
    const startBtn = document.getElementById('campaign-start-btn');
    startBtn.style.display = readOnly ? 'none' : '';
    startBtn.textContent = state === 'paused' ? 'Resume sending' : 'Start sending';
}

function setField(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value === null || value === undefined ? '' : String(value);
}

function setCampaignStatus(message, kind) {
    setSaveStatus(document.getElementById('campaign-save-status'), message, kind);
}

// ============================================================================
// The message editor
// ============================================================================

// setEditorMode moves between the rich editor, the HTML source and a preview,
// carrying the content across so the three never disagree about what will be
// sent.
function setEditorMode(mode) {
    const rich = document.getElementById('campaign-html');
    const source = document.getElementById('campaign-html-source');
    const preview = document.getElementById('campaign-preview');
    const toolbar = document.getElementById('wysiwyg-toolbar');

    // Take the current content from whichever surface was authoritative.
    if (campaignState.editorMode === 'rich') {
        source.value = rich.innerHTML;
    } else if (campaignState.editorMode === 'html') {
        noteStrippedStyleBlock(source.value);
        rich.innerHTML = sanitizeEmailHTML(source.value);
    }

    campaignState.editorMode = mode;
    rich.style.display = mode === 'rich' ? '' : 'none';
    source.style.display = mode === 'html' ? '' : 'none';
    preview.style.display = mode === 'preview' ? '' : 'none';
    toolbar.style.display = mode === 'rich' ? '' : 'none';

    if (mode === 'preview') {
        // srcdoc into a sandboxed frame: no scripts, no same-origin access, so
        // a pasted-in template cannot reach the session it is being previewed
        // in. The merge values shown are the first recipient's.
        preview.srcdoc = buildPreviewDocument();
    }

    document.querySelectorAll('.editor-modes .mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
}

function currentHTMLBody() {
    return campaignState.editorMode === 'html'
        ? document.getElementById('campaign-html-source').value
        : document.getElementById('campaign-html').innerHTML;
}

function buildPreviewDocument() {
    const sample = firstRecipientVars();
    const body = mergePreview(sanitizeEmailHTML(currentHTMLBody()), sample);
    // The frame carries its own minimal styling: it is a mail client stand-in,
    // not part of the dashboard, and inheriting the dark theme would misreport
    // how the message looks.
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
        <style>
          body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
                 color: #111; background: #fff; margin: 0; padding: 1.25rem; line-height: 1.5; }
          img { max-width: 100%; }
        </style></head><body>${body}</body></html>`;
}

// mergePreview fills merge fields for display only. Unresolved ones are left
// visible rather than blanked, so the preview shows the gap the recipient
// would see instead of hiding it.
function mergePreview(html, vars) {
    return html.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (whole, field) => {
        const value = vars[field.toLowerCase()];
        return value === undefined ? whole : escapeHtml(value);
    });
}

// firstRecipientVars reads the first data row of the pasted list, so a preview
// shows real values rather than placeholders.
function firstRecipientVars() {
    const raw = document.getElementById('campaign-recipients').value || '';
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    if (lines.length < 2) return {};

    const header = splitDelimited(lines[0]);
    if (header.length < 2 || header[0].includes('@')) return {};
    const row = splitDelimited(lines[1]);

    const vars = {};
    header.forEach((name, i) => {
        vars[name.trim().toLowerCase()] = (row[i] || '').trim();
    });
    return vars;
}

function splitDelimited(line) {
    return line.includes('\t') ? line.split('\t') : line.split(',');
}

// generatePlainText writes the text alternative from the HTML. Bulk mail with
// no text part looks like bulk mail, and writing it twice by hand is how the
// two drift apart.
function generatePlainText() {
    const text = htmlToPlainText(sanitizeEmailHTML(currentHTMLBody()));
    const el = document.getElementById('campaign-text');
    if (el.value.trim() && !confirm('Replace the existing plain text?')) return;
    el.value = text;
    markCampaignDirty();
}

function htmlToPlainText(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const lines = [];

    const walk = (node) => {
        for (const child of node.childNodes) {
            if (child.nodeType === Node.TEXT_NODE) {
                const text = child.textContent.replace(/\s+/g, ' ');
                if (text.trim()) lines.push({ text, block: false });
                continue;
            }
            if (child.nodeType !== Node.ELEMENT_NODE) continue;

            const tag = child.tagName.toLowerCase();
            if (tag === 'br') { lines.push({ text: '', block: true }); continue; }
            if (tag === 'hr') { lines.push({ text: '---', block: true }); continue; }
            if (tag === 'li') { lines.push({ text: '- ', block: true }); }

            walk(child);

            // A link's destination is invisible in plain text unless it is
            // written out, and a newsletter whose links vanish is unusable.
            if (tag === 'a') {
                const href = child.getAttribute('href') || '';
                if (href && href !== child.textContent.trim()) {
                    lines.push({ text: ` <${href}>`, block: false });
                }
            }
            if (['p', 'div', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li', 'blockquote', 'table', 'tr'].includes(tag)) {
                lines.push({ text: '', block: true });
            }
        }
    };
    walk(doc.body);

    let out = '';
    for (const piece of lines) {
        if (piece.block) {
            if (!out.endsWith('\n')) out += '\n';
            out += piece.text;
        } else {
            out += piece.text;
        }
    }
    return out.replace(/\n{3,}/g, '\n\n').replace(/[ \t]+\n/g, '\n').trim();
}

// ----------------------------------------------------------------------------
// Sanitising
// ----------------------------------------------------------------------------

// sanitizeEmailHTML strips what must not run before HTML is put into the page.
//
// The editing surface is a live part of the admin document, so anything with an
// event handler on it — a pasted <img onerror>, most obviously — runs with the
// operator's session the moment it is inserted. Campaign HTML routinely comes
// from a designer, an agency or a template site, so treating it as trusted
// because an administrator pasted it gets the threat model backwards.
//
// Parsing happens in a detached DOMParser document, which does not execute
// anything while it is being examined.
const ALLOWED_URL_SCHEMES = /^(https?:|mailto:|tel:|#|\/|data:image\/(png|jpe?g|gif|webp);)/i;

function sanitizeEmailHTML(html) {
    if (!html) return '';
    const doc = new DOMParser().parseFromString(String(html), 'text/html');

    doc.querySelectorAll('script, iframe, object, embed, link, meta, base, form, input, button, style')
        .forEach(el => el.remove());

    doc.querySelectorAll('*').forEach(el => {
        for (const attr of Array.from(el.attributes)) {
            const name = attr.name.toLowerCase();
            // Event handlers, however they are spelled.
            if (name.startsWith('on')) {
                el.removeAttribute(attr.name);
                continue;
            }
            if (name === 'href' || name === 'src' || name === 'srcset' || name === 'action' || name === 'formaction') {
                const value = attr.value.trim();
                if (!ALLOWED_URL_SCHEMES.test(value)) {
                    el.removeAttribute(attr.name);
                }
                continue;
            }
            // style is kept — email is styled inline and stripping it would
            // make the editor useless — but url() can load and, historically,
            // execute, so it does not survive.
            if (name === 'style' && /url\s*\(|expression\s*\(|javascript:/i.test(attr.value)) {
                el.removeAttribute(attr.name);
            }
        }
    });

    return doc.body.innerHTML;
}

// noteStrippedStyleBlock explains a removal that is otherwise mystifying: a
// pasted template arrives with a <style> block, and the paste appears to lose
// its design for no reason.
//
// The block cannot be kept. It is inserted into the live dashboard document,
// where its rules apply to the whole page rather than to the message. Inline
// styles are what email needs anyway — most clients discard <style> — so the
// message is not just an apology.
let styleBlockNoticeShown = false;
function noteStrippedStyleBlock(html) {
    if (styleBlockNoticeShown || !/<style[\s>]/i.test(html)) return;
    styleBlockNoticeShown = true;
    showToast('The pasted <style> block was removed. Email styling needs to be inline to survive most clients.', 'info');
}

// ----------------------------------------------------------------------------
// Toolbar
// ----------------------------------------------------------------------------

// The toolbar uses document.execCommand. It is deprecated and has no
// replacement: every alternative is either a third-party editor or a selection
// and range implementation of comparable size. The commands used here are the
// ones every engine still supports.
function initializeCampaignEditor() {
    const toolbar = document.getElementById('wysiwyg-toolbar');
    if (!toolbar) return;

    toolbar.addEventListener('click', (e) => {
        const button = e.target.closest('button[data-cmd]');
        if (!button) return;
        e.preventDefault();
        runEditorCommand(button.dataset.cmd, button.dataset.value);
    });

    // Buttons must not steal the selection they are about to act on.
    toolbar.addEventListener('mousedown', (e) => e.preventDefault());

    const rich = document.getElementById('campaign-html');
    rich.addEventListener('input', () => { markCampaignDirty(); updateMergeFields(); });

    // Pasted content is sanitised and inserted as HTML rather than left to the
    // browser, which would carry over scripts and handlers from the source page.
    rich.addEventListener('paste', (e) => {
        const html = e.clipboardData?.getData('text/html');
        if (!html) return; // plain text needs no help
        e.preventDefault();
        noteStrippedStyleBlock(html);
        document.execCommand('insertHTML', false, sanitizeEmailHTML(html));
    });

    ['campaign-name', 'campaign-from', 'campaign-reply-to', 'campaign-subject',
        'campaign-rate', 'campaign-text', 'campaign-html-source'].forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => {
                markCampaignDirty();
                updateMergeFields();
            });
        });

    const recipients = document.getElementById('campaign-recipients');
    recipients?.addEventListener('input', () => {
        markCampaignDirty();
        updateRecipientSummary();
        updateMergeFields();
    });

    document.getElementById('campaign-recipients-file')?.addEventListener('change', handleRecipientFile);
}

function runEditorCommand(cmd, value) {
    const rich = document.getElementById('campaign-html');
    rich.focus();

    if (cmd === 'createLink') {
        const url = prompt('Link address', 'https://');
        if (!url) return;
        if (!ALLOWED_URL_SCHEMES.test(url.trim())) {
            showToast('That link scheme is not allowed in email', 'error');
            return;
        }
        document.execCommand('createLink', false, url.trim());
    } else if (cmd === 'insertImage') {
        const url = prompt('Image address', 'https://');
        if (!url) return;
        if (!ALLOWED_URL_SCHEMES.test(url.trim())) {
            showToast('That image address is not allowed', 'error');
            return;
        }
        document.execCommand('insertImage', false, url.trim());
    } else if (cmd === 'mergeField') {
        const field = prompt('Merge field name (a column from your recipient list)', 'first_name');
        if (!field) return;
        const clean = field.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '');
        if (!clean) return;
        document.execCommand('insertText', false, `{{${clean}}}`);
    } else if (cmd === 'formatBlock') {
        document.execCommand('formatBlock', false, `<${value}>`);
    } else {
        document.execCommand(cmd, false, value || null);
    }

    markCampaignDirty();
    updateMergeFields();
}

function markCampaignDirty() {
    campaignState.dirty = true;
    setCampaignStatus('Unsaved changes', '');
}

// ============================================================================
// Merge fields
// ============================================================================

// updateMergeFields shows which placeholders the message uses and whether the
// recipient list supplies them. An unsupplied field renders as a blank in
// delivered mail, which is only obvious once it has gone out.
function updateMergeFields() {
    const el = document.getElementById('campaign-merge-fields');
    if (!el) return;

    const text = [
        document.getElementById('campaign-subject')?.value || '',
        currentHTMLBody(),
        document.getElementById('campaign-text')?.value || '',
    ].join(' ');

    const used = new Set();
    for (const match of text.matchAll(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g)) {
        used.add(match[1].toLowerCase());
    }
    if (used.size === 0) {
        el.innerHTML = '';
        return;
    }

    const supplied = new Set(Object.keys(firstRecipientVars()));
    const chips = [...used].map(field => {
        const ok = supplied.has(field);
        return `<span class="merge-chip ${ok ? 'ok' : 'missing'}"
                      title="${ok ? 'supplied by the recipient list' : 'no column supplies this; it will render empty'}"
                >{{${escapeHtml(field)}}}</span>`;
    }).join('');

    el.innerHTML = `<span class="merge-label">Merge fields</span>${chips}`;
}

// ============================================================================
// Recipients
// ============================================================================

function handleRecipientFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    // A list big enough to hang the browser reading it is a list that should be
    // trimmed before it becomes a mailing.
    const maxBytes = 10 * 1024 * 1024;
    if (file.size > maxBytes) {
        showToast(`${file.name} is larger than 10 MB; split it or paste the addresses`, 'error');
        event.target.value = '';
        return;
    }

    const reader = new FileReader();
    reader.onload = () => {
        document.getElementById('campaign-recipients').value = String(reader.result || '');
        markCampaignDirty();
        updateRecipientSummary();
        updateMergeFields();
        showToast(`Loaded ${file.name}`, 'success');
    };
    reader.onerror = () => showToast(`Could not read ${file.name}`, 'error');
    reader.readAsText(file);
    event.target.value = '';
}

// updateRecipientSummary counts what has been pasted. It is deliberately
// labelled as a line count rather than a recipient count: the server does the
// parsing, and claiming a number here that the server then disagrees with is
// how an operator ends up trusting the wrong figure.
function updateRecipientSummary() {
    const el = document.getElementById('campaign-recipients-summary');
    if (!el) return;
    const raw = document.getElementById('campaign-recipients').value || '';
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    if (lines.length === 0) {
        el.innerHTML = '';
        return;
    }
    const hasHeader = lines.length > 1 && !lines[0].includes('@') && splitDelimited(lines[0]).length > 1;
    const count = hasHeader ? lines.length - 1 : lines.length;
    el.innerHTML = `<span class="recipients-count">${count} line${count === 1 ? '' : 's'}</span>
        <span class="field-hint">counted after saving, when the server parses the list</span>`;
}

async function loadCampaignRecipients(id) {
    try {
        const response = await fetch(`${API_BASE}/campaigns/${encodeURIComponent(id)}/recipients`);
        if (!response.ok) return;
        const data = await response.json();
        campaignState.recipientSummary = data;

        const recipients = data.recipients || [];
        // Round-trip the stored list back into the textarea so editing a saved
        // campaign starts from what was actually stored, not an empty box that
        // would clear the list on the next save.
        const header = recipients.length > 0 && recipients[0].vars
            ? ['email', ...Object.keys(recipients[0].vars)]
            : null;
        const lines = header ? [header.join(',')] : [];
        for (const r of recipients) {
            if (header) {
                lines.push([r.email, ...header.slice(1).map(k => csvEscape((r.vars || {})[k] || ''))].join(','));
            } else {
                lines.push(r.email);
            }
        }
        setField('campaign-recipients', lines.join('\n'));

        const el = document.getElementById('campaign-recipients-summary');
        el.innerHTML = `<span class="recipients-count">${data.total} recipient${data.total === 1 ? '' : 's'}</span>` +
            (data.truncated
                ? `<span class="field-hint">showing the first ${recipients.length}; saving from here would keep only those, so edit the list from its source</span>`
                : '');
        // Editing a truncated list would silently drop the rest, so the box is
        // read-only when the server did not send all of it — and, more
        // importantly, saving must not send back the visible fragment as if it
        // were the whole list. An empty recipients field means "leave the
        // stored list alone", which is the only safe thing to send here.
        campaignState.recipientsTruncated = !!data.truncated;
        document.getElementById('campaign-recipients').readOnly = !!data.truncated;
    } catch (error) {
        console.debug('recipient preview unavailable:', error);
    }
}

function csvEscape(value) {
    const s = String(value);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// ============================================================================
// Saving and sending
// ============================================================================

function collectCampaign() {
    // The rich editor is authoritative unless the source view is open, in which
    // case the source is what the operator is looking at.
    if (campaignState.editorMode === 'rich') {
        document.getElementById('campaign-html-source').value =
            document.getElementById('campaign-html').innerHTML;
    }
    const rate = document.getElementById('campaign-rate').value.trim();

    return {
        name: document.getElementById('campaign-name').value.trim(),
        from: document.getElementById('campaign-from').value.trim(),
        reply_to: document.getElementById('campaign-reply-to').value.trim(),
        subject: document.getElementById('campaign-subject').value,
        html_body: currentHTMLBody(),
        text_body: document.getElementById('campaign-text').value,
        rate_per_minute: rate === '' ? 0 : Number(rate),
        // Sending the visible fragment of a truncated list would replace the
        // stored list with it. Empty means "keep what is stored".
        recipients: campaignState.recipientsTruncated
            ? ''
            : document.getElementById('campaign-recipients').value,
    };
}

async function saveCampaign(options = {}) {
    const body = collectCampaign();
    const editing = campaignState.editingId;
    const url = editing
        ? `${API_BASE}/campaigns/${encodeURIComponent(editing)}`
        : `${API_BASE}/campaigns`;

    setCampaignStatus('Saving...', '');
    try {
        const response = await fetch(url, {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const text = await response.text();
        if (!response.ok) throw new Error(text || `HTTP ${response.status}`);

        const result = JSON.parse(text);
        campaignState.editingId = result.id;
        campaignState.editingState = result.state;
        campaignState.dirty = false;
        document.getElementById('campaign-editor-title').textContent = result.name || 'Campaign';

        // Warnings are shown rather than counted: "3 lines were skipped" with
        // no way to see which lines is a report the operator cannot act on.
        renderCampaignWarnings(result.warnings);
        setCampaignStatus(`Saved · ${result.total} recipient${result.total === 1 ? '' : 's'}`, 'success');
        if (!options.quiet) showToast('Campaign saved', 'success');
        return result;
    } catch (error) {
        console.error('Error saving campaign:', error);
        setCampaignStatus(error.message, 'error');
        if (!options.quiet) showToast(`Could not save: ${error.message}`, 'error');
        return null;
    }
}

function renderCampaignWarnings(warnings) {
    const el = document.getElementById('campaign-editor-notice');
    if (!warnings || warnings.length === 0) {
        el.innerHTML = '';
        return;
    }
    el.innerHTML = `
        <div class="warning-banner">
            <strong>Worth checking before this goes out</strong>
            <ul>${warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>
        </div>`;
}

// startCampaign saves first: starting from the form as displayed, without
// storing it, would send something that does not match what is on screen.
async function startCampaign() {
    const saved = await saveCampaign({ quiet: true });
    if (!saved) return;

    const total = saved.total || 0;
    const remaining = saved.remaining ?? total;
    const verb = saved.state === 'paused' ? 'Resume' : 'Start';
    if (!confirm(`${verb} sending to ${remaining} recipient${remaining === 1 ? '' : 's'}?\n\n` +
        `From: ${saved.from}\nSubject: ${saved.subject}\n\nThis cannot be recalled once messages are queued.`)) {
        return;
    }
    await campaignAction(saved.id, 'start');
    showCampaignEditor(false);
    refreshCampaigns();
}

async function campaignAction(id, action) {
    try {
        const response = await fetch(`${API_BASE}/campaigns/${encodeURIComponent(id)}/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
        });
        const text = await response.text();
        if (!response.ok) throw new Error(text || `HTTP ${response.status}`);
        const result = JSON.parse(text);
        campaignState.editingState = result.state;
        showToast(`Campaign ${result.state}`, 'success');
        await refreshCampaigns();
        return result;
    } catch (error) {
        console.error(`Error on campaign ${action}:`, error);
        showToast(`${action} failed: ${error.message}`, 'error');
        return null;
    }
}

async function sendCampaignTest() {
    const to = document.getElementById('campaign-test-address').value.trim();
    if (!to) {
        showToast('Enter an address to send the test to', 'error');
        return;
    }
    // Save first so the test is of what is on screen, not of an earlier draft.
    const saved = await saveCampaign({ quiet: true });
    if (!saved) return;

    try {
        const response = await fetch(`${API_BASE}/campaigns/${encodeURIComponent(saved.id)}/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to }),
        });
        const text = await response.text();
        if (!response.ok) throw new Error(text || `HTTP ${response.status}`);
        showToast(`Test sent to ${to}`, 'success');
    } catch (error) {
        console.error('Error sending test:', error);
        showToast(`Test send failed: ${error.message}`, 'error');
    }
}

async function deleteCampaign(id) {
    if (!confirm('Delete this campaign? Messages already queued will still be delivered.')) return;
    try {
        const response = await fetch(`${API_BASE}/campaigns/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);
        showToast('Campaign deleted', 'success');
        await refreshCampaigns();
    } catch (error) {
        console.error('Error deleting campaign:', error);
        showToast(`Delete failed: ${error.message}`, 'error');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initializeCampaignEditor();
    refreshMassMailerVisibility();
});

// ============================================================================
// Suppression list
// ============================================================================
//
// Addresses that permanently failed or complained. Campaigns skip them; this is
// where an operator sees who, and why, and can put an address back when it was
// suppressed in error.

async function refreshSuppression() {
    const listEl = document.getElementById('suppression-list');
    if (!listEl) return;
    const query = document.getElementById('suppression-search')?.value.trim() || '';

    try {
        const response = await fetch(`${API_BASE}/suppression?q=${encodeURIComponent(query)}`);
        if (response.status === 503) {
            listEl.innerHTML = '<div class="field-hint">The suppression list is not available on this server.</div>';
            return;
        }
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);
        const data = await response.json();

        if (!data.suppressed || data.suppressed.length === 0) {
            listEl.innerHTML = query
                ? `<div class="field-hint">No suppressed address matches ${escapeHtml(query)}.</div>`
                : '<div class="field-hint">Nothing is suppressed. Addresses appear here when a message to them fails permanently.</div>';
            return;
        }

        listEl.innerHTML = `
            <table class="messages-table trace-results">
                <thead><tr><th>Address</th><th>Why</th><th>Reason</th><th>When</th><th></th></tr></thead>
                <tbody>
                    ${data.suppressed.map(e => `
                        <tr>
                            <td>${escapeHtml(e.address)}</td>
                            <td><span class="campaign-state ${e.source === 'complaint' ? 'failed' : 'paused'}">${escapeHtml(e.source)}</span></td>
                            <td class="trace-detail-text">${escapeHtml(e.reason || '—')}</td>
                            <td>${escapeHtml(formatTimeAgo(e.created_at))}</td>
                            <td><button class="btn btn-secondary btn-sm"
                                onclick="unsuppressAddress('${escapeJsArg(e.address)}')">Allow again</button></td>
                        </tr>`).join('')}
                </tbody>
            </table>
            <div class="field-hint">${data.total} address${data.total === 1 ? '' : 'es'} suppressed.</div>`;
    } catch (error) {
        console.error('Suppression list failed:', error);
        listEl.innerHTML = `<div class="error-message">Could not load the list: ${escapeHtml(error.message)}</div>`;
    }
}

async function suppressAddress() {
    const input = document.getElementById('suppression-add');
    const address = input.value.trim();
    if (!address) return;

    try {
        const response = await fetch(`${API_BASE}/suppression`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, reason: 'added from the dashboard' }),
        });
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);
        input.value = '';
        showToast(`${address} will not be mailed`, 'success');
        await refreshSuppression();
    } catch (error) {
        showToast(`Could not suppress: ${error.message}`, 'error');
    }
}

async function unsuppressAddress(address) {
    // Confirmed because it is the one action here that starts mail flowing
    // again, and the address is on the list for a reason someone recorded.
    if (!confirm(`Allow mail to ${address} again?\n\nIt was suppressed because delivery failed permanently or the recipient complained.`)) return;

    try {
        const response = await fetch(`${API_BASE}/suppression/${encodeURIComponent(address)}`, { method: 'DELETE' });
        if (!response.ok) throw new Error(await response.text() || `HTTP ${response.status}`);
        showToast(`${address} can be mailed again`, 'success');
        await refreshSuppression();
    } catch (error) {
        showToast(`Could not remove: ${error.message}`, 'error');
    }
}

// importDirectoryRecipients loads the account directory into the recipient box.
//
// The addresses are put in the textarea rather than attached to the campaign as
// "everyone", so the operator sees exactly who is about to be mailed and can
// edit the list. A campaign that resolves "everyone" when it starts sends to a
// different set of people than the one that was reviewed, and there is no way
// to check it beforehand.
async function importDirectoryRecipients() {
    const button = document.getElementById('campaign-import-directory');
    const box = document.getElementById('campaign-recipients');
    if (!box) return;

    const original = button ? button.textContent : '';
    if (button) { button.disabled = true; button.textContent = 'Importing...'; }

    try {
        const response = await fetch(`${API_BASE}/directory/recipients`);
        const data = await response.json().catch(() => ({}));

        if (!data.available) {
            // Not an error state: plenty of deployments have no directory.
            showToast(data.reason || 'No account directory is available', 'warning');
            return;
        }

        const recipients = data.recipients || [];
        if (recipients.length === 0) {
            showToast('The directory returned no usable addresses', 'warning');
            return;
        }

        // Emitted as CSV with the merge variables the directory supplied, so
        // the existing parser handles it and the operator can see the columns.
        const hasVars = recipients.some(r => r.vars && Object.keys(r.vars).length > 0);
        let text;
        if (hasVars) {
            const columns = ['email', ...new Set(recipients.flatMap(r => Object.keys(r.vars || {})))];
            const rows = recipients.map(r => columns.map(c =>
                csvCell(c === 'email' ? r.email : ((r.vars || {})[c] || ''))).join(','));
            text = [columns.join(','), ...rows].join('\n');
        } else {
            text = recipients.map(r => r.email).join('\n');
        }

        // Appended rather than replacing: an operator who has already pasted a
        // list should not lose it to a mis-click.
        const existing = box.value.trim();
        box.value = existing ? `${existing}\n${text}` : text;
        box.dispatchEvent(new Event('input', { bubbles: true }));

        let message = `Imported ${recipients.length} recipient${recipients.length === 1 ? '' : 's'}`;
        if (data.truncated) message += ' (the directory has more than were imported)';
        showToast(message, data.truncated ? 'warning' : 'success');

        // Anything the directory could not be used for is shown rather than
        // dropped, so the count difference is explainable.
        if (data.skipped && data.skipped.length > 0) {
            const summary = document.getElementById('campaign-recipients-summary');
            if (summary) {
                summary.innerHTML = `<div class="field-hint">Skipped ${data.skipped.length} directory
                    account${data.skipped.length === 1 ? '' : 's'}: ${escapeHtml(data.skipped.slice(0, 10).join('; '))}${
                    data.skipped.length > 10 ? ' and more' : ''}</div>`;
            }
        }
    } catch (error) {
        showToast(`Directory import failed: ${error.message}`, 'error');
    } finally {
        if (button) { button.disabled = false; button.textContent = original; }
    }
}

// csvCell quotes a value that would otherwise break the column layout.
function csvCell(value) {
    const text = String(value === undefined || value === null ? '' : value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
