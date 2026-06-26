const App = {
    init() {
        Editor.init();
        this.bindButtons();
        this.checkHealth();
        this.initSettings();
    },

    bindButtons() {
        document.getElementById('btn-security').addEventListener('click', () => this.runSecurityAnalysis());
        document.getElementById('btn-bugs').addEventListener('click', () => this.runBugAnalysis());
        document.getElementById('btn-translate').addEventListener('click', () => this.runTranslation());
        document.getElementById('btn-fix').addEventListener('click', () => this.runFix());
        document.getElementById('btn-clear').addEventListener('click', () => this.clearResults());
        document.getElementById('btn-close-results').addEventListener('click', () => this.clearResults());
        document.getElementById('settings-btn').addEventListener('click', () => this.toggleSettings());
        document.getElementById('btn-close-settings').addEventListener('click', () => this.toggleSettings());
        document.getElementById('setting-llm-enabled').addEventListener('change', (e) => {
            document.getElementById('setting-ollama-host').disabled = !e.target.checked;
            document.getElementById('setting-ollama-model').disabled = !e.target.checked;
        });
    },

    showLoading() {
        document.getElementById('loading-overlay').classList.remove('hidden');
        document.getElementById('results-container').classList.remove('hidden');
    },

    hideLoading() {
        document.getElementById('loading-overlay').classList.add('hidden');
    },

    disableButtons() {
        document.querySelectorAll('.action-btn').forEach(b => b.disabled = true);
    },

    enableButtons() {
        document.querySelectorAll('.action-btn').forEach(b => b.disabled = false);
    },

    clearResults() {
        document.getElementById('results-container').classList.add('hidden');
        document.getElementById('results-content').innerHTML = '';
        document.getElementById('results-summary').innerHTML = '';
    },

    async runSecurityAnalysis() {
        const code = Editor.getCode();
        if (!code.trim()) {
            this.showError('Please enter some code to analyse.');
            return;
        }

        this.showLoading();
        this.disableButtons();
        document.getElementById('results-content').innerHTML = '';

        try {
            const result = await API.analyzeSecurity(code, Editor.getLanguage());
            this.renderFindings(result, 'Security Analysis');
        } catch (err) {
            this.showError(err.message);
        } finally {
            this.hideLoading();
            this.enableButtons();
        }
    },

    async runBugAnalysis() {
        const code = Editor.getCode();
        if (!code.trim()) {
            this.showError('Please enter some code to analyse.');
            return;
        }

        this.showLoading();
        this.disableButtons();
        document.getElementById('results-content').innerHTML = '';

        try {
            const result = await API.findBugs(code, Editor.getLanguage());
            this.renderFindings(result, 'Bug Analysis');
        } catch (err) {
            this.showError(err.message);
        } finally {
            this.hideLoading();
            this.enableButtons();
        }
    },

    async runTranslation() {
        const code = Editor.getCode();
        if (!code.trim()) {
            this.showError('Please enter some code to translate.');
            return;
        }

        this.showLoading();
        this.disableButtons();
        document.getElementById('results-content').innerHTML = '';

        try {
            const result = await API.translateCode(code, Editor.getLanguage());
            this.renderTranslation(result);
        } catch (err) {
            this.showError(err.message);
        } finally {
            this.hideLoading();
            this.enableButtons();
        }
    },

    async runFix() {
        const code = Editor.getCode();
        if (!code.trim()) {
            this.showError('Please enter some code to fix.');
            return;
        }

        this.showLoading();
        this.disableButtons();
        document.getElementById('results-content').innerHTML = '';

        try {
            const result = await API.fixCode(code, Editor.getLanguage());
            this.renderFix(result);
        } catch (err) {
            this.showError(err.message);
        } finally {
            this.hideLoading();
            this.enableButtons();
        }
    },

    renderFindings(result, title) {
        const container = document.getElementById('results-container');
        const summary = document.getElementById('results-summary');
        const content = document.getElementById('results-content');

        container.classList.remove('hidden');

        let summaryHtml = '';
        if (result.critical_count > 0) summaryHtml += `<span class="summary-badge critical">${result.critical_count} Critical</span>`;
        if (result.high_count > 0) summaryHtml += `<span class="summary-badge high">${result.high_count} High</span>`;
        if (result.medium_count > 0) summaryHtml += `<span class="summary-badge medium">${result.medium_count} Medium</span>`;
        if (result.low_count > 0) summaryHtml += `<span class="summary-badge low">${result.low_count} Low</span>`;

        const titleEl = container.querySelector('.results-header h2');
        titleEl.textContent = `${title} — ${result.language}`;
        summary.innerHTML = summaryHtml + `<span style="color: var(--text-muted); font-size: 12px;">(${result.total_count} total)</span>`;

        if (result.findings.length === 0) {
            content.innerHTML = `
                <div class="empty-state">
                    <div class="icon">&#9989;</div>
                    <p>No issues found. The code looks clean!</p>
                </div>`;
            return;
        }

        let html = '';
        for (const f of result.findings) {
            html += `
                <div class="finding ${f.severity}">
                    <div class="finding-header">
                        <span class="finding-severity ${f.severity}">${f.severity}</span>
                        <span class="finding-rule">${this.escapeHtml(f.rule_id)}</span>
                        ${f.line ? `<span class="finding-line">Line ${f.line}</span>` : ''}
                    </div>
                    <div class="finding-message">${this.escapeHtml(f.message)}</div>
                    ${f.snippet ? `<div class="finding-snippet">${this.escapeHtml(f.snippet)}</div>` : ''}
                    ${f.recommendation ? `<div class="finding-recommendation">&#128161; ${this.escapeHtml(f.recommendation)}</div>` : ''}
                </div>`;
        }
        content.innerHTML = html;
    },

    renderTranslation(result) {
        const container = document.getElementById('results-container');
        const content = document.getElementById('results-content');
        const summary = document.getElementById('results-summary');

        container.classList.remove('hidden');
        const titleEl = container.querySelector('.results-header h2');
        titleEl.textContent = `Code Translation — ${result.language}`;
        summary.innerHTML = result.llm_used
            ? '<span class="summary-badge low">LLM Powered</span>'
            : '';

        if (result.error) {
            content.innerHTML = `<div class="error-message">${this.escapeHtml(result.error)}</div>`;
            return;
        }

        content.innerHTML = `<div class="translation-output">${this.escapeHtml(result.plain_english)}</div>`;
    },

    renderFix(result) {
        const container = document.getElementById('results-container');
        const content = document.getElementById('results-content');
        const summary = document.getElementById('results-summary');

        container.classList.remove('hidden');
        const titleEl = container.querySelector('.results-header h2');
        titleEl.textContent = `Fixed Code — ${result.language}`;
        summary.innerHTML = result.llm_used
            ? '<span class="summary-badge low">LLM Powered</span>'
            : '';

        if (result.error) {
            content.innerHTML = `<div class="error-message">${this.escapeHtml(result.error)}</div>`;
            return;
        }

        content.innerHTML = `
            <p style="margin-bottom: 12px; color: var(--text-secondary);">Here is the corrected code:</p>
            <div class="fix-output">${this.escapeHtml(result.fixed_code)}</div>`;
    },

    showError(msg) {
        const container = document.getElementById('results-container');
        const content = document.getElementById('results-content');
        const summary = document.getElementById('results-summary');

        container.classList.remove('hidden');
        summary.innerHTML = '';
        content.innerHTML = `<div class="error-message">${this.escapeHtml(msg)}</div>`;
    },

    async checkHealth() {
        try {
            const health = await API.healthCheck();
            const dot = document.getElementById('llm-status');
            if (health.llm_enabled && health.llm === 'connected') {
                dot.className = 'status-dot connected';
                dot.title = 'LLM: Connected';
            } else if (health.llm_enabled) {
                dot.className = 'status-dot disconnected';
                dot.title = 'LLM: Disconnected — start Ollama';
            } else {
                dot.className = 'status-dot';
                dot.title = 'LLM: Disabled';
            }
        } catch {
            document.getElementById('llm-status').className = 'status-dot disconnected';
        }
    },

    initSettings() {
        document.getElementById('setting-llm-enabled').addEventListener('change', (e) => {
            document.getElementById('setting-ollama-host').disabled = !e.target.checked;
            document.getElementById('setting-ollama-model').disabled = !e.target.checked;
        });
    },

    toggleSettings() {
        document.getElementById('settings-modal').classList.toggle('hidden');
        this.checkHealth();
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());
