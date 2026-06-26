const API = {
    base: '/api',

    async _request(path, body) {
        const res = await fetch(`${this.base}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || `Request failed with status ${res.status}`);
        }

        return data;
    },

    async analyzeSecurity(code, language) {
        return this._request('/analyze/security', { code, language });
    },

    async findBugs(code, language) {
        return this._request('/analyze/bugs', { code, language });
    },

    async translateCode(code, language) {
        return this._request('/translate', { code, language });
    },

    async fixCode(code, language) {
        return this._request('/fix', { code, language });
    },

    async healthCheck() {
        try {
            const res = await fetch(`${this.base}/health`);
            return await res.json();
        } catch {
            return { status: 'error', llm: 'unreachable', llm_enabled: false };
        }
    }
};
