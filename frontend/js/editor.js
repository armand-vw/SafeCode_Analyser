const Editor = {
    input: null,
    lineNumbers: null,

    init() {
        this.input = document.getElementById('code-input');
        this.lineNumbers = document.getElementById('line-numbers');

        this.input.addEventListener('input', () => this.update());
        this.input.addEventListener('scroll', () => this.syncScroll());
        this.input.addEventListener('keydown', (e) => this.handleKeydown(e));

        this.update();
    },

    update() {
        const text = this.input.value;
        const lines = text.split('\n');
        const lineCount = lines.length;

        let nums = '';
        for (let i = 1; i <= lineCount; i++) {
            nums += i + '\n';
        }
        this.lineNumbers.textContent = nums;

        document.getElementById('line-count').textContent = `${lineCount} line${lineCount !== 1 ? 's' : ''}`;
        document.getElementById('char-count').textContent = `${text.length} char${text.length !== 1 ? 's' : ''}`;
    },

    syncScroll() {
        this.lineNumbers.scrollTop = this.input.scrollTop;
    },

    handleKeydown(e) {
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = this.input.selectionStart;
            const end = this.input.selectionEnd;
            this.input.value = this.input.value.substring(0, start) + '    ' + this.input.value.substring(end);
            this.input.selectionStart = this.input.selectionEnd = start + 4;
            this.update();
        }
    },

    getCode() {
        return this.input.value;
    },

    setCode(code) {
        this.input.value = code;
        this.update();
    },

    getLanguage() {
        return document.getElementById('lang-select').value;
    },

    clear() {
        this.input.value = '';
        this.update();
    }
};
