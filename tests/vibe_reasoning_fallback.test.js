const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadTestExports(overrides = {}) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
    const context = {
        AbortController,
        AbortSignal,
        console,
        clearTimeout,
        fetch: async () => { throw new Error('fetch is not available in this test'); },
        localStorage: overrides.localStorage || {
            getItem: () => null,
            setItem: () => {},
            removeItem: () => {}
        },
        document: {
            addEventListener: () => {}
        },
        setTimeout,
        window: {}
    };

    vm.runInNewContext(`${source}\nthis.__testExports = { AppState, AdminManager, VibeCodingManager, LLMService, MarkdownRenderer, DEFAULT_VIBE_CODER_PROMPT, DEFAULT_VIBE_REVIEWER_PROMPT, DEFAULT_PROMPTS, DEFAULT_PROMPT_MATRIX_VERSION, DEFAULT_SUPPORT_SYSTEM_PROMPT };`, context);
    return context.__testExports;
}

function readVibeLanguageOptions() {
    const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
    const select = html.match(/<select id="vibe-lang">([\s\S]*?)<\/select>/);
    assert.ok(select, 'vibe language select not found');
    return [...select[1].matchAll(/<option value="([^"]+)"/g)].map(m => m[1]);
}

function readIndexHtml() {
    return fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
}

function readStylesCss() {
    return fs.readFileSync(path.join(__dirname, '..', 'styles.css'), 'utf8');
}

test('vibecode uses content when an LLM result has normal content', () => {
    const { VibeCodingManager } = loadTestExports();

    assert.equal(
        VibeCodingManager._getLLMVisibleText({ content: 'visible answer', reasoning: 'hidden reasoning' }),
        'visible answer'
    );
});

test('vibecode falls back to reasoning_content when content is empty', () => {
    const { VibeCodingManager } = loadTestExports();

    assert.equal(
        VibeCodingManager._getLLMVisibleText({ content: '', reasoning: 'reasoning-only answer' }),
        'reasoning-only answer'
    );
});

test('vibecode copy widget uses final code for coder and full review text for reviewer', () => {
    const { VibeCodingManager } = loadTestExports();

    assert.equal(
        VibeCodingManager._getIterationCopyText(
            'coder',
            'Пояснение\n```python\nprint("ok")\n```',
            'print("ok")'
        ),
        'print("ok")'
    );
    assert.equal(
        VibeCodingManager._getIterationCopyText(
            'reviewer',
            'ОЦЕНКА: 8/10\nКод рабочий, но нет обработки ошибок.',
            'ignored'
        ),
        'ОЦЕНКА: 8/10\nКод рабочий, но нет обработки ошибок.'
    );
});

test('vibecode auto-collapse targets only previous iterations', () => {
    const { VibeCodingManager } = loadTestExports();

    assert.equal(VibeCodingManager._shouldAutoCollapseIteration('1', 2), true);
    assert.equal(VibeCodingManager._shouldAutoCollapseIteration('2', 2), false);
    assert.equal(VibeCodingManager._shouldAutoCollapseIteration('3', 2), false);
    assert.equal(VibeCodingManager._shouldAutoCollapseIteration('', 2), false);
});

test('vibecode adds Jupyter guidance only for Python coder and reviewer prompts', () => {
    const { VibeCodingManager, DEFAULT_VIBE_CODER_PROMPT } = loadTestExports();

    assert.doesNotMatch(DEFAULT_VIBE_CODER_PROMPT, /Jupyter Notebook|argparse/i);

    const coderPython = VibeCodingManager._buildVibeLanguageInstruction('coder', 'python', 'Python');
    const reviewerPython = VibeCodingManager._buildVibeLanguageInstruction('reviewer', 'python', 'Python');
    const coderJs = VibeCodingManager._buildVibeLanguageInstruction('coder', 'javascript', 'JavaScript');
    const reviewerJs = VibeCodingManager._buildVibeLanguageInstruction('reviewer', 'javascript', 'JavaScript');

    assert.match(coderPython, /Jupyter Notebook/i);
    assert.match(coderPython, /argparse/i);
    assert.match(reviewerPython, /Jupyter Notebook/i);
    assert.match(reviewerPython, /argparse/i);
    assert.doesNotMatch(coderJs, /Jupyter Notebook|argparse/i);
    assert.doesNotMatch(reviewerJs, /Jupyter Notebook|argparse/i);
});

test('vibecode default role prompts are English and lock human text to Russian', () => {
    const { DEFAULT_VIBE_CODER_PROMPT, DEFAULT_VIBE_REVIEWER_PROMPT } = loadTestExports();

    assert.match(DEFAULT_VIBE_CODER_PROMPT, /You are a Principal Engineer/i);
    assert.match(DEFAULT_VIBE_CODER_PROMPT, /comments and user-facing explanatory text in Russian/i);
    assert.match(DEFAULT_VIBE_CODER_PROMPT, /code identifiers.*English/i);
    assert.match(DEFAULT_VIBE_CODER_PROMPT, /Do not use Chinese/i);
    assert.doesNotMatch(DEFAULT_VIBE_CODER_PROMPT, /[А-Яа-яЁё]/);

    assert.match(DEFAULT_VIBE_REVIEWER_PROMPT, /You are a strict Senior Code Reviewer/i);
    assert.match(DEFAULT_VIBE_REVIEWER_PROMPT, /Write the review in Russian/i);
    assert.match(DEFAULT_VIBE_REVIEWER_PROMPT, /Do not use Chinese/i);
    assert.doesNotMatch(DEFAULT_VIBE_REVIEWER_PROMPT, /[А-Яа-яЁё]/);
});

test('vibecode language selector exposes only Python and JavaScript', () => {
    assert.deepEqual(readVibeLanguageOptions(), ['python', 'javascript']);
});

test('vibecode task placeholder uses a clear CSV preview example', () => {
    const html = readIndexHtml();
    const match = html.match(/<textarea id="vibe-task"[^>]*placeholder="([^"]+)"/);

    assert.ok(match, 'vibe task placeholder not found');
    assert.match(match[1], /CSV/i);
    assert.match(match[1], /первые 5 строк/i);
    assert.match(match[1], /последние 5 строк/i);
    assert.match(match[1], /лист 1/i);
    assert.doesNotMatch(match[1], /JSON-логов|argparse/i);
});

test('vibecode long iteration bodies remain scrollable and clear of support widget', () => {
    const css = readStylesCss();
    const pageRule = css.match(/#page-vibecode\s*\{([\s\S]*?)\}/);
    const bodyRule = css.match(/(?:^|\n)\.vibe-iter-body\s*\{([\s\S]*?)\}/);

    assert.ok(pageRule, '#page-vibecode rule not found');
    assert.ok(bodyRule, '.vibe-iter-body rule not found');
    assert.match(pageRule[1], /padding-bottom\s*:\s*(?:9[0-9]|1[0-9]{2})px/);
    assert.match(pageRule[1], /scroll-padding-bottom\s*:/);
    assert.match(bodyRule[1], /max-height\s*:/);
    assert.match(bodyRule[1], /overflow-y\s*:\s*auto/);
});

test('static assets use cache-busting query strings for file URL reloads', () => {
    const html = readIndexHtml();

    assert.match(html, /href="styles\.css\?v=[^"]+"/);
    assert.match(html, /src="app\.js\?v=[^"]+"/);
});

test('help page documents current vibecoding and prompt behavior', () => {
    const html = readIndexHtml();

    assert.match(html, /data-scroll="help-vibecode"/);
    assert.match(html, /id="help-vibecode"/);
    assert.match(html, /Кодер/);
    assert.match(html, /Ревьюер/);
    assert.match(html, /одну и ту же модель/);
    assert.match(html, /LM Studio \/ Ollama \/ Xinference/);
    assert.match(html, /11 встроенными промптами/);
    assert.match(html, /английском/i);
    assert.match(html, /ответ на русском/i);
    assert.doesNotMatch(html, /поставляется с 8 предустановленными промптами/);
    assert.doesNotMatch(html, /Итоговая оценка безопасности X\/10/);
    assert.doesNotMatch(html, /Выдаёт оценку 1-10/);
    assert.doesNotMatch(html, /оценкой соответствия/);
    assert.doesNotMatch(html, /проверяются 10 категорий/);
    assert.doesNotMatch(html, /Что будет проверено \(8 категорий\)/);
    assert.doesNotMatch(html, /стоят ~4x дороже/);
});

test('support chat system prompt documents current app and vibecoding workflow', () => {
    const { DEFAULT_SUPPORT_SYSTEM_PROMPT } = loadTestExports();

    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /AI сканер/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /нижн.*прав|прав.*нижн/i);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /Вайбкодинг/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /Кодер/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /Ревьюер/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /3 итерац|тр[её]х итерац/i);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /ОЦЕНКА: N\/10/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /LM Studio \/ Ollama \/ Xinference/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /Python/);
    assert.match(DEFAULT_SUPPORT_SYSTEM_PROMPT, /JavaScript/);
});

test('admin settings migrate the legacy default support prompt to the current one', () => {
    const storage = new Map();
    storage.set('codesentinel_admin_settings', JSON.stringify({
        mode: 'cloud',
        cloudApiKey: '',
        cloudModel: 'deepseek-chat',
        cloudUrl: 'https://api.deepseek.com',
        localProvider: 'xinference',
        localUrl: 'http://127.0.0.1:9997',
        localModel: '',
        temperature: 0.2,
        maxTokens: 768,
        contextWindow: 4096,
        systemPrompt: 'Ты — виртуальный ассистент первой линии технической поддержки группы УПФЭ. Экономические эффекты.',
        welcomeMessage: 'old welcome'
    }));

    const { AdminManager, DEFAULT_SUPPORT_SYSTEM_PROMPT } = loadTestExports({
        localStorage: {
            getItem: key => storage.get(key) || null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key)
        }
    });
    const admin = new AdminManager({});
    const persisted = JSON.parse(storage.get('codesentinel_admin_settings'));

    assert.equal(admin.settings.systemPrompt, DEFAULT_SUPPORT_SYSTEM_PROMPT);
    assert.equal(persisted.systemPrompt, DEFAULT_SUPPORT_SYSTEM_PROMPT);
    assert.equal(storage.get('codesentinel_admin_support_prompt_version'), '2');
});

test('default prompt matrix uses English system instructions with Russian output policy', () => {
    const { DEFAULT_PROMPTS } = loadTestExports();

    assert.ok(DEFAULT_PROMPTS.length >= 10);
    for (const prompt of DEFAULT_PROMPTS) {
        assert.match(prompt.systemPrompt, /Write the entire answer in Russian/i, prompt.id);
        assert.match(prompt.systemPrompt, /code identifiers.*English/i, prompt.id);
        assert.match(prompt.systemPrompt, /Do not use Chinese/i, prompt.id);
        assert.doesNotMatch(prompt.systemPrompt, /Найди|Проведи|Сформируй|Анализируй|Рефакторинг кода|Оцени код|ЗАПРЕТЫ|ИСКАТЬ/i, prompt.id);
    }
});

test('default prompt matrix migration refreshes built-in prompts and preserves instruction files', () => {
    const storage = new Map();
    const oldPrompt = {
        id: 'infosec_vuln',
        role: 'infosec',
        actionName: 'Анализ уязвимостей',
        systemPrompt: 'Найди уязвимости безопасности в предоставленном коде.',
        contextContent: 'Internal policy v1',
        contextFile: 'policy.md'
    };
    const customPrompt = {
        id: 'custom_prompt',
        role: 'developer',
        actionName: 'Custom',
        systemPrompt: 'Custom prompt stays untouched',
        contextContent: '',
        contextFile: ''
    };
    storage.set('codesentinel_prompts', JSON.stringify([oldPrompt, customPrompt]));

    const { AppState, DEFAULT_PROMPT_MATRIX_VERSION } = loadTestExports({
        localStorage: {
            getItem: key => storage.get(key) || null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key)
        }
    });

    const state = new AppState();
    const migrated = state.prompts.find(prompt => prompt.id === 'infosec_vuln');
    const custom = state.prompts.find(prompt => prompt.id === 'custom_prompt');

    assert.match(migrated.systemPrompt, /Write the entire answer in Russian/i);
    assert.match(migrated.systemPrompt, /code identifiers.*English/i);
    assert.doesNotMatch(migrated.systemPrompt, /Найди уязвимости/i);
    assert.equal(migrated.contextContent, 'Internal policy v1');
    assert.equal(migrated.contextFile, 'policy.md');
    assert.equal(custom.systemPrompt, 'Custom prompt stays untouched');
    assert.equal(storage.get('codesentinel_prompt_matrix_version'), String(DEFAULT_PROMPT_MATRIX_VERSION));
});

test('vibecode builds the final system prompt with visible language additions', () => {
    const { VibeCodingManager } = loadTestExports();

    const coderPrompt = VibeCodingManager._buildFinalSystemPrompt('coder', 'BASE CODER', 'python', 'Python');
    const reviewerPrompt = VibeCodingManager._buildFinalSystemPrompt('reviewer', 'BASE REVIEWER', 'javascript', 'JavaScript');

    assert.match(coderPrompt, /^BASE CODER/);
    assert.match(coderPrompt, /Jupyter Notebook/i);
    assert.match(coderPrompt, /plain prose without #/i);
    assert.match(coderPrompt, /Do not use Chinese/i);
    assert.doesNotMatch(coderPrompt, /ОЦЕНКА: N\/10/);

    assert.match(reviewerPrompt, /^BASE REVIEWER/);
    assert.match(reviewerPrompt, /Promise/i);
    assert.match(reviewerPrompt, /review in Russian/i);
    assert.match(reviewerPrompt, /ОЦЕНКА: N\/10/);
});

test('vibecode auto-addition summaries are English like the final prompt blocks', () => {
    const { VibeCodingManager } = loadTestExports();

    const summaries = [
        VibeCodingManager._getLanguageInstructionSummary('coder', 'python', 'Python'),
        VibeCodingManager._getLanguageInstructionSummary('reviewer', 'python', 'Python'),
        VibeCodingManager._getLanguageInstructionSummary('coder', 'javascript', 'JavaScript'),
        VibeCodingManager._getLanguageInstructionSummary('reviewer', 'javascript', 'JavaScript'),
        VibeCodingManager._getLanguageInstructionSummary('coder', 'python', 'Python', 'CUSTOM')
    ];

    for (const summary of summaries) {
        assert.doesNotMatch(summary, /[А-Яа-яЁё]/, summary);
    }
    assert.match(summaries[0], /Jupyter/i);
    assert.match(summaries[2], /modern JS/i);
    assert.match(summaries[4], /custom auto-addition/i);
});

test('vibecode can replace default language additions with a custom one', () => {
    const { VibeCodingManager } = loadTestExports();

    const coderPrompt = VibeCodingManager._buildFinalSystemPrompt(
        'coder',
        'BASE CODER',
        'python',
        'Python',
        'CUSTOM NOTE: write a compact notebook cell.'
    );
    const reviewerPrompt = VibeCodingManager._buildFinalSystemPrompt(
        'reviewer',
        'BASE REVIEWER',
        'javascript',
        'JavaScript',
        'CUSTOM REVIEW NOTE: focus on browser lifecycle.'
    );

    assert.match(coderPrompt, /CUSTOM NOTE/);
    assert.doesNotMatch(coderPrompt, /Jupyter Notebook/i);
    assert.match(reviewerPrompt, /CUSTOM REVIEW NOTE/);
    assert.match(reviewerPrompt, /ОЦЕНКА: N\/10/);
    assert.doesNotMatch(reviewerPrompt, /Promise/i);
});

test('vibecode page exposes final prompt preview controls', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

    assert.match(html, /id="vibe-coder-auto-summary"/);
    assert.match(html, /id="vibe-reviewer-auto-summary"/);
    assert.match(html, /id="vibe-coder-final-prompt"/);
    assert.match(html, /id="vibe-reviewer-final-prompt"/);
    assert.match(html, /data-vibe-final-toggle="coder"/);
    assert.match(html, /data-vibe-final-toggle="reviewer"/);
    assert.match(html, /id="vibe-coder-auto-editor"/);
    assert.match(html, /id="vibe-reviewer-auto-editor"/);
    assert.match(html, /data-vibe-auto-toggle="coder"/);
    assert.match(html, /data-vibe-auto-reset="reviewer"/);
});

test('python vibecode prompts forbid plain text lines inside notebook code', () => {
    const { VibeCodingManager } = loadTestExports();

    const coderPython = VibeCodingManager._buildVibeLanguageInstruction('coder', 'python', 'Python');
    const reviewerPython = VibeCodingManager._buildVibeLanguageInstruction('reviewer', 'python', 'Python');

    assert.match(coderPython, /plain prose without #/i);
    assert.match(coderPython, /SyntaxError/i);
    assert.match(reviewerPython, /plain prose without #/i);
    assert.match(reviewerPython, /SyntaxError/i);
});

test('vibecode adds JavaScript-specific guidance for coder and reviewer prompts', () => {
    const { VibeCodingManager } = loadTestExports();

    const coderJs = VibeCodingManager._buildVibeLanguageInstruction('coder', 'javascript', 'JavaScript');
    const reviewerJs = VibeCodingManager._buildVibeLanguageInstruction('reviewer', 'javascript', 'JavaScript');
    const coderAbap = VibeCodingManager._buildVibeLanguageInstruction('coder', 'abap', 'ABAP');

    assert.match(coderJs, /modern JavaScript/i);
    assert.match(coderJs, /const\/let/i);
    assert.match(coderJs, /async\/await/i);
    assert.match(coderJs, /browser|Node/i);
    assert.match(reviewerJs, /DOM/i);
    assert.match(reviewerJs, /XSS/i);
    assert.match(reviewerJs, /Promise/i);
    assert.match(reviewerJs, /event listener/i);
    assert.doesNotMatch(coderAbap, /modern JavaScript|async\/await|XSS/i);
});

test('coder output renders as a compact code cell instead of markdown', () => {
    const { VibeCodingManager } = loadTestExports();

    const html = VibeCodingManager._renderCoderCellHtml(`\`\`\`python
import pandas as pd

# Константы в начале ячейки
FILE_PATH = "data.xlsx"
\`\`\``);

    assert.match(html, /<pre class="vibe-code-cell"><code>/);
    assert.match(html, /# Константы в начале ячейки/);
    assert.doesNotMatch(html, /<h1>|<h2>|<p>|```python/);
});

test('reviewer markdown code blocks keep their own copy button', () => {
    const { MarkdownRenderer, VibeCodingManager } = loadTestExports();

    const reviewerPython = VibeCodingManager._buildVibeLanguageInstruction('reviewer', 'python', 'Python');
    const html = MarkdownRenderer.render(`Исправленный фрагмент:
\`\`\`python
print("ok")
\`\`\``);

    assert.match(reviewerPython, /fenced code block/i);
    assert.match(reviewerPython, /copied separately/i);
    assert.match(html, /btn-copy-code/);
    assert.match(html, /<code class="lang-python">print\(&quot;ok&quot;\)<\/code>/);
});

test('markdown renderer keeps an unclosed streaming code fence as code', () => {
    const { MarkdownRenderer } = loadTestExports();

    const html = MarkdownRenderer.render(`Исправленный код:
\`\`\`python
# Настройки
FILE_NAME = "example.xlsx"`);

    assert.match(html, /btn-copy-code/);
    assert.match(html, /<code class="lang-python"># Настройки/);
    assert.doesNotMatch(html, /<h1>Настройки<\/h1>/);
    assert.doesNotMatch(html, /```python/);
});

test('vibecode can prepend a recovered score to a reasoning-only review', () => {
    const { VibeCodingManager } = loadTestExports();

    const review = VibeCodingManager._createRecoveredReview(
        'ОЦЕНКА: 7/10\nдальше ничего не нужно',
        'Подробное ревью без первой строки оценки.'
    );

    assert.match(review, /^ОЦЕНКА: 7\/10/);
    assert.match(review, /Подробное ревью без первой строки оценки\./);
});

test('vibecode parses score from a reviewer JSON object', () => {
    const { VibeCodingManager } = loadTestExports();
    const manager = Object.create(VibeCodingManager.prototype);

    assert.equal(manager._parseScore('{"score":8,"review":"Есть замечания по обработке ошибок."}'), 8);
    assert.equal(manager._parseScore('```json\n{"оценка":"6/10","замечания":["нет тестов"]}\n```'), 6);
});

test('vibecode can recover score when the recovery model returns JSON', () => {
    const { VibeCodingManager } = loadTestExports();

    const review = VibeCodingManager._createRecoveredReview(
        '{"score": 5, "reason": "существенные проблемы"}',
        'Ревьюер написал замечания, но не вернул первую строку оценки.'
    );

    assert.match(review, /^ОЦЕНКА: 5\/10/);
});

test('local provider URL builder accepts base URLs with or without /v1', () => {
    const { LLMService } = loadTestExports();

    assert.equal(LLMService.inferLocalProviderFromUrl('http://127.0.0.1:1234'), 'lmstudio');
    assert.equal(LLMService.inferLocalProviderFromUrl('http://localhost:11434'), 'ollama');
    assert.equal(LLMService.normalizeLocalBaseUrl('http://localhost:11434/api', 'ollama'), 'http://localhost:11434');
    assert.equal(
        LLMService.buildLocalChatUrl({ localProvider: 'lmstudio', localUrl: 'http://localhost:1234/v1/' }),
        'http://localhost:1234/v1/chat/completions'
    );
    assert.equal(
        LLMService.buildLocalChatUrl({ localProvider: 'ollama', localUrl: 'http://localhost:11434' }),
        'http://localhost:11434/v1/chat/completions'
    );
    assert.equal(
        LLMService.buildLocalChatUrl({ localProvider: 'xinference', localUrl: 'http://127.0.0.1:9997/v1' }),
        'http://127.0.0.1:9997/v1/chat/completions'
    );
});

test('local provider model parser supports Ollama tags and OpenAI-compatible lists', () => {
    const { LLMService } = loadTestExports();

    assert.deepEqual(
        JSON.parse(JSON.stringify(LLMService.parseLocalModels({
            models: [{
                name: 'qwen2.5-coder:14b',
                details: { family: 'qwen2', parameter_size: '14B' }
            }]
        }, 'ollama'))),
        [{
            id: 'qwen2.5-coder:14b',
            name: 'qwen2.5-coder:14b',
            owned_by: 'qwen2 14B',
            contextLength: 0
        }]
    );

    assert.deepEqual(
        JSON.parse(JSON.stringify(LLMService.parseLocalModels({
            data: [{ id: 'qwen/qwen3-coder-next', owned_by: 'lmstudio', context_length: 32768 }]
        }, 'lmstudio'))),
        [{
            id: 'qwen/qwen3-coder-next',
            name: 'qwen/qwen3-coder-next',
            owned_by: 'lmstudio',
            contextLength: 32768
        }]
    );
});
