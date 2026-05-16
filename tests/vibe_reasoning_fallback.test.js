const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadTestExports() {
    const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
    const context = {
        AbortController,
        AbortSignal,
        console,
        clearTimeout,
        fetch: async () => { throw new Error('fetch is not available in this test'); },
        localStorage: {
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

    vm.runInNewContext(`${source}\nthis.__testExports = { VibeCodingManager, LLMService, DEFAULT_VIBE_CODER_PROMPT };`, context);
    return context.__testExports;
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
