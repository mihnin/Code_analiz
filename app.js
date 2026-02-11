/* ============================================================
   AI сканер — AI Code Analysis Application
   Pure Vanilla JS (ES6+), No Dependencies
   ============================================================ */

'use strict';

/* ============================================================
   DEFAULT PROMPTS MATRIX
   ============================================================ */
const DEFAULT_PROMPTS = [
    // === INFOSEC ===
    {
        id: 'infosec_vuln',
        role: 'infosec',
        actionName: 'Анализ уязвимостей',
        systemPrompt: `Ты — эксперт по информационной безопасности с 15-летним опытом аудита корпоративных систем. Проанализируй предоставленный код на наличие уязвимостей по методологии OWASP Top 10.

Для каждой найденной уязвимости укажи:
1. **Тип уязвимости** (CWE ID, если применимо)
2. **Критичность** (Critical / High / Medium / Low)
3. **Строка/фрагмент кода** с проблемой
4. **Описание** — почему это опасно
5. **Рекомендация** — как исправить с примером кода

Особое внимание для языков:
- ABAP: проверки авторизации (AUTHORITY-CHECK), SQL-инъекции через динамические запросы, захардкоженные учётные данные
- 1С: привилегированный режим, внешние обработки, SQL-инъекции через "Выполнить"
- Python: инъекции через eval/exec, небезопасная десериализация, SSRF
- JavaScript: XSS, prototype pollution, небезопасные зависимости

В конце выдай общую оценку безопасности от 1 до 5 и резюме.`,
        contextFile: ''
    },
    {
        id: 'infosec_audit',
        role: 'infosec',
        actionName: 'Аудит безопасности',
        systemPrompt: `Ты — аудитор информационной безопасности. Проведи комплексный аудит предоставленного кода по следующим направлениям:

1. **Аутентификация и авторизация** — проверяются ли права доступа? Есть ли обход?
2. **Управление данными** — как обрабатываются чувствительные данные? Логирование паролей?
3. **Конфигурация безопасности** — захардкоженные ключи, пароли, токены
4. **Обработка ошибок** — утечка информации через сообщения об ошибках
5. **Криптография** — используются ли устаревшие алгоритмы?
6. **Сетевое взаимодействие** — валидация входных данных, CORS, CSRF

Формат отчёта:
- Заголовок раздела
- Найденные проблемы (если есть)
- Рекомендации по исправлению
- Общее заключение и compliance-статус`,
        contextFile: ''
    },

    // === CONSULTANT ===
    {
        id: 'consultant_explain',
        role: 'consultant',
        actionName: 'Объяснить логику',
        systemPrompt: `Ты — опытный бизнес-консультант и системный аналитик. Объясни логику предоставленного кода простым и понятным языком для бизнес-пользователей.

Структура ответа:
1. **Общее назначение** — что делает этот код в терминах бизнес-процесса
2. **Пошаговая логика** — разбор каждого значимого блока на понятном языке
3. **Входные данные** — что получает программа
4. **Выходные данные** — что программа возвращает/изменяет
5. **Бизнес-правила** — какие правила реализованы в коде
6. **Зависимости** — от каких систем/данных зависит работа

Избегай технического жаргона. Если используешь технический термин — поясни его.`,
        contextFile: ''
    },
    {
        id: 'consultant_tz_modify',
        role: 'consultant',
        actionName: 'ТЗ на доработку',
        systemPrompt: `Ты — системный аналитик. На основе предоставленного кода сформируй Техническое Задание (ТЗ) на его доработку.

Формат ТЗ (строго соблюдай структуру):

# Техническое задание на доработку

## 1. Общие сведения
- Название системы/модуля:
- Текущая версия:
- Дата:

## 2. Текущее состояние
Описание текущей реализации (на основе анализа кода)

## 3. Цели доработки
Что нужно изменить/улучшить (перечисли потенциальные улучшения)

## 4. Функциональные требования
### FR-001: [Название]
- Описание:
- Входные данные:
- Выходные данные:
- Бизнес-правила:

## 5. Нефункциональные требования
- Производительность
- Безопасность
- Совместимость

## 6. Ограничения и допущения

## 7. Критерии приёмки`,
        contextFile: ''
    },
    {
        id: 'consultant_tz_new',
        role: 'consultant',
        actionName: 'ТЗ с нуля',
        systemPrompt: `Ты — ведущий системный аналитик. Проанализируй предоставленный код и создай полноценное Техническое Задание с нуля, как если бы этот функционал нужно было разработать заново.

Формат ТЗ:

# Техническое задание

## 1. Введение
### 1.1 Цель документа
### 1.2 Область применения
### 1.3 Термины и сокращения

## 2. Общее описание системы
### 2.1 Назначение
### 2.2 Пользователи системы
### 2.3 Границы системы

## 3. Функциональные требования
(Каждое требование: ID, Название, Описание, Приоритет, Входные/Выходные данные)

## 4. Нефункциональные требования
### 4.1 Производительность
### 4.2 Безопасность
### 4.3 Надёжность
### 4.4 Масштабируемость

## 5. Интерфейсы взаимодействия
### 5.1 Пользовательский интерфейс
### 5.2 Программные интерфейсы (API)

## 6. Требования к данным

## 7. Ограничения и допущения

## 8. Критерии приёмки`,
        contextFile: ''
    },

    // === DEVELOPER ===
    {
        id: 'dev_refactor',
        role: 'developer',
        actionName: 'Рефакторинг',
        systemPrompt: `Ты — Senior Developer с экспертизой в чистом коде и архитектурных паттернах. Проведи рефакторинг предоставленного кода.

Порядок анализа:
1. **Текущие проблемы** — что не так с кодом (code smells, антипаттерны)
2. **Предложения по рефакторингу** — конкретные изменения с обоснованием
3. **Рефакторинг-код** — полный переписанный вариант с комментариями
4. **Что изменилось** — список изменений и почему

Применяй принципы: SOLID, DRY, KISS, YAGNI.
Учитывай специфику языка (ABAP: модульные функции vs классы; 1С: типовые/нетиповые; Python: PEP-8; JS: современный ES6+).

В конце обязательно выставь **оценку качества кода от 1 до 5**:
- 1 — Критически плохой код, требует полной переработки
- 2 — Много проблем, работает но ненадёжно
- 3 — Средний уровень, есть что улучшить
- 4 — Хороший код, минимальные замечания
- 5 — Отличный код, образцовый`,
        contextFile: ''
    },
    {
        id: 'dev_quality',
        role: 'developer',
        actionName: 'Оценка качества (1-5)',
        systemPrompt: `Ты — эксперт по качеству кода. Оцени предоставленный код по шкале от 1 до 5 по каждому критерию:

## Критерии оценки:

### 1. Читаемость (1-5)
- Именование переменных и функций
- Структура и форматирование
- Комментарии (уместность и полнота)

### 2. Архитектура (1-5)
- Модульность
- Разделение ответственности
- Паттерны проектирования

### 3. Надёжность (1-5)
- Обработка ошибок
- Граничные случаи
- Валидация входных данных

### 4. Производительность (1-5)
- Алгоритмическая сложность
- Оптимальность решения
- Потребление ресурсов

### 5. Поддерживаемость (1-5)
- Лёгкость внесения изменений
- Тестируемость
- Документация

## Итоговая оценка: X/5 (среднее)
## Резюме: краткое заключение и топ-3 рекомендации`,
        contextFile: ''
    },
    {
        id: 'dev_performance',
        role: 'developer',
        actionName: 'Анализ производительности',
        systemPrompt: `Ты — эксперт по оптимизации и производительности ПО. Проанализируй предоставленный код на предмет проблем с производительностью.

Порядок анализа:
1. **Алгоритмическая сложность** — O(n) для ключевых операций
2. **Узкие места** — что может тормозить при больших объёмах данных
3. **Потребление памяти** — утечки, избыточное потребление
4. **I/O операции** — запросы к БД, файловые операции, сетевые вызовы
5. **Параллельность** — возможности для асинхронной обработки

Для каждой проблемы:
- Описание проблемы
- Потенциальное влияние (при N = 100, 10000, 1000000 записей)
- Рекомендация с примером оптимизированного кода

Специфика:
- ABAP: SELECT *, вложенные LOOP, внутренние таблицы
- 1С: запросы без индексов, обход результатов запроса
- Python: GIL, генераторы vs списки, numpy для массивов
- JS: DOM манипуляции, event loop блокировка, Web Workers`,
        contextFile: ''
    }
];

/* ============================================================
   ROLE DEFINITIONS
   ============================================================ */
const ROLES = {
    infosec: {
        name: 'Информационная безопасность',
        shortName: 'ИБ',
        icon: 'i-security',
        color: 'infosec',
        team: 'InfoSec Team'
    },
    consultant: {
        name: 'Консультант',
        shortName: 'Конс.',
        icon: 'i-consultant',
        color: 'consultant',
        team: 'Consulting'
    },
    developer: {
        name: 'Разработчик',
        shortName: 'Dev',
        icon: 'i-developer',
        color: 'developer',
        team: 'Development'
    }
};

/* ============================================================
   REASONING MODEL DETECTION (heuristic by name)
   ============================================================ */
const REASONING_PATTERNS = [
    /\br1\b/i,          // deepseek-r1, r1-distill, etc.
    /reasoner/i,        // deepseek-reasoner
    /thinking/i,        // models with thinking in name
    /\bcot\b/i,         // chain-of-thought
    /\breason/i,        // reasoning models
    /qwen3/i,           // Qwen3 family supports thinking by default
    /qwq/i,             // QwQ reasoning model
];

function isLikelyReasoningModel(modelName) {
    if (!modelName) return false;
    return REASONING_PATTERNS.some(pattern => pattern.test(modelName));
}

const LANGUAGES = {
    abap: 'ABAP',
    '1c': '1С',
    python: 'Python',
    javascript: 'JavaScript'
};

/* ============================================================
   APPLICATION STATE
   ============================================================ */
class AppState {
    constructor() {
        this.currentPage = 'analysis';
        this.selectedRole = 'infosec';
        this.selectedLang = 'abap';
        this.selectedAction = null;
        this.attachedFile = null;
        this.attachedFileContent = '';
        this.chatMessages = [];
        this.conversationHistory = [];
        this.isGenerating = false;
        this.abortController = null;

        // Settings
        this.settings = {
            mode: 'cloud',
            cloudApiKey: '',
            cloudModel: 'deepseek-chat',
            cloudUrl: 'https://api.deepseek.com',
            localUrl: 'http://172.16.33.12:9997',
            localModel: '',
            temperature: 0.3,
            maxTokens: 4096,
            contextWindow: 65536
        };

        // Prompts
        this.prompts = [];

        // History
        this.history = [];

        this.loadFromStorage();
    }

    loadFromStorage() {
        try {
            const saved = localStorage.getItem('codesentinel_settings');
            if (saved) {
                const parsed = JSON.parse(saved);
                Object.assign(this.settings, parsed);
            }
        } catch (e) { /* ignore */ }

        try {
            const saved = localStorage.getItem('codesentinel_prompts');
            if (saved) {
                this.prompts = JSON.parse(saved);
            }
        } catch (e) { /* ignore */ }

        if (this.prompts.length === 0) {
            this.prompts = JSON.parse(JSON.stringify(DEFAULT_PROMPTS));
        }

        try {
            const saved = localStorage.getItem('codesentinel_history');
            if (saved) {
                this.history = JSON.parse(saved);
            }
        } catch (e) { /* ignore */ }
    }

    saveSettings() {
        localStorage.setItem('codesentinel_settings', JSON.stringify(this.settings));
    }

    savePrompts() {
        localStorage.setItem('codesentinel_prompts', JSON.stringify(this.prompts));
    }

    saveHistory() {
        localStorage.setItem('codesentinel_history', JSON.stringify(this.history));
    }

    getPromptsForRole(role) {
        return this.prompts.filter(p => p.role === role);
    }

    getPromptById(id) {
        return this.prompts.find(p => p.id === id);
    }

    addHistoryEntry(entry) {
        this.history.unshift(entry);
        if (this.history.length > 50) this.history.pop();
        this.saveHistory();
    }
}

/* ============================================================
   LLM SERVICE
   ============================================================ */
class LLMService {
    constructor(state) {
        this.state = state;
    }

    buildMessages(systemPrompt, userCode, language, contextContent) {
        const langLabel = LANGUAGES[language] || language;
        let userContent = `Язык программирования: ${langLabel}\n\n`;

        if (contextContent) {
            userContent += `Контекст (из прикреплённого файла):\n${contextContent}\n\n`;
        }

        userContent += `Код для анализа:\n\`\`\`${language}\n${userCode}\n\`\`\``;

        return [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent }
        ];
    }

    buildFollowUpMessages(conversationHistory, followUpQuestion) {
        const messages = [...conversationHistory];
        messages.push({ role: 'user', content: followUpQuestion });
        return messages;
    }

    getEndpointConfig() {
        const s = this.state.settings;
        if (s.mode === 'cloud') {
            return {
                url: (s.cloudUrl || 'https://api.deepseek.com').replace(/\/+$/, '') + '/chat/completions',
                apiKey: s.cloudApiKey,
                model: s.cloudModel || 'deepseek-chat'
            };
        }
        return {
            url: (s.localUrl || 'http://172.16.33.12:9997').replace(/\/+$/, '') + '/v1/chat/completions',
            apiKey: '',
            model: s.localModel || 'local-model'
        };
    }

    async callLLM(messages, onChunk, abortSignal) {
        const config = this.getEndpointConfig();

        if (this.state.settings.mode === 'cloud' && !config.apiKey) {
            throw new Error('API ключ не указан. Перейдите в Настройки и введите ключ DeepSeek API.');
        }

        const headers = { 'Content-Type': 'application/json' };
        if (config.apiKey) {
            headers['Authorization'] = `Bearer ${config.apiKey}`;
        }

        const body = {
            model: config.model,
            messages: messages,
            stream: true,
            temperature: this.state.settings.temperature,
            max_tokens: this.state.settings.maxTokens
        };

        const response = await fetch(config.url, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            signal: abortSignal
        });

        if (!response.ok) {
            const errText = await response.text().catch(() => '');
            let detail = '';
            try {
                const errJson = JSON.parse(errText);
                detail = errJson.error?.message || errJson.message || errText;
            } catch { detail = errText; }
            throw new Error(`API Error ${response.status}: ${detail || response.statusText}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let fullContent = '';
        let fullReasoning = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed || !trimmed.startsWith('data:')) continue;

                const data = trimmed.slice(5).trim();
                if (data === '[DONE]') continue;

                try {
                    const parsed = JSON.parse(data);
                    const delta = parsed.choices?.[0]?.delta;
                    if (!delta) continue;

                    const reasoningDelta = delta.reasoning_content || null;
                    const contentDelta = delta.content || null;

                    if (reasoningDelta) fullReasoning += reasoningDelta;
                    if (contentDelta) fullContent += contentDelta;

                    if (reasoningDelta || contentDelta) {
                        onChunk({ contentDelta, reasoningDelta, fullContent, fullReasoning });
                    }
                } catch { /* skip malformed chunks */ }
            }
        }

        return { content: fullContent, reasoning: fullReasoning };
    }

    async testConnection() {
        const config = this.getEndpointConfig();
        const headers = { 'Content-Type': 'application/json' };
        if (config.apiKey) {
            headers['Authorization'] = `Bearer ${config.apiKey}`;
        }

        const body = {
            model: config.model,
            messages: [{ role: 'user', content: 'Hello' }],
            max_tokens: 5,
            stream: false
        };

        const response = await fetch(config.url, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(10000)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json = await response.json();
        return json.model || config.model;
    }

    async fetchLocalModels() {
        const baseUrl = (this.state.settings.localUrl || 'http://172.16.33.12:9997').replace(/\/+$/, '');
        const response = await fetch(`${baseUrl}/v1/models`, {
            method: 'GET',
            signal: AbortSignal.timeout(10000)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json = await response.json();
        const models = json.data || json.models || [];
        return models.map(m => ({
            id: m.id || m.name || m.model,
            name: m.id || m.name || m.model,
            owned_by: m.owned_by || '',
            contextLength: m.context_length || m.max_model_len || m.context_window || 0
        })).filter(m => m.id);
    }
}

/* ============================================================
   MARKDOWN RENDERER
   ============================================================ */
class MarkdownRenderer {
    static render(text) {
        if (!text) return '';

        let html = text;

        // Escape HTML entities (but not in code blocks)
        const codeBlocks = [];
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
            const idx = codeBlocks.length;
            codeBlocks.push({ lang, code: MarkdownRenderer.escapeHtml(code.trim()) });
            return `%%CODEBLOCK_${idx}%%`;
        });

        const inlineCodes = [];
        html = html.replace(/`([^`]+)`/g, (_, code) => {
            const idx = inlineCodes.length;
            inlineCodes.push(MarkdownRenderer.escapeHtml(code));
            return `%%INLINE_${idx}%%`;
        });

        // Escape HTML in remaining text
        html = MarkdownRenderer.escapeHtml(html);

        // Restore code blocks
        html = html.replace(/%%CODEBLOCK_(\d+)%%/g, (_, idx) => {
            const block = codeBlocks[+idx];
            return `<div class="code-block-wrapper"><button class="btn-copy-code" onclick="App.copyCode(this)">Копировать</button><pre><code class="lang-${block.lang}">${block.code}</code></pre></div>`;
        });

        // Restore inline code
        html = html.replace(/%%INLINE_(\d+)%%/g, (_, idx) => {
            return `<code>${inlineCodes[+idx]}</code>`;
        });

        // Headers
        html = html.replace(/^######\s+(.+)$/gm, '<h6>$1</h6>');
        html = html.replace(/^#####\s+(.+)$/gm, '<h5>$1</h5>');
        html = html.replace(/^####\s+(.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^###\s+(.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^##\s+(.+)$/gm, '<h2>$1</h2>');
        html = html.replace(/^#\s+(.+)$/gm, '<h1>$1</h1>');

        // Bold & Italic
        html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

        // Blockquote
        html = html.replace(/^&gt;\s?(.+)$/gm, '<blockquote>$1</blockquote>');

        // Horizontal rule
        html = html.replace(/^---+$/gm, '<hr>');

        // Tables
        html = MarkdownRenderer.renderTables(html);

        // Unordered lists — mark with temporary tags
        html = html.replace(/^(\s*)-\s+(.+)$/gm, '<uli>$2</uli>');

        // Ordered lists — mark with temporary tags
        html = html.replace(/^(\s*)\d+\.\s+(.+)$/gm, '<oli>$2</oli>');

        // Wrap consecutive unordered list items
        html = html.replace(/(<uli>[\s\S]*?<\/uli>\n?)+/g, (match) => {
            return '<ul>' + match.replace(/<uli>/g, '<li>').replace(/<\/uli>/g, '</li>') + '</ul>';
        });

        // Wrap consecutive ordered list items
        html = html.replace(/(<oli>[\s\S]*?<\/oli>\n?)+/g, (match) => {
            return '<ol>' + match.replace(/<oli>/g, '<li>').replace(/<\/oli>/g, '</li>') + '</ol>';
        });

        // Paragraphs: wrap remaining text lines
        html = html.replace(/^(?!<[a-z/])((?!%%).+)$/gm, '<p>$1</p>');

        // Clean up empty paragraphs
        html = html.replace(/<p>\s*<\/p>/g, '');

        return html;
    }

    static renderTables(html) {
        const tableRegex = /^\|(.+)\|\s*\n\|[\s\-:|]+\|\s*\n((?:\|.+\|\s*\n?)+)/gm;
        return html.replace(tableRegex, (match, headerRow, bodyRows) => {
            const headers = headerRow.split('|').map(h => h.trim()).filter(Boolean);
            const rows = bodyRows.trim().split('\n').map(row =>
                row.split('|').map(c => c.trim()).filter(Boolean)
            );

            let table = '<table><thead><tr>';
            headers.forEach(h => table += `<th>${h}</th>`);
            table += '</tr></thead><tbody>';
            rows.forEach(row => {
                table += '<tr>';
                row.forEach(c => table += `<td>${c}</td>`);
                table += '</tr>';
            });
            table += '</tbody></table>';
            return table;
        });
    }

    static escapeHtml(str) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return str.replace(/[&<>"']/g, c => map[c]);
    }
}

/* ============================================================
   TOAST NOTIFICATIONS
   ============================================================ */
/* ============================================================
   TOKEN ESTIMATOR
   BPE tokenizers: English ~4 chars/token, Cyrillic ~2 chars/token
   ============================================================ */
class TokenEstimator {
    static estimate(text) {
        if (!text) return 0;
        let cyrCount = 0;
        let otherCount = 0;
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (code >= 0x0400 && code <= 0x04FF) {
                cyrCount++;
            } else {
                otherCount++;
            }
        }
        // Cyrillic: ~2 chars per token, Latin/code: ~4 chars per token
        return Math.ceil(cyrCount / 2 + otherCount / 4);
    }

    static formatCount(n) {
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }
}

class Toast {
    static show(message, type = 'success', duration = 4000) {
        const container = document.getElementById('toast-container');
        const iconMap = {
            success: '#i-check',
            error: '#i-warning',
            warning: '#i-warning'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-icon"><svg class="icon"><use href="${iconMap[type] || '#i-check'}"/></svg></span>
            <span>${message}</span>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'toastOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
}

/* ============================================================
   MAIN APPLICATION
   ============================================================ */
class Application {
    constructor() {
        this.state = new AppState();
        this.llm = new LLMService(this.state);
        this.editingPromptId = null;
        this._modalContextFile = '';
        this._modalContextContent = '';
        this.init();
    }

    init() {
        this.bindNavigation();
        this.bindAnalysisPage();
        this.bindSettingsPage();
        this.bindHistoryPage();
        this.bindHelpPage();
        this.bindModals();
        this.bindMobileMenu();
        this.bindSidebarToggle();
        this.bindHelpLinks();

        this.renderActionButtons();
        this.renderSettingsForm();
        this.renderPromptsTable();
        this.renderHistory();
        this.updateConnectionStatus();
        this.selectFirstAction();
        this.bindTokenMeter();
        this.bindGlobalKeys();
    }

    /* ------ Navigation ------ */
    bindNavigation() {
        document.querySelectorAll('.nav-item[data-page]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.navigateTo(item.dataset.page);
            });
        });
    }

    navigateTo(page) {
        this.state.currentPage = page;

        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.getElementById(`page-${page}`)?.classList.add('active');

        // Close mobile sidebar
        document.getElementById('sidebar').classList.remove('open');
        document.querySelector('.sidebar-overlay')?.classList.remove('visible');
    }

    /* ------ Mobile Menu ------ */
    bindMobileMenu() {
        const btn = document.getElementById('mobile-menu-btn');
        const sidebar = document.getElementById('sidebar');

        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'sidebar-overlay';
        document.body.appendChild(overlay);

        btn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('visible');
        });

        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('visible');
        });
    }

    /* ------ Sidebar Toggle ------ */
    bindSidebarToggle() {
        const btn = document.getElementById('sidebar-toggle');
        if (!btn) return;

        // Restore saved state
        if (localStorage.getItem('codesentinel_sidebar_collapsed') === 'true') {
            document.body.classList.add('sidebar-collapsed');
        }

        btn.addEventListener('click', () => {
            document.body.classList.toggle('sidebar-collapsed');
            const collapsed = document.body.classList.contains('sidebar-collapsed');
            localStorage.setItem('codesentinel_sidebar_collapsed', collapsed);
        });
    }

    /* ------ Analysis Page ------ */
    bindAnalysisPage() {
        const roleSelect = document.getElementById('role-select');
        const langSelect = document.getElementById('lang-select');
        const codeInput = document.getElementById('code-input');
        const fileInput = document.getElementById('file-input');
        const btnAnalyze = document.getElementById('btn-analyze');
        const btnClearCode = document.getElementById('btn-clear-code');
        const btnPaste = document.getElementById('btn-paste');
        const btnClearChat = document.getElementById('btn-clear-chat');
        const btnExportChat = document.getElementById('btn-export-chat');
        const chatFollowup = document.getElementById('chat-followup');
        const btnSendFollowup = document.getElementById('btn-send-followup');
        const btnStopGeneration = document.getElementById('btn-stop-generation');

        roleSelect.addEventListener('change', () => {
            this.state.selectedRole = roleSelect.value;
            this.state.selectedAction = null;
            this.renderActionButtons();
            this.selectFirstAction();
        });

        langSelect.addEventListener('change', () => {
            this.state.selectedLang = langSelect.value;
        });

        codeInput.addEventListener('input', () => {
            this.updateCodeStats();
            this.updateAnalyzeButton();
        });

        // Tab support in textarea
        codeInput.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                e.preventDefault();
                const start = codeInput.selectionStart;
                const end = codeInput.selectionEnd;
                codeInput.value = codeInput.value.substring(0, start) + '    ' + codeInput.value.substring(end);
                codeInput.selectionStart = codeInput.selectionEnd = start + 4;
                codeInput.dispatchEvent(new Event('input'));
            }
        });

        // File input
        document.getElementById('btn-attach-label').addEventListener('click', (e) => {
            // Label already triggers file input
        });

        fileInput.addEventListener('change', () => {
            const file = fileInput.files[0];
            if (!file) return;
            this.handleFileAttach(file);
        });

        document.getElementById('btn-remove-file')?.addEventListener('click', () => {
            this.removeAttachedFile();
        });

        btnPaste.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                codeInput.value = text;
                codeInput.dispatchEvent(new Event('input'));
                Toast.show('Код вставлен из буфера обмена');
            } catch {
                Toast.show('Не удалось прочитать буфер обмена', 'warning');
            }
        });

        btnClearCode.addEventListener('click', () => {
            codeInput.value = '';
            codeInput.dispatchEvent(new Event('input'));
        });

        btnAnalyze.addEventListener('click', () => this.runAnalysis());

        btnClearChat.addEventListener('click', () => this.clearChat());

        btnExportChat.addEventListener('click', () => this.exportChat());

        // Follow-up
        chatFollowup.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendFollowUp();
            }
        });

        btnSendFollowup.addEventListener('click', () => this.sendFollowUp());

        btnStopGeneration.addEventListener('click', () => this.stopGeneration());

        // Welcome hint cards
        document.querySelectorAll('.hint-card[data-role]').forEach(card => {
            card.addEventListener('click', () => {
                const role = card.dataset.role;
                document.getElementById('role-select').value = role;
                this.state.selectedRole = role;
                this.state.selectedAction = null;
                this.renderActionButtons();
                this.selectFirstAction();
            });
        });
    }

    handleFileAttach(file) {
        const MAX_FILE_SIZE = 512 * 1024; // 500 KB

        if (file.size > MAX_FILE_SIZE) {
            const sizeMB = (file.size / 1024 / 1024).toFixed(1);
            Toast.show(`Файл слишком большой (${sizeMB} МБ). Максимум: 500 КБ`, 'error', 5000);
            document.getElementById('file-input').value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            // Check if content looks like binary (too many non-printable chars)
            const sample = content.substring(0, 1000);
            const nonPrintable = (sample.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
            if (nonPrintable > sample.length * 0.1) {
                Toast.show('Файл содержит бинарные данные. Поддерживаются только текстовые форматы (.txt, .md, .json и др.)', 'error', 5000);
                document.getElementById('file-input').value = '';
                return;
            }

            this.state.attachedFile = file.name;
            this.state.attachedFileContent = content;
            const info = document.getElementById('attached-file-info');
            const sizeLabel = file.size < 1024
                ? `${file.size} Б`
                : `${(file.size / 1024).toFixed(1)} КБ`;
            document.getElementById('attached-filename').textContent = `${file.name} (${sizeLabel})`;
            info.style.display = 'flex';
            Toast.show(`Файл "${file.name}" прикреплён (${sizeLabel})`);
            this.updateTokenMeter();
        };
        reader.onerror = () => {
            Toast.show('Ошибка чтения файла', 'error');
        };
        reader.readAsText(file);
    }

    removeAttachedFile() {
        this.state.attachedFile = null;
        this.state.attachedFileContent = '';
        document.getElementById('attached-file-info').style.display = 'none';
        document.getElementById('file-input').value = '';
        this.updateTokenMeter();
    }

    updateCodeStats() {
        const code = document.getElementById('code-input').value;
        const lines = code ? code.split('\n').length : 0;
        const chars = code.length;
        document.getElementById('code-stats').textContent = `${lines} строк | ${chars} симв.`;
        this.updateTokenMeter();
    }

    updateAnalyzeButton() {
        const code = document.getElementById('code-input').value.trim();
        const btn = document.getElementById('btn-analyze');
        btn.disabled = !code || !this.state.selectedAction || this.state.isGenerating;
    }

    updateTokenMeter() {
        const prompt = this.state.getPromptById(this.state.selectedAction);
        const promptText = prompt ? (prompt.systemPrompt + (prompt.contextContent || '')) : '';
        const codeText = document.getElementById('code-input').value;
        const fileText = this.state.attachedFileContent || '';

        // Estimate tokens for each part
        const promptTokens = TokenEstimator.estimate(promptText);
        const inputTokens = TokenEstimator.estimate(codeText);
        const fileTokens = TokenEstimator.estimate(fileText);

        // History tokens: sum of all messages in conversation
        let historyTokens = 0;
        for (const msg of this.state.conversationHistory) {
            historyTokens += TokenEstimator.estimate(msg.content);
        }

        const reservedTokens = this.state.settings.maxTokens;
        const contextWindow = this.state.settings.contextWindow;

        const usedTokens = promptTokens + inputTokens + fileTokens + historyTokens;
        const totalNeeded = usedTokens + reservedTokens;

        // Update breakdown text
        const breakdown = document.getElementById('token-breakdown');
        breakdown.textContent = `~${TokenEstimator.formatCount(usedTokens)} токенов ввода`;
        if (totalNeeded > contextWindow) {
            breakdown.className = 'token-breakdown over';
        } else if (totalNeeded > contextWindow * 0.8) {
            breakdown.className = 'token-breakdown warn';
        } else {
            breakdown.className = 'token-breakdown ok';
        }

        // Update bar segments
        const pct = (v) => Math.min((v / contextWindow) * 100, 100);
        document.getElementById('token-bar-prompt').style.width = pct(promptTokens) + '%';
        document.getElementById('token-bar-input').style.width = pct(inputTokens) + '%';
        document.getElementById('token-bar-file').style.width = pct(fileTokens) + '%';
        document.getElementById('token-bar-history').style.width = pct(historyTokens) + '%';
        document.getElementById('token-bar-reserved').style.width = pct(reservedTokens) + '%';

        // Used label
        document.getElementById('token-used-label').textContent =
            `${TokenEstimator.formatCount(totalNeeded)} / ${TokenEstimator.formatCount(contextWindow)}`;

        // Details panel
        document.getElementById('td-prompt').textContent = TokenEstimator.formatCount(promptTokens);
        document.getElementById('td-input').textContent = TokenEstimator.formatCount(inputTokens);
        document.getElementById('td-file').textContent = TokenEstimator.formatCount(fileTokens);
        document.getElementById('td-history').textContent = TokenEstimator.formatCount(historyTokens);
        document.getElementById('td-reserved').textContent = TokenEstimator.formatCount(reservedTokens);
        document.getElementById('td-total').textContent =
            `${TokenEstimator.formatCount(totalNeeded)} / ${TokenEstimator.formatCount(contextWindow)}`;
    }

    bindTokenMeter() {
        // Toggle details on click
        const meter = document.querySelector('.token-meter');
        const details = document.getElementById('token-details');
        meter.addEventListener('click', (e) => {
            if (e.target.closest('.btn-analyze')) return;
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        });

        // Update token meter when action changes
        // (already triggered by updateCodeStats on code input)
        this.updateTokenMeter();
    }

    renderActionButtons() {
        const container = document.getElementById('action-buttons');
        const prompts = this.state.getPromptsForRole(this.state.selectedRole);

        container.innerHTML = prompts.map(p => `
            <button class="action-btn ${this.state.selectedAction === p.id ? 'active' : ''}"
                    data-action-id="${p.id}">
                ${p.actionName}
            </button>
        `).join('');

        container.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                container.querySelectorAll('.action-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.state.selectedAction = btn.dataset.actionId;
                this.updateAnalyzeButton();
                this.updateTokenMeter();
            });
        });
    }

    selectFirstAction() {
        const prompts = this.state.getPromptsForRole(this.state.selectedRole);
        if (prompts.length > 0) {
            this.state.selectedAction = prompts[0].id;
            const firstBtn = document.querySelector('.action-btn');
            if (firstBtn) firstBtn.classList.add('active');
        }
        this.updateAnalyzeButton();
        this.updateTokenMeter();
    }

    /* ------ Chat ------ */
    addChatMessage(role, content, meta = null) {
        const msg = { role, content, meta, time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) };
        this.state.chatMessages.push(msg);
        return this.renderChatMessage(msg);
    }

    renderChatMessage(msg) {
        const container = document.getElementById('chat-messages');

        // Remove welcome if present
        const welcome = container.querySelector('.chat-welcome');
        if (welcome) welcome.remove();

        const div = document.createElement('div');
        div.className = `msg msg-${msg.role}`;

        const avatarText = msg.role === 'user' ? 'Вы' : 'AI';
        const name = msg.role === 'user' ? 'Вы' : 'AI сканер';

        const metaHtml = msg.meta ? `<span class="msg-meta">${msg.meta}</span>` : '';
        const copyBtn = msg.role === 'assistant'
            ? `<button class="btn-copy-msg" title="Скопировать ответ"><svg class="icon"><use href="#i-copy"/></svg></button>`
            : '';

        div.innerHTML = `
            <div class="msg-avatar">${avatarText}</div>
            <div class="msg-body">
                <div class="msg-header">
                    <span class="msg-name">${name}</span>
                    <span class="msg-time">${msg.time}</span>
                    ${metaHtml}
                    ${copyBtn}
                </div>
                <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : MarkdownRenderer.escapeHtml(msg.content)}</div>
            </div>
        `;

        this.bindMsgCopyBtn(div);

        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return div;
    }

    createStreamingMessage() {
        const container = document.getElementById('chat-messages');
        const welcome = container.querySelector('.chat-welcome');
        if (welcome) welcome.remove();

        const div = document.createElement('div');
        div.className = 'msg msg-assistant';
        div.id = 'streaming-msg';

        div.innerHTML = `
            <div class="msg-avatar">AI</div>
            <div class="msg-body">
                <div class="msg-header">
                    <span class="msg-name">AI сканер</span>
                    <span class="msg-time">${new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</span>
                    <span class="msg-model-badge-area"></span>
                    <button class="btn-copy-msg" title="Скопировать ответ"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
                <div class="msg-reasoning" style="display:none">
                    <div class="reasoning-header">
                        <svg class="icon"><use href="#i-brain"/></svg>
                        <span class="reasoning-label">Рассуждает...</span>
                        <span class="reasoning-toggle">Показать</span>
                    </div>
                    <div class="reasoning-content" style="display:none"></div>
                </div>
                <div class="msg-content"><div class="typing-indicator"><span></span><span></span><span></span></div></div>
            </div>
        `;

        this.bindMsgCopyBtn(div);
        this.bindReasoningToggle(div);

        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return div;
    }

    updateStreamingMessage(div, info) {
        const { fullContent, fullReasoning } = info;

        // Handle reasoning section
        if (fullReasoning) {
            const reasoningEl = div.querySelector('.msg-reasoning');
            if (reasoningEl) {
                reasoningEl.style.display = 'block';
                const contentArea = reasoningEl.querySelector('.reasoning-content');
                contentArea.textContent = fullReasoning;

                const label = reasoningEl.querySelector('.reasoning-label');
                if (!fullContent) {
                    label.textContent = 'Рассуждает...';
                    label.classList.add('active');
                } else {
                    const tokens = TokenEstimator.estimate(fullReasoning);
                    label.textContent = `Рассуждения (~${TokenEstimator.formatCount(tokens)} токенов)`;
                    label.classList.remove('active');
                }
            }
        }

        // Handle content
        const contentEl = div.querySelector('.msg-content');
        if (fullContent) {
            contentEl.innerHTML = MarkdownRenderer.render(fullContent);
        }

        const container = document.getElementById('chat-messages');
        container.scrollTop = container.scrollHeight;
    }

    bindMsgCopyBtn(msgDiv) {
        const btn = msgDiv.querySelector('.btn-copy-msg');
        if (!btn) return;
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const text = msgDiv.querySelector('.msg-content').innerText;
            navigator.clipboard.writeText(text).then(() => {
                btn.classList.add('copied');
                const icon = btn.querySelector('use');
                icon.setAttribute('href', '#i-check');
                Toast.show('Скопировано в буфер обмена');
                setTimeout(() => {
                    btn.classList.remove('copied');
                    icon.setAttribute('href', '#i-copy');
                }, 2000);
            }).catch(() => {
                Toast.show('Не удалось скопировать', 'warning');
            });
        });
    }

    bindReasoningToggle(div) {
        const header = div.querySelector('.reasoning-header');
        if (!header) return;
        header.addEventListener('click', () => {
            const content = div.querySelector('.reasoning-content');
            const toggle = div.querySelector('.reasoning-toggle');
            const isVisible = content.style.display !== 'none';
            content.style.display = isVisible ? 'none' : 'block';
            toggle.textContent = isVisible ? 'Показать' : 'Скрыть';
        });
    }

    finalizeStreamingMessage(div, result) {
        div.removeAttribute('id');

        // Add model badge showing reasoning status
        const badgeArea = div.querySelector('.msg-model-badge-area');
        if (badgeArea) {
            if (result.reasoning) {
                const tokens = TokenEstimator.estimate(result.reasoning);
                badgeArea.innerHTML = `<span class="msg-model-badge reasoning"><svg class="icon"><use href="#i-brain"/></svg> С рассуждениями (~${TokenEstimator.formatCount(tokens)})</span>`;
            } else if (this.state.settings.mode === 'local') {
                badgeArea.innerHTML = `<span class="msg-model-badge no-reasoning">Без рассуждений</span>`;
            }
        }

        // Finalize reasoning label if reasoning was present
        if (result.reasoning) {
            const label = div.querySelector('.reasoning-label');
            if (label) {
                const tokens = TokenEstimator.estimate(result.reasoning);
                label.textContent = `Рассуждения (~${TokenEstimator.formatCount(tokens)} токенов)`;
                label.classList.remove('active');
            }
        }
    }

    clearChat() {
        this.state.chatMessages = [];
        this.state.conversationHistory = [];
        const container = document.getElementById('chat-messages');
        container.innerHTML = `
            <div class="chat-welcome">
                <div class="welcome-icon"><svg class="icon"><use href="#i-brain"/></svg></div>
                <h3>AI сканер</h3>
                <p>Вставьте исходный код, ТЗ или функциональную спецификацию, выберите роль и действие</p>
                <div class="welcome-hints">
                    <div class="hint-card" data-role="infosec"><svg class="icon"><use href="#i-security"/></svg><span>ИБ-аудит</span></div>
                    <div class="hint-card" data-role="consultant"><svg class="icon"><use href="#i-consultant"/></svg><span>Консалтинг</span></div>
                    <div class="hint-card" data-role="developer"><svg class="icon"><use href="#i-developer"/></svg><span>Разработка</span></div>
                </div>
            </div>
        `;

        container.querySelectorAll('.hint-card[data-role]').forEach(card => {
            card.addEventListener('click', () => {
                const role = card.dataset.role;
                document.getElementById('role-select').value = role;
                this.state.selectedRole = role;
                this.state.selectedAction = null;
                this.renderActionButtons();
                this.selectFirstAction();
            });
        });

        document.getElementById('chat-followup').disabled = true;
        document.getElementById('btn-send-followup').disabled = true;
        this.updateTokenMeter();
    }

    exportChat() {
        if (this.state.chatMessages.length === 0) {
            Toast.show('Нет сообщений для экспорта', 'warning');
            return;
        }

        const lines = this.state.chatMessages.map(m => {
            const prefix = m.role === 'user' ? '## Вы' : '## AI сканер';
            return `${prefix} (${m.time})\n\n${m.content}`;
        });

        const text = `# AI сканер — Результаты анализа\nДата: ${new Date().toLocaleString('ru-RU')}\n\n---\n\n${lines.join('\n\n---\n\n')}`;

        const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `codesentinel_${Date.now()}.md`;
        a.click();
        URL.revokeObjectURL(url);
        Toast.show('Чат экспортирован');
    }

    /* ------ Run Analysis ------ */
    async runAnalysis() {
        const code = document.getElementById('code-input').value.trim();
        if (!code || !this.state.selectedAction) return;

        const prompt = this.state.getPromptById(this.state.selectedAction);
        if (!prompt) return;

        const role = ROLES[this.state.selectedRole];
        const lang = LANGUAGES[this.state.selectedLang];
        const modelName = this.state.settings.mode === 'cloud'
            ? (this.state.settings.cloudModel || 'deepseek-chat')
            : (this.state.settings.localModel || 'local-model');
        const meta = `${role.shortName} → ${prompt.actionName} → ${lang} | ${modelName}`;

        // Add user message
        this.addChatMessage('user', code, meta);

        // Build system prompt with optional instruction file
        let systemPrompt = prompt.systemPrompt;
        if (prompt.contextContent) {
            systemPrompt += '\n\n--- Дополнительные инструкции ---\n' + prompt.contextContent;
        }

        // Build API messages
        const messages = this.llm.buildMessages(
            systemPrompt,
            code,
            this.state.selectedLang,
            this.state.attachedFileContent
        );

        // Store conversation history for follow-ups
        this.state.conversationHistory = [...messages];

        // Start generation
        this.setGenerating(true);
        const streamDiv = this.createStreamingMessage();

        try {
            this.state.abortController = new AbortController();

            const result = await this.llm.callLLM(
                messages,
                (info) => this.updateStreamingMessage(streamDiv, info),
                this.state.abortController.signal
            );

            // Finalize streaming message (add badges, toggle)
            this.finalizeStreamingMessage(streamDiv, result);

            // Save to conversation history
            this.state.conversationHistory.push({ role: 'assistant', content: result.content });
            this.state.chatMessages.push({
                role: 'assistant',
                content: result.content,
                time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
            });
            this.updateTokenMeter();

            // Save to history
            this.state.addHistoryEntry({
                id: Date.now().toString(),
                role: this.state.selectedRole,
                action: prompt.actionName,
                language: this.state.selectedLang,
                timestamp: new Date().toISOString(),
                messages: this.state.chatMessages.slice(-2),
                codeSnippet: code.substring(0, 100)
            });
            this.renderHistory();

            // Enable follow-up
            document.getElementById('chat-followup').disabled = false;
            document.getElementById('btn-send-followup').disabled = false;

        } catch (err) {
            if (err.name === 'AbortError') {
                this.updateStreamingMessage(streamDiv, { fullContent: '*Генерация остановлена пользователем*', fullReasoning: '' });
            } else {
                streamDiv.remove();
                this.addChatMessage('assistant', `**Ошибка:** ${err.message}\n\nПроверьте настройки подключения к API.`);
                Toast.show(err.message, 'error', 6000);
            }
        } finally {
            this.setGenerating(false);
            this.state.abortController = null;
        }
    }

    async sendFollowUp() {
        const input = document.getElementById('chat-followup');
        const question = input.value.trim();
        if (!question || this.state.isGenerating || this.state.conversationHistory.length === 0) return;

        input.value = '';

        this.addChatMessage('user', question);
        this.state.conversationHistory.push({ role: 'user', content: question });

        this.setGenerating(true);
        const streamDiv = this.createStreamingMessage();

        try {
            this.state.abortController = new AbortController();

            const result = await this.llm.callLLM(
                this.state.conversationHistory,
                (info) => this.updateStreamingMessage(streamDiv, info),
                this.state.abortController.signal
            );

            // Finalize streaming message
            this.finalizeStreamingMessage(streamDiv, result);

            this.state.conversationHistory.push({ role: 'assistant', content: result.content });
            this.state.chatMessages.push({
                role: 'assistant',
                content: result.content,
                time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
            });
            this.updateTokenMeter();

        } catch (err) {
            if (err.name === 'AbortError') {
                this.updateStreamingMessage(streamDiv, { fullContent: '*Генерация остановлена*', fullReasoning: '' });
            } else {
                streamDiv.remove();
                this.addChatMessage('assistant', `**Ошибка:** ${err.message}`);
            }
        } finally {
            this.setGenerating(false);
            this.state.abortController = null;
        }
    }

    stopGeneration() {
        if (this.state.abortController) {
            this.state.abortController.abort();
        }
    }

    setGenerating(isGenerating) {
        this.state.isGenerating = isGenerating;
        const btnAnalyze = document.getElementById('btn-analyze');
        const btnSend = document.getElementById('btn-send-followup');
        const btnStop = document.getElementById('btn-stop-generation');
        const input = document.getElementById('chat-followup');

        if (isGenerating) {
            btnAnalyze.disabled = true;
            btnSend.style.display = 'none';
            btnStop.style.display = 'flex';
            input.disabled = true;
        } else {
            this.updateAnalyzeButton();
            btnSend.style.display = 'flex';
            btnStop.style.display = 'none';
            input.disabled = this.state.conversationHistory.length === 0;
        }
    }

    /* ------ Settings Page ------ */
    bindSettingsPage() {
        // Environment toggle
        document.getElementById('env-toggle').addEventListener('click', (e) => {
            const btn = e.target.closest('.toggle-btn');
            if (!btn) return;
            const mode = btn.dataset.mode;

            document.querySelectorAll('#env-toggle .toggle-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            this.state.settings.mode = mode;

            const cloudSettings = document.getElementById('cloud-settings');
            const localSettings = document.getElementById('local-settings');

            const ctxSelect = document.getElementById('setting-context-window');
            if (mode === 'cloud') {
                cloudSettings.classList.remove('disabled');
                localSettings.classList.add('disabled');
                localSettings.querySelector('.label-badge').textContent = 'Отключено';
                // Restore cloud default context window
                ctxSelect.value = '65536';
            } else {
                localSettings.classList.remove('disabled');
                cloudSettings.classList.add('disabled');
                localSettings.querySelector('.label-badge').textContent = 'Активно';
                // Set local default context window
                ctxSelect.value = '8192';
            }
            // Update context window display
            const ctxVal = parseInt(ctxSelect.value);
            document.getElementById('context-window-value').textContent = ctxVal >= 1024 ? (ctxVal / 1024) + 'K' : ctxVal;
        });

        // Fetch local models
        document.getElementById('btn-fetch-models').addEventListener('click', () => {
            this.fetchLocalModels();
        });

        // Local model dropdown -> detect reasoning type
        document.getElementById('setting-local-model-select').addEventListener('change', (e) => {
            this.updateLocalModelTypeIndicator(e.target.value);
        });

        // DeepSeek model radio cards
        document.querySelectorAll('input[name="deepseek-model"]').forEach(radio => {
            radio.addEventListener('change', () => {
                document.querySelectorAll('.model-card').forEach(c => c.classList.remove('active'));
                if (radio.checked) {
                    radio.closest('.model-card').classList.add('active');
                }
            });
        });

        // Range sliders (temperature & max tokens) + context window
        const tempSlider = document.getElementById('setting-temperature');
        const tokensSlider = document.getElementById('setting-max-tokens');
        const ctxSelect = document.getElementById('setting-context-window');

        tempSlider.addEventListener('input', () => {
            document.getElementById('temperature-value').textContent = tempSlider.value;
        });

        tokensSlider.addEventListener('input', () => {
            document.getElementById('max-tokens-value').textContent = tokensSlider.value;
        });

        ctxSelect.addEventListener('change', () => {
            const val = parseInt(ctxSelect.value);
            const label = val >= 1024 ? (val / 1024) + 'K' : val;
            document.getElementById('context-window-value').textContent = label;
        });

        // Toggle password visibility
        document.querySelectorAll('.toggle-password').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.dataset.target;
                const input = document.getElementById(targetId);
                const icon = btn.querySelector('use');
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.setAttribute('href', '#i-eye');
                } else {
                    input.type = 'password';
                    icon.setAttribute('href', '#i-eye-off');
                }
            });
        });

        // Save settings
        document.getElementById('btn-save-settings').addEventListener('click', () => {
            this.saveSettingsFromForm();
            Toast.show('Настройки сохранены');
        });

        // Test connection
        document.getElementById('btn-test-connection').addEventListener('click', () => {
            this.testConnection();
        });

        // Search prompts
        document.getElementById('prompt-search').addEventListener('input', (e) => {
            this.filterPromptsTable(e.target.value);
        });

        // Add prompt
        document.getElementById('btn-add-prompt').addEventListener('click', () => {
            this.openPromptModal(null);
        });
    }

    renderSettingsForm() {
        const s = this.state.settings;
        document.getElementById('setting-api-key').value = s.cloudApiKey || '';
        document.getElementById('setting-cloud-url').value = s.cloudUrl || 'https://api.deepseek.com';
        document.getElementById('setting-local-url').value = s.localUrl || 'http://172.16.33.12:9997';

        // DeepSeek model radio
        const modelValue = s.cloudModel || 'deepseek-chat';
        const radios = document.querySelectorAll('input[name="deepseek-model"]');
        radios.forEach(r => {
            r.checked = r.value === modelValue;
            const card = r.closest('.model-card');
            card.classList.toggle('active', r.checked);
        });

        // Temperature, Max Tokens & Context Window
        const tempSlider = document.getElementById('setting-temperature');
        const tokensSlider = document.getElementById('setting-max-tokens');
        const ctxSelect = document.getElementById('setting-context-window');
        tempSlider.value = s.temperature ?? 0.3;
        tokensSlider.value = s.maxTokens ?? 4096;
        ctxSelect.value = s.contextWindow ?? 65536;
        document.getElementById('temperature-value').textContent = tempSlider.value;
        document.getElementById('max-tokens-value').textContent = tokensSlider.value;
        const ctxVal = parseInt(ctxSelect.value);
        document.getElementById('context-window-value').textContent = ctxVal >= 1024 ? (ctxVal / 1024) + 'K' : ctxVal;

        // Set toggle state
        const mode = s.mode || 'cloud';
        document.querySelectorAll('#env-toggle .toggle-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.mode === mode);
        });

        const cloudSettings = document.getElementById('cloud-settings');
        const localSettings = document.getElementById('local-settings');
        if (mode === 'local') {
            cloudSettings.classList.add('disabled');
            localSettings.classList.remove('disabled');
            localSettings.querySelector('.label-badge').textContent = 'Активно';
        } else {
            cloudSettings.classList.remove('disabled');
            localSettings.classList.add('disabled');
        }
    }

    saveSettingsFromForm() {
        this.state.settings.cloudApiKey = document.getElementById('setting-api-key').value.trim();
        const checkedRadio = document.querySelector('input[name="deepseek-model"]:checked');
        this.state.settings.cloudModel = checkedRadio ? checkedRadio.value : 'deepseek-chat';
        this.state.settings.cloudUrl = document.getElementById('setting-cloud-url').value.trim() || 'https://api.deepseek.com';
        this.state.settings.localUrl = document.getElementById('setting-local-url').value.trim() || 'http://172.16.33.12:9997';
        this.state.settings.localModel = document.getElementById('setting-local-model-select').value;
        this.state.settings.temperature = parseFloat(document.getElementById('setting-temperature').value) || 0.3;
        this.state.settings.maxTokens = parseInt(document.getElementById('setting-max-tokens').value) || 4096;
        this.state.settings.contextWindow = parseInt(document.getElementById('setting-context-window').value) || 65536;
        this.state.saveSettings();
        this.updateTokenMeter();
        this.updateConnectionStatus();
    }

    async testConnection() {
        this.saveSettingsFromForm();

        const btn = document.getElementById('btn-test-connection');
        const result = document.getElementById('test-connection-result');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Проверка...';
        btn.disabled = true;
        result.textContent = '';
        result.className = 'connection-result';

        try {
            const model = await this.llm.testConnection();
            this.updateConnectionStatus(true);
            result.className = 'connection-result success';
            result.textContent = `Подключено! Модель: ${model}`;
            Toast.show(`Подключение успешно! Модель: ${model}`);
        } catch (err) {
            this.updateConnectionStatus(false);
            result.className = 'connection-result error';
            result.textContent = `Ошибка: ${err.message}`;
            Toast.show(`Ошибка подключения: ${err.message}`, 'error', 6000);
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }
    }

    async fetchLocalModels() {
        // Save the current URL first
        this.state.settings.localUrl = document.getElementById('setting-local-url').value.trim() || 'http://172.16.33.12:9997';

        const btn = document.getElementById('btn-fetch-models');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span>';
        btn.disabled = true;

        const select = document.getElementById('setting-local-model-select');
        const hint = document.getElementById('local-model-hint');

        try {
            const models = await this.llm.fetchLocalModels();

            select.innerHTML = '';

            if (models.length === 0) {
                select.innerHTML = '<option value="">Модели не найдены</option>';
                hint.textContent = '';
                Toast.show('Сервер доступен, но модели не найдены', 'warning');
                return;
            }

            select.innerHTML = `<option value="">-- Выберите модель (${models.length}) --</option>`;
            this._localModelsCache = {};
            models.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m.id;
                let label = m.name;
                if (m.contextLength) label += ` [${Math.round(m.contextLength / 1024)}K]`;
                if (m.owned_by) label += ` (${m.owned_by})`;
                opt.textContent = label;
                select.appendChild(opt);
                this._localModelsCache[m.id] = m;
            });

            hint.textContent = `(найдено: ${models.length})`;

            // Auto-select if current model matches saved setting
            const current = this.state.settings.localModel;
            if (current) {
                select.value = current;
            }

            // Auto-select first if only one model
            if (models.length === 1) {
                select.value = models[0].id;
            }

            // Show type indicator for selected model
            this.updateLocalModelTypeIndicator(select.value);

            this.updateConnectionStatus(true);
            Toast.show(`Найдено моделей: ${models.length}`);
        } catch (err) {
            select.innerHTML = '<option value="">Ошибка загрузки</option>';
            hint.textContent = '';
            Toast.show(`Не удалось загрузить модели: ${err.message}`, 'error', 6000);
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }
    }

    updateConnectionStatus(forceOnline = null) {
        const sidebarStatus = document.getElementById('connection-status');
        const apiStatus = document.getElementById('api-status');

        const hasConfig = this.state.settings.mode === 'cloud'
            ? !!this.state.settings.cloudApiKey
            : !!this.state.settings.localUrl;

        const isOnline = forceOnline !== null ? forceOnline : hasConfig;

        if (isOnline) {
            sidebarStatus.className = 'connection-status online';
            sidebarStatus.querySelector('.status-text').textContent = 'Подключено';
            if (apiStatus) {
                apiStatus.className = 'status-badge online';
                apiStatus.querySelector('span:last-child').textContent = 'Подключено';
            }
        } else {
            sidebarStatus.className = 'connection-status offline';
            sidebarStatus.querySelector('.status-text').textContent = 'Не подключено';
            if (apiStatus) {
                apiStatus.className = 'status-badge offline';
                apiStatus.querySelector('span:last-child').textContent = 'Нет подключения';
            }
        }
    }

    updateLocalModelTypeIndicator(modelName) {
        const indicator = document.getElementById('local-model-type');
        if (!indicator) return;

        if (!modelName) {
            indicator.style.display = 'none';
            return;
        }

        const isReasoning = isLikelyReasoningModel(modelName);

        // Auto-set context window from model metadata if available
        const modelData = this._localModelsCache?.[modelName];
        let ctxInfo = '';
        if (modelData?.contextLength) {
            const ctxK = Math.round(modelData.contextLength / 1024);
            ctxInfo = ` | Контекст: ${ctxK}K`;
            // Auto-select closest context window value
            const ctxSelect = document.getElementById('setting-context-window');
            const options = [...ctxSelect.options].map(o => parseInt(o.value));
            const closest = options.reduce((prev, curr) =>
                Math.abs(curr - modelData.contextLength) < Math.abs(prev - modelData.contextLength) ? curr : prev
            );
            ctxSelect.value = closest;
            const ctxVal = parseInt(ctxSelect.value);
            document.getElementById('context-window-value').textContent = ctxVal >= 1024 ? (ctxVal / 1024) + 'K' : ctxVal;
        }

        indicator.style.display = 'flex';
        if (isReasoning) {
            indicator.className = 'local-model-type type-reasoning';
            indicator.innerHTML = `<svg class="icon"><use href="#i-brain"/></svg> Рассуждающая модель (CoT)${ctxInfo}`;
        } else {
            indicator.className = 'local-model-type type-standard';
            indicator.innerHTML = `<svg class="icon"><use href="#i-chat"/></svg> Стандартная модель${ctxInfo}`;
        }
    }

    /* ------ Prompts Table ------ */
    renderPromptsTable() {
        const tbody = document.getElementById('prompts-tbody');
        if (!tbody) return;

        tbody.innerHTML = this.state.prompts.map(p => {
            const role = ROLES[p.role] || ROLES.developer;
            return `
                <tr data-prompt-id="${p.id}">
                    <td>
                        <div class="table-role-cell">
                            <div class="table-role-icon ${p.role}">
                                <svg class="icon"><use href="#${role.icon}"/></svg>
                            </div>
                            <div>
                                <div class="table-role-name">${role.name}</div>
                                <div class="table-role-sub">${role.team}</div>
                            </div>
                        </div>
                    </td>
                    <td><span class="table-badge ${p.role}">${p.actionName}</span></td>
                    <td><div class="table-prompt-text" title="${MarkdownRenderer.escapeHtml(p.systemPrompt)}">${MarkdownRenderer.escapeHtml(p.systemPrompt.substring(0, 150))}...</div></td>
                    <td>${p.contextFile
                        ? `<span class="table-file-badge"><svg class="icon"><use href="#i-attach"/></svg>${MarkdownRenderer.escapeHtml(p.contextFile)}</span>`
                        : '<span style="color:var(--text-muted)">—</span>'
                    }</td>
                    <td>
                        <div class="table-actions">
                            <button class="table-action-btn edit" data-id="${p.id}" title="Редактировать">
                                <svg class="icon"><use href="#i-edit"/></svg>
                            </button>
                            <button class="table-action-btn delete" data-id="${p.id}" title="Удалить">
                                <svg class="icon"><use href="#i-delete"/></svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        // Bind edit/delete
        tbody.querySelectorAll('.table-action-btn.edit').forEach(btn => {
            btn.addEventListener('click', () => this.openPromptModal(btn.dataset.id));
        });

        tbody.querySelectorAll('.table-action-btn.delete').forEach(btn => {
            btn.addEventListener('click', () => this.deletePrompt(btn.dataset.id));
        });
    }

    filterPromptsTable(query) {
        const q = query.toLowerCase();
        document.querySelectorAll('#prompts-tbody tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(q) ? '' : 'none';
        });
    }

    deletePrompt(id) {
        if (!confirm('Удалить этот промпт?')) return;
        this.state.prompts = this.state.prompts.filter(p => p.id !== id);
        this.state.savePrompts();
        this.renderPromptsTable();
        this.renderActionButtons();
        this.selectFirstAction();
        Toast.show('Промпт удалён');
    }

    /* ------ Prompt Modal ------ */
    bindModals() {
        document.getElementById('btn-modal-close').addEventListener('click', () => this.closePromptModal());
        document.getElementById('btn-modal-cancel').addEventListener('click', () => this.closePromptModal());
        document.getElementById('btn-modal-save').addEventListener('click', () => this.savePromptFromModal());

        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) this.closePromptModal();
        });

        // Modal context file picker
        document.getElementById('modal-context-file').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            if (file.size > 512 * 1024) {
                Toast.show('Файл слишком большой. Максимум: 500 КБ', 'error');
                e.target.value = '';
                return;
            }
            const reader = new FileReader();
            reader.onload = (ev) => {
                const content = ev.target.result;
                const sample = content.substring(0, 1000);
                const nonPrintable = (sample.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
                if (nonPrintable > sample.length * 0.1) {
                    Toast.show('Файл содержит бинарные данные', 'error');
                    return;
                }
                this._modalContextFile = file.name;
                this._modalContextContent = content;
                const sizeLabel = file.size < 1024 ? `${file.size} Б` : `${(file.size / 1024).toFixed(1)} КБ`;
                document.getElementById('modal-context-filename').textContent = `${file.name} (${sizeLabel})`;
                document.getElementById('modal-context-info').style.display = 'flex';
            };
            reader.onerror = () => Toast.show('Ошибка чтения файла', 'error');
            reader.readAsText(file);
        });

        document.getElementById('btn-modal-context-clear').addEventListener('click', () => {
            this._modalContextFile = '';
            this._modalContextContent = '';
            document.getElementById('modal-context-info').style.display = 'none';
            document.getElementById('modal-context-file').value = '';
        });

        // History modal
        document.getElementById('btn-history-modal-close').addEventListener('click', () => this.closeHistoryModal());
        document.getElementById('btn-history-modal-close2').addEventListener('click', () => this.closeHistoryModal());
        document.getElementById('btn-history-restore').addEventListener('click', () => this.restoreFromHistory());

        document.getElementById('history-modal-overlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) this.closeHistoryModal();
        });
    }

    openPromptModal(id) {
        this.editingPromptId = id;
        const modal = document.getElementById('modal-overlay');
        const title = document.getElementById('modal-title');
        const fileInfo = document.getElementById('modal-context-info');
        const fileNameEl = document.getElementById('modal-context-filename');

        if (id) {
            const prompt = this.state.getPromptById(id);
            if (!prompt) return;
            title.textContent = 'Редактировать промпт';
            document.getElementById('modal-role').value = prompt.role;
            document.getElementById('modal-action').value = prompt.actionName;
            document.getElementById('modal-prompt').value = prompt.systemPrompt;
            this._modalContextFile = prompt.contextFile || '';
            this._modalContextContent = prompt.contextContent || '';
        } else {
            title.textContent = 'Новый промпт';
            document.getElementById('modal-role').value = 'infosec';
            document.getElementById('modal-action').value = '';
            document.getElementById('modal-prompt').value = '';
            this._modalContextFile = '';
            this._modalContextContent = '';
        }

        // Show/hide file info
        if (this._modalContextFile) {
            fileNameEl.textContent = this._modalContextFile;
            fileInfo.style.display = 'flex';
        } else {
            fileInfo.style.display = 'none';
        }
        document.getElementById('modal-context-file').value = '';

        modal.style.display = 'flex';
    }

    closePromptModal() {
        document.getElementById('modal-overlay').style.display = 'none';
        this.editingPromptId = null;
        this._modalContextFile = '';
        this._modalContextContent = '';
    }

    savePromptFromModal() {
        const role = document.getElementById('modal-role').value;
        const actionName = document.getElementById('modal-action').value.trim();
        const systemPrompt = document.getElementById('modal-prompt').value.trim();

        if (!actionName || !systemPrompt) {
            Toast.show('Заполните название действия и текст промпта', 'warning');
            return;
        }

        if (this.editingPromptId) {
            const prompt = this.state.getPromptById(this.editingPromptId);
            if (prompt) {
                prompt.role = role;
                prompt.actionName = actionName;
                prompt.systemPrompt = systemPrompt;
                prompt.contextFile = this._modalContextFile;
                prompt.contextContent = this._modalContextContent;
            }
        } else {
            this.state.prompts.push({
                id: 'custom_' + Date.now(),
                role,
                actionName,
                systemPrompt,
                contextFile: this._modalContextFile,
                contextContent: this._modalContextContent
            });
        }

        this.state.savePrompts();
        this.renderPromptsTable();
        this.renderActionButtons();
        this.selectFirstAction();
        this.closePromptModal();
        this.updateTokenMeter();
        Toast.show('Промпт сохранён');
    }

    /* ------ History Page ------ */
    bindHistoryPage() {
        document.getElementById('btn-clear-all-history').addEventListener('click', () => {
            if (!confirm('Очистить всю историю?')) return;
            this.state.history = [];
            this.state.saveHistory();
            this.renderHistory();
            Toast.show('История очищена');
        });
    }

    renderHistory() {
        const container = document.getElementById('history-list');

        if (this.state.history.length === 0) {
            container.innerHTML = `
                <div class="history-empty">
                    <svg class="icon"><use href="#i-history"/></svg>
                    <p>История пуста</p>
                    <span>Результаты анализа будут сохраняться автоматически</span>
                </div>
            `;
            return;
        }

        container.innerHTML = this.state.history.map(entry => {
            const role = ROLES[entry.role] || ROLES.developer;
            const date = new Date(entry.timestamp);
            const dateStr = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
            const timeStr = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            const lang = LANGUAGES[entry.language] || entry.language;
            const snippet = entry.codeSnippet ? entry.codeSnippet.substring(0, 60) + '...' : '';

            return `
                <div class="history-item" data-history-id="${entry.id}">
                    <div class="history-item-icon ${entry.role}">
                        <svg class="icon"><use href="#${role.icon}"/></svg>
                    </div>
                    <div class="history-item-body">
                        <div class="history-item-title">${role.name} — ${entry.action}</div>
                        <div class="history-item-meta">
                            <span>${lang}</span>
                            <span>${dateStr} ${timeStr}</span>
                            <span>${snippet}</span>
                        </div>
                    </div>
                    <div class="history-item-actions">
                        <button class="table-action-btn delete history-delete-btn" data-id="${entry.id}" title="Удалить">
                            <svg class="icon"><use href="#i-delete"/></svg>
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        // Bind click to view
        container.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (e.target.closest('.history-delete-btn')) return;
                this.openHistoryModal(item.dataset.historyId);
            });
        });

        // Bind delete
        container.querySelectorAll('.history-delete-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.deleteHistoryEntry(btn.dataset.id);
            });
        });
    }

    deleteHistoryEntry(id) {
        this.state.history = this.state.history.filter(h => h.id !== id);
        this.state.saveHistory();
        this.renderHistory();
        Toast.show('Запись удалена');
    }

    openHistoryModal(id) {
        const entry = this.state.history.find(h => h.id === id);
        if (!entry) return;

        this._viewingHistoryId = id;
        const role = ROLES[entry.role] || ROLES.developer;
        const lang = LANGUAGES[entry.language] || entry.language;

        document.getElementById('history-modal-title').textContent =
            `${role.name} — ${entry.action} (${lang})`;

        const container = document.getElementById('history-modal-messages');
        container.innerHTML = '';

        (entry.messages || []).forEach(msg => {
            const div = document.createElement('div');
            div.className = `msg msg-${msg.role}`;
            const avatarText = msg.role === 'user' ? 'Вы' : 'AI';
            const name = msg.role === 'user' ? 'Вы' : 'AI сканер';
            const copyBtn = msg.role === 'assistant'
                ? `<button class="btn-copy-msg" title="Скопировать ответ"><svg class="icon"><use href="#i-copy"/></svg></button>`
                : '';

            div.innerHTML = `
                <div class="msg-avatar">${avatarText}</div>
                <div class="msg-body">
                    <div class="msg-header">
                        <span class="msg-name">${name}</span>
                        <span class="msg-time">${msg.time || ''}</span>
                        ${copyBtn}
                    </div>
                    <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : MarkdownRenderer.escapeHtml(msg.content)}</div>
                </div>
            `;
            this.bindMsgCopyBtn(div);
            container.appendChild(div);
        });

        document.getElementById('history-modal-overlay').style.display = 'flex';
    }

    closeHistoryModal() {
        document.getElementById('history-modal-overlay').style.display = 'none';
        this._viewingHistoryId = null;
    }

    restoreFromHistory() {
        const entry = this.state.history.find(h => h.id === this._viewingHistoryId);
        if (!entry) return;

        // Navigate to analysis, restore messages
        this.navigateTo('analysis');
        this.clearChat();

        // Set selectors
        document.getElementById('role-select').value = entry.role;
        this.state.selectedRole = entry.role;
        this.state.selectedLang = entry.language;
        document.getElementById('lang-select').value = entry.language;
        this.renderActionButtons();
        this.selectFirstAction();

        // Restore messages
        (entry.messages || []).forEach(msg => {
            this.addChatMessage(msg.role, msg.content, msg.meta);
        });

        document.getElementById('chat-followup').disabled = false;
        document.getElementById('btn-send-followup').disabled = false;

        this.closeHistoryModal();
        Toast.show('Сессия восстановлена');
    }

    /* ------ Help Page ------ */
    bindHelpPage() {
        document.querySelectorAll('.help-toc-item[data-scroll]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = item.dataset.scroll;
                const target = document.getElementById(targetId);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    }

    bindHelpLinks() {
        document.querySelectorAll('.help-link-btn[data-help-target]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const sectionId = btn.dataset.helpTarget;
                this.navigateToHelp(sectionId);
            });
        });
    }

    /* ------ Global Keyboard Shortcuts ------ */
    bindGlobalKeys() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                // Close modals first
                const promptModal = document.getElementById('modal-overlay');
                if (promptModal && promptModal.style.display !== 'none' && promptModal.style.display !== '') {
                    this.closePromptModal();
                    return;
                }
                const historyModal = document.getElementById('history-modal-overlay');
                if (historyModal && historyModal.style.display !== 'none' && historyModal.style.display !== '') {
                    this.closeHistoryModal();
                    return;
                }
                // Stop generation
                if (this.state.isGenerating) {
                    this.stopGeneration();
                }
            }
        });

        // Ctrl+Enter to analyze from code textarea
        document.getElementById('code-input').addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if (!document.getElementById('btn-analyze').disabled) {
                    this.runAnalysis();
                }
            }
        });
    }

    navigateToHelp(sectionId) {
        this.navigateTo('help');
        setTimeout(() => {
            const target = document.getElementById(sectionId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }, 100);
    }

    /* ------ Copy Code Helper ------ */
    copyCode(button) {
        const pre = button.nextElementSibling;
        const code = pre?.textContent || '';
        navigator.clipboard.writeText(code).then(() => {
            const orig = button.textContent;
            button.textContent = 'Скопировано!';
            setTimeout(() => button.textContent = orig, 1500);
        }).catch(() => {
            Toast.show('Не удалось скопировать', 'warning');
        });
    }
}

/* ============================================================
   INITIALIZE
   ============================================================ */
let App;
document.addEventListener('DOMContentLoaded', () => {
    App = new Application();

    // Expose copyCode globally for inline onclick
    window.App = App;
});
