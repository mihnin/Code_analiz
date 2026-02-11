/* ============================================================
   CodeSentinel — AI Code Analysis Application
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
            localUrl: 'http://localhost:1234',
            localModel: ''
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
            url: (s.localUrl || 'http://localhost:1234').replace(/\/+$/, '') + '/v1/chat/completions',
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
            temperature: 0.3,
            max_tokens: 4096
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
                    const delta = parsed.choices?.[0]?.delta?.content;
                    if (delta) {
                        fullContent += delta;
                        onChunk(delta, fullContent);
                    }
                } catch { /* skip malformed chunks */ }
            }
        }

        return fullContent;
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

        // Unordered lists
        html = html.replace(/^(\s*)-\s+(.+)$/gm, '<li>$2</li>');
        html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

        // Ordered lists
        html = html.replace(/^(\s*)\d+\.\s+(.+)$/gm, '<li>$2</li>');

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
        this.init();
    }

    init() {
        this.bindNavigation();
        this.bindAnalysisPage();
        this.bindSettingsPage();
        this.bindHistoryPage();
        this.bindModals();
        this.bindMobileMenu();
        this.bindSidebarToggle();

        this.renderActionButtons();
        this.renderSettingsForm();
        this.renderPromptsTable();
        this.renderHistory();
        this.updateConnectionStatus();
        this.selectFirstAction();
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
        const reader = new FileReader();
        reader.onload = (e) => {
            this.state.attachedFile = file.name;
            this.state.attachedFileContent = e.target.result;
            const info = document.getElementById('attached-file-info');
            document.getElementById('attached-filename').textContent = file.name;
            info.style.display = 'flex';
            Toast.show(`Файл "${file.name}" прикреплён`);
        };
        reader.readAsText(file);
    }

    removeAttachedFile() {
        this.state.attachedFile = null;
        this.state.attachedFileContent = '';
        document.getElementById('attached-file-info').style.display = 'none';
        document.getElementById('file-input').value = '';
    }

    updateCodeStats() {
        const code = document.getElementById('code-input').value;
        const lines = code ? code.split('\n').length : 0;
        const chars = code.length;
        document.getElementById('code-stats').textContent = `${lines} строк | ${chars} символов`;
    }

    updateAnalyzeButton() {
        const code = document.getElementById('code-input').value.trim();
        const btn = document.getElementById('btn-analyze');
        btn.disabled = !code || !this.state.selectedAction || this.state.isGenerating;
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
        const name = msg.role === 'user' ? 'Вы' : 'CodeSentinel AI';

        const metaHtml = msg.meta ? `<span class="msg-meta">${msg.meta}</span>` : '';

        div.innerHTML = `
            <div class="msg-avatar">${avatarText}</div>
            <div class="msg-body">
                <div class="msg-header">
                    <span class="msg-name">${name}</span>
                    <span class="msg-time">${msg.time}</span>
                    ${metaHtml}
                </div>
                <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : MarkdownRenderer.escapeHtml(msg.content)}</div>
            </div>
        `;

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
                    <span class="msg-name">CodeSentinel AI</span>
                    <span class="msg-time">${new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
                <div class="msg-content"><div class="typing-indicator"><span></span><span></span><span></span></div></div>
            </div>
        `;

        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return div;
    }

    updateStreamingMessage(div, fullContent) {
        const contentEl = div.querySelector('.msg-content');
        contentEl.innerHTML = MarkdownRenderer.render(fullContent);
        const container = document.getElementById('chat-messages');
        container.scrollTop = container.scrollHeight;
    }

    clearChat() {
        this.state.chatMessages = [];
        this.state.conversationHistory = [];
        const container = document.getElementById('chat-messages');
        container.innerHTML = `
            <div class="chat-welcome">
                <div class="welcome-icon"><svg class="icon"><use href="#i-brain"/></svg></div>
                <h3>CodeSentinel AI</h3>
                <p>Выберите роль, язык и действие, затем вставьте код и нажмите "Анализировать"</p>
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
    }

    exportChat() {
        if (this.state.chatMessages.length === 0) {
            Toast.show('Нет сообщений для экспорта', 'warning');
            return;
        }

        const lines = this.state.chatMessages.map(m => {
            const prefix = m.role === 'user' ? '## Вы' : '## CodeSentinel AI';
            return `${prefix} (${m.time})\n\n${m.content}`;
        });

        const text = `# CodeSentinel — Результаты анализа\nДата: ${new Date().toLocaleString('ru-RU')}\n\n---\n\n${lines.join('\n\n---\n\n')}`;

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
        const meta = `${role.shortName} → ${prompt.actionName} → ${lang}`;

        // Add user message
        this.addChatMessage('user', code, meta);

        // Build API messages
        const messages = this.llm.buildMessages(
            prompt.systemPrompt,
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

            const fullContent = await this.llm.callLLM(
                messages,
                (chunk, fullText) => this.updateStreamingMessage(streamDiv, fullText),
                this.state.abortController.signal
            );

            // Save to conversation history
            this.state.conversationHistory.push({ role: 'assistant', content: fullContent });
            this.state.chatMessages.push({
                role: 'assistant',
                content: fullContent,
                time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
            });

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
                this.updateStreamingMessage(streamDiv, '*Генерация остановлена пользователем*');
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

            const fullContent = await this.llm.callLLM(
                this.state.conversationHistory,
                (chunk, fullText) => this.updateStreamingMessage(streamDiv, fullText),
                this.state.abortController.signal
            );

            this.state.conversationHistory.push({ role: 'assistant', content: fullContent });
            this.state.chatMessages.push({
                role: 'assistant',
                content: fullContent,
                time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
            });

        } catch (err) {
            if (err.name === 'AbortError') {
                this.updateStreamingMessage(streamDiv, '*Генерация остановлена*');
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

            if (mode === 'cloud') {
                cloudSettings.classList.remove('disabled');
                localSettings.classList.add('disabled');
                localSettings.querySelector('.label-badge').textContent = 'Отключено';
                cloudSettings.querySelector('.label-hint')?.classList.remove('hidden');
            } else {
                localSettings.classList.remove('disabled');
                cloudSettings.classList.add('disabled');
                localSettings.querySelector('.label-badge').textContent = 'Активно';
            }
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
        document.getElementById('setting-cloud-model').value = s.cloudModel || 'deepseek-chat';
        document.getElementById('setting-cloud-url').value = s.cloudUrl || 'https://api.deepseek.com';
        document.getElementById('setting-local-url').value = s.localUrl || 'http://localhost:1234';
        document.getElementById('setting-local-model').value = s.localModel || '';

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
        this.state.settings.cloudModel = document.getElementById('setting-cloud-model').value.trim() || 'deepseek-chat';
        this.state.settings.cloudUrl = document.getElementById('setting-cloud-url').value.trim() || 'https://api.deepseek.com';
        this.state.settings.localUrl = document.getElementById('setting-local-url').value.trim() || 'http://localhost:1234';
        this.state.settings.localModel = document.getElementById('setting-local-model').value.trim();
        this.state.saveSettings();
        this.updateConnectionStatus();
    }

    async testConnection() {
        this.saveSettingsFromForm();

        const btn = document.getElementById('btn-test-connection');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Проверка...';
        btn.disabled = true;

        try {
            const model = await this.llm.testConnection();
            this.updateConnectionStatus(true);
            Toast.show(`Подключение успешно! Модель: ${model}`);
        } catch (err) {
            this.updateConnectionStatus(false);
            Toast.show(`Ошибка подключения: ${err.message}`, 'error', 6000);
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

        if (id) {
            const prompt = this.state.getPromptById(id);
            if (!prompt) return;
            title.textContent = 'Редактировать промпт';
            document.getElementById('modal-role').value = prompt.role;
            document.getElementById('modal-action').value = prompt.actionName;
            document.getElementById('modal-prompt').value = prompt.systemPrompt;
            document.getElementById('modal-context').value = prompt.contextFile || '';
        } else {
            title.textContent = 'Новый промпт';
            document.getElementById('modal-role').value = 'infosec';
            document.getElementById('modal-action').value = '';
            document.getElementById('modal-prompt').value = '';
            document.getElementById('modal-context').value = '';
        }

        modal.style.display = 'flex';
    }

    closePromptModal() {
        document.getElementById('modal-overlay').style.display = 'none';
        this.editingPromptId = null;
    }

    savePromptFromModal() {
        const role = document.getElementById('modal-role').value;
        const actionName = document.getElementById('modal-action').value.trim();
        const systemPrompt = document.getElementById('modal-prompt').value.trim();
        const contextFile = document.getElementById('modal-context').value.trim();

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
                prompt.contextFile = contextFile;
            }
        } else {
            this.state.prompts.push({
                id: 'custom_' + Date.now(),
                role,
                actionName,
                systemPrompt,
                contextFile
            });
        }

        this.state.savePrompts();
        this.renderPromptsTable();
        this.renderActionButtons();
        this.selectFirstAction();
        this.closePromptModal();
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
            const name = msg.role === 'user' ? 'Вы' : 'CodeSentinel AI';

            div.innerHTML = `
                <div class="msg-avatar">${avatarText}</div>
                <div class="msg-body">
                    <div class="msg-header">
                        <span class="msg-name">${name}</span>
                        <span class="msg-time">${msg.time || ''}</span>
                    </div>
                    <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : MarkdownRenderer.escapeHtml(msg.content)}</div>
                </div>
            `;
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
