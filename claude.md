# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI сканер** — Role-Based AI Code Assistant SPA for enterprise analysis of source code, functional specifications (ФС), and technical requirements (ТЗ). Supports ABAP, 1C, Python, JavaScript. Three roles: InfoSec, Consultant, Developer. Connects to cloud API (DeepSeek) or local models (LM Studio, Ollama, Xinference) via OpenAI-compatible protocol.

## Running

No build tools, no npm, no bundlers. Open `index.html` directly in a browser. Fully autonomous — zero external dependencies.

**Deployment files** (air-gapped/КСПД): `index.html`, `styles.css`, `app.js`, `logo.png` — 4 files in one folder.

**Syntax check**: `node -c app.js` (no runtime needed, just syntax validation).

## Architecture

Three-file SPA: `index.html` (structure + 30 inline SVG icons), `styles.css` (dark theme via CSS custom properties), `app.js` (all logic).

### app.js Structure

- **`REASONING_PATTERNS` + `isLikelyReasoningModel()`** — heuristic detection of thinking/reasoning models by name patterns (`r1`, `reasoner`, `qwen3`, `qwq`, `cot`, `thinking`).
- **`AppState`** — centralized state: settings, prompts, history, chat messages. Persists to `localStorage`. `getPromptsForRole(role, language)` filters prompts by role and optionally by programming language.
- **`LLMService`** — API calls via OpenAI-compatible protocol. `callLLM()` streams SSE, parses `delta.content`, `delta.reasoning_content`, and `delta.reasoning`, returns `{ content, reasoning }`. `testConnection()` pings API. `fetchLocalModels()` discovers models via GET `/v1/models` (also extracts `context_length` metadata). `_createTimeoutSignal(ms)` — polyfill for `AbortSignal.timeout()` (browser compatibility).
- **`MarkdownRenderer`** — static class. Markdown→HTML with XSS protection (escape first, restore code blocks after). Supports: headers, bold/italic, tables, ordered/unordered lists, code blocks (with copy button via event delegation), blockquotes, horizontal rules.
- **`TokenEstimator`** — static class. Cyrillic ~2 chars/token, Latin/code ~4 chars/token. Drives real-time token meter.
- **`Toast`** — notification system with null-safe container access.
- **`Application`** — main controller. Pages: analysis, settings, history, help. Manages streaming with reasoning support, prompt CRUD, model type indicators, keyboard shortcuts. Key utilities:
  - `_validateTextFile(file)` / `_isBinaryContent(content)` / `_formatFileSize(size)` — shared file validation (extension whitelist + binary heuristic + size limit)
  - `_hasModalUnsavedChanges()` — protects against accidental modal close with unsaved data
  - `_startWaitingTimer(div)` / `_clearWaitingTimer()` — elapsed time indicator while waiting for first LLM response chunk
  - `bindCodeCopyDelegation()` — event delegation for dynamically created code block copy buttons (no inline `onclick`)

### Data Flow

1. User selects Role → Language → Action → pastes code/text
2. `runAnalysis()` finds prompt, appends `contextContent` (instruction file) to system prompt with `--- Дополнительные инструкции ---` separator
3. `buildMessages()` constructs: `[system + language instruction] + [language] + [attached file] + [user code]`. Language instruction ("ВАЖНО: Пользователь указал язык — X") enforces correct language detection by the LLM.
4. `createStreamingMessage()` shows waiting indicator with elapsed timer ("Отправка запроса..." → "Ожидание ответа модели... (Xs)")
5. `callLLM()` streams SSE; `onChunk({ contentDelta, reasoningDelta, fullContent, fullReasoning })` updates UI in real-time. First chunk clears the waiting indicator.
6. `updateStreamingMessage()` renders content via MarkdownRenderer, shows reasoning section with toggle if model produces `reasoning_content`
7. `finalizeStreamingMessage()` adds model badge: "С рассуждениями (~N токенов)", "Без рассуждений", or "Рассуждения не получены" (when model detected as reasoning but no reasoning_content received)
8. Conversation history maintained for follow-ups; token meter updates after each exchange

### Reasoning/Thinking Model Support

- **SSE parsing**: `delta.reasoning_content` OR `delta.reasoning` accumulated into `fullReasoning`, `delta.content` into `fullContent`
- **Return format**: `callLLM()` returns `{ content: string, reasoning: string }`
- **UI**: collapsible reasoning section (`.msg-reasoning`) with brain icon, pulsing animation during thinking, token count after completion
- **Model detection**: `isLikelyReasoningModel()` checks name patterns; actual detection confirmed by `reasoning_content` presence in stream
- **Settings indicator**: `updateLocalModelTypeIndicator()` shows "Рассуждающая модель (CoT)" or "Стандартная модель" with auto-detected context window
- **Edge case**: If model is heuristically detected as reasoning but no `reasoning_content` received, badge shows "Рассуждения не получены" with tooltip

### Prompt System

Prompts are stored in `AppState.prompts` array. Each prompt has: `id`, `role`, `language` (optional), `actionName`, `systemPrompt`, `contextContent` (instruction file).

- **Language filtering**: prompts with `language` field only appear when matching language is selected; prompts without `language` appear for all languages
- **Modal editing**: language selector in prompt modal (`#modal-language`); unsaved changes protection via `_hasModalUnsavedChanges()` on overlay click / Escape
- **Instruction files**: `contextContent` appended to system prompt, persisted with prompt in localStorage

### Two File Attachment Systems

| | Main panel "Файл контекста" | Prompt → "Файл инструкций" |
|---|---|---|
| **What** | User data (code, specs) | Rules/standards/policies for AI |
| **Goes into** | `user` message | `system` message (appended to prompt) |
| **Lifetime** | One analysis session | Saved with prompt in localStorage |
| **Stored as** | `state.attachedFileContent` | `prompt.contextContent` |
| **Validation** | `_validateTextFile()` — extension + size + binary check | Same validation |

### Token Budget System

Token meter in code panel footer tracks context window usage in real-time:
- **Segments**: system prompt (purple) + user input (blue) + attached file (yellow) + chat history (teal) + reserved for response (grey)
- **Budget**: `usedTokens + maxTokens` ≤ `contextWindow`; bar yellow >80%, red when exceeded
- **Context window**: client-side only (not sent to API); must match model's real context window for accurate meter. Auto-set to 8K for local, 64K for cloud on mode switch. Auto-detected from model metadata when available.
- **Safety**: division by zero guard when `contextWindow` is 0

### API Configuration

- **Cloud**: DeepSeek API (OpenAI-compatible). `deepseek-chat` (fast) and `deepseek-reasoner` (CoT).
- **Local**: LM Studio/Ollama/Xinference at configurable URL (default `http://172.16.33.12:9997`). `/v1/chat/completions` for inference, `/v1/models` for discovery (with `context_length` extraction).
- **Shared settings**: `contextWindow` (4K–256K), `maxTokens` (256–16384, default 4096), `temperature` (0–2, default 0.3). All sent to API except `contextWindow`.

### localStorage Keys

| Key | Content |
|-----|---------|
| `codesentinel_settings` | API config, mode, model, temperature, maxTokens, contextWindow |
| `codesentinel_prompts` | User-customized prompts matrix (including contextContent, language) |
| `codesentinel_history` | Past analysis sessions (max 50) |
| `codesentinel_sidebar_collapsed` | Sidebar visibility state |

### Keyboard Shortcuts

- **Ctrl+Enter** in code textarea — run analysis
- **Escape** — close modals (with unsaved changes check), stop generation
- **Tab** in code textarea — insert 4 spaces

## Design System

CSS custom properties in `:root`. Key tokens:
- Colors: `--primary: #135bec`, `--bg-body: #101622`, `--bg-surface: #1a2234`
- Role colors: `--role-infosec` (indigo), `--role-consultant` (amber), `--role-developer` (teal)
- Reasoning: purple theme (`#a855f7`) for reasoning UI elements
- Waiting indicator: spinning ring + pulsing text (`.waiting-indicator`, `.waiting-spinner`, `.waiting-text`)
- All icons are inline SVG `<symbol>` in `index.html` (prefix `i-`), referenced via `<use href="#i-name"/>`

## Key Constraints

- **Fully autonomous**: no external CDN, fonts, or libraries. Must work in air-gapped corporate networks (КСПД).
- **No build step**: pure HTML5 + CSS3 + Vanilla JS (ES6+). Opens directly in browser from filesystem.
- **Browser compatibility**: `AbortSignal.timeout()` wrapped in polyfill; no inline `onclick` handlers (event delegation instead).
- **Russian UI**: all labels, prompts, messages in Russian. Respond to user in Russian.
- **File attachments**: only `.txt`, `.md`, `.markdown`. Max 500KB. Binary rejected via heuristic check. Extension validated in JS before reading.
- **Copy buttons**: every AI response has copy-to-clipboard; code blocks inside responses have their own copy button (bound via event delegation).
- **No inline event handlers**: use `addEventListener` or event delegation (`bindCodeCopyDelegation()`).

## Reference Files

- `example/code1.html`, `example/code2.html` — design reference mockups
- `help.txt` — API documentation reference
- `.env` — DeepSeek API key (gitignored, never commit)
- `logo.png` — brand logo (compass)
