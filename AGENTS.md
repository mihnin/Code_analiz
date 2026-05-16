# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

**AI сканер** — Role-Based AI Code Assistant SPA for enterprise analysis of source code, functional specifications (ФС), and technical requirements (ТЗ). Supports ABAP, 1C, Python, JavaScript. Three roles: InfoSec, Consultant, Developer. Connects to cloud API (DeepSeek) or local models (LM Studio, Ollama, Xinference) via OpenAI-compatible protocol.

## Running

No build tools, no npm, no bundlers. Open `index.html` directly in a browser. Fully autonomous — zero external dependencies.

**Deployment files** (air-gapped/КСПД): `index.html`, `styles.css`, `app.js`, `logo.png` — 4 files in one folder.

**Syntax check**: `node -c app.js` (no runtime needed, just syntax validation).

**Behavior tests**: `node --test tests/vibe_reasoning_fallback.test.js`. These cover VibeCoding reasoning fallback, JSON/recovered review scores, provider URL/model parsing, Python-only Jupyter guidance, copy payload behavior, and auto-collapse rules.

## Architecture

Three-file SPA: `index.html` (structure + 30 inline SVG icons), `styles.css` (dark theme via CSS custom properties), `app.js` (all logic).

### app.js Structure

- **`REASONING_PATTERNS` + `isLikelyReasoningModel()`** — heuristic detection of thinking/reasoning models by name patterns (`r1`, `reasoner`, `qwen3`, `qwq`, `cot`, `thinking`).
- **`AppState`** — centralized state: settings, prompts, history, chat messages. Persists to `localStorage`. `getPromptsForRole(role, language)` filters prompts by role and optionally by programming language.
- **`LLMService`** — API calls via OpenAI-compatible protocol. `callLLM()` streams SSE, parses `delta.content`, `delta.reasoning_content`, and `delta.reasoning`, returns `{ content, reasoning }`. `testConnection()` pings API. `fetchLocalModels()` discovers models via GET `/v1/models` (also extracts `context_length` metadata). `_createTimeoutSignal(ms)` — polyfill for `AbortSignal.timeout()` (browser compatibility).
- **`MarkdownRenderer`** — static class. Markdown→HTML with XSS protection (escape first, restore code blocks after). Supports: headers, bold/italic, tables, ordered/unordered lists, code blocks (with copy button via event delegation), blockquotes, horizontal rules.
- **`TokenEstimator`** — static class. Cyrillic ~2 chars/token, Latin/code ~4 chars/token. Drives real-time token meter.
- **`Toast`** — notification system with null-safe container access.
- **`AdminManager`** — admin page controller. Password-gated (`ADMIN_PASSWORD`), manages support chat settings (API config, system prompt, generation params). Persists to `codesentinel_admin_settings`.
- **`SupportChat`** — floating support widget (bottom-right sphere button). Uses its own LLM connection (separate from main analysis). Default system prompt knows the app internals; escalates complex questions to Мартьянов Николай.
- **`Application`** — main controller. Pages: analysis, settings, history, help, admin. Manages streaming with reasoning support, prompt CRUD, model type indicators, keyboard shortcuts. Key utilities:
  - `_validateTextFile(file)` / `_isBinaryContent(content)` / `_formatFileSize(size)` — shared file validation (extension whitelist + binary heuristic + size limit)
  - `_hasModalUnsavedChanges()` — protects against accidental modal close with unsaved data
  - `_startWaitingTimer(div)` / `_clearWaitingTimer()` — elapsed time indicator while waiting for first LLM response chunk
  - `bindCodeCopyDelegation()` — event delegation for dynamically created code block copy buttons (no inline `onclick`)
- **`VibeCodingManager`** — two-model coding loop. Coder writes code, Reviewer scores it, failed scores feed the next coder iteration. Handles reasoning-only LLM output, score parsing/recovery, JSON score fallback, iteration copy buttons, auto-collapsing old iterations, and Python/Jupyter-specific prompt guidance.

### Local Provider Support

Local inference is split into two concepts:
- **API type** (`localProvider`): `lmstudio`, `ollama`, or `xinference`. This controls endpoint paths and model-list parsing.
- **API address** (`localUrl`): actual host/port such as `http://localhost:1234`, `http://localhost:11434`, `http://127.0.0.1:9997`, or a corporate server IP.

`LOCAL_PROVIDER_CONFIG` defines provider labels, default URLs, chat paths, and model-list paths. `LLMService.buildLocalChatUrl()` and `buildLocalModelListUrls()` must be used instead of hand-building `/v1/...` URLs. Ollama discovery supports `/api/tags`; LM Studio and Xinference use OpenAI-compatible `/v1/models`.

When deploying to a server with only Xinference, choose **Тип локального API = Xinference** and set **Адрес API-сервера** to the server URL, for example `http://SERVER_IP:9997`. Use `127.0.0.1` only when the browser runs on the same host as Xinference.

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
- **VibeCoding edge case**: `VibeCodingManager._getLLMVisibleText()` uses `content` first, then falls back to `reasoning`. This is required for models that answer reasoning-only through LM Studio/Xinference.

### VibeCoding

VibeCoding is a separate page with a two-model cycle:
1. Coder receives the task plus optional previous review and returns a full code version.
2. Reviewer checks that code and must provide a score.
3. If the score is below threshold, the next coder iteration receives the previous code plus cleaned reviewer remarks.

Important implementation details:
- Settings keys: `vibeCoderModel`, `vibeReviewerModel`, `vibeMaxIterations`, `vibeScoreThreshold`, `vibeCoderPrompt`, `vibeReviewerPrompt`.
- Coder and Reviewer always use the local provider configured in the main settings.
- Reviewer score parsing accepts `ОЦЕНКА: N/10`, `SCORE: N/10`, bare `N/10`, and strict/fenced JSON such as `{"score": 8}`.
- If the review text exists but score parsing fails, `_buildScoreRecoveryMessages()` asks a short recovery prompt through the coder model when available.
- Iterations have small top-right widgets: collapse/expand and copy. Coder copy payload is the extracted final code; Reviewer copy payload is the full review text.
- When a newer iteration starts, older iteration cards auto-collapse. Users can reopen them with the chevron button.
- For selected language `python`, `_buildVibeLanguageInstruction()` adds notebook guidance to both Coder and Reviewer: code is intended for one Jupyter Notebook/JupyterLab cell, not a CLI `.py` file. Reviewer must not penalize missing `argparse`, `sys.argv`, or `if __name__ == "__main__"` unless the user explicitly requested a script/package. This instruction must not be added for ABAP, 1C, or JavaScript.

### Prompt System

Prompts are stored in `AppState.prompts` array. Each prompt has: `id`, `role`, `language` (optional), `actionName`, `systemPrompt`, `contextContent` (instruction file).

- **Language-specific prompts**: `infosec_python` (Python), `infosec_abap` (ABAP), `infosec_1c` (1С) — deep security analysis tailored to each language's vulnerability patterns (SQL injection variants, AUTHORITY-CHECK for ABAP, Выполнить/COM-objects for 1С, eval/pickle/SSTI for Python)
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
- **Local**: LM Studio/Ollama/Xinference at configurable URL (default `http://172.16.33.12:9997`). Use the selected provider type plus `localUrl`; do not hardcode endpoints. `/v1/chat/completions` is used for OpenAI-compatible inference, while model discovery differs by provider.
- **Shared settings**: `contextWindow` (4K–256K), `maxTokens` (256–16384, default 4096), `temperature` (0–2, default 0.3). All sent to API except `contextWindow`.

### localStorage Keys

| Key | Content |
|-----|---------|
| `codesentinel_settings` | API config, mode, localProvider, model, temperature, maxTokens, contextWindow, VibeCoding settings |
| `codesentinel_prompts` | User-customized prompts matrix (including contextContent, language) |
| `codesentinel_history` | Past analysis sessions (max 50) |
| `codesentinel_sidebar_collapsed` | Sidebar visibility state |
| `codesentinel_admin_settings` | Admin page settings (support chat API config, system prompt) |

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
- **HTML safety**: any persisted/user-controlled string inserted through `innerHTML` must be escaped via `MarkdownRenderer.escapeHtml()` or rendered through DOM APIs (`textContent`, `appendChild`). This includes prompt `actionName`, model names, history snippets, chat metadata, and filenames. Do not regress to raw template interpolation for localStorage-backed data.

## Reference Files

- `example/code1.html`, `example/code2.html` — design reference mockups
- `help.txt` — API documentation reference
- `.env` — DeepSeek API key (gitignored, never commit)
- `logo.png` — brand logo (compass)
- `prompts/infosec_universal_vulnerability_analysis.md` — comprehensive security prompt template (570 lines, all languages)
- `примеры плохих файлов/` — sample vulnerable Python files from InfoSec team (test reference for security prompts)
