# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI сканер** — Role-Based AI Code Assistant SPA for enterprise analysis of source code, functional specifications (ФС), and technical requirements (ТЗ). Supports ABAP, 1C, Python, JavaScript. Three roles: InfoSec, Consultant, Developer. Connects to cloud API (DeepSeek) or local models (LM Studio, Ollama, Xinference) via OpenAI-compatible protocol.

## Running

No build tools, no npm, no bundlers. Open `index.html` directly in a browser. Fully autonomous — zero external dependencies.

**Deployment files** (air-gapped/КСПД): `index.html`, `styles.css`, `app.js`, `logo.png` — 4 files in one folder.

## Architecture

Three-file SPA: `index.html` (structure + 30 inline SVG icons), `styles.css` (dark theme via CSS custom properties), `app.js` (all logic).

### app.js Structure

- **`REASONING_PATTERNS` + `isLikelyReasoningModel()`** — heuristic detection of thinking/reasoning models by name patterns (`r1`, `reasoner`, `qwen3`, `qwq`, `cot`, `thinking`).
- **`AppState`** — centralized state: settings, prompts, history, chat messages. Persists to `localStorage`.
- **`LLMService`** — API calls via OpenAI-compatible protocol. `callLLM()` streams SSE, parses both `delta.content` and `delta.reasoning_content`, returns `{ content, reasoning }`. `testConnection()` pings API. `fetchLocalModels()` discovers models via GET `/v1/models` (also extracts `context_length` metadata).
- **`MarkdownRenderer`** — static class. Markdown→HTML with XSS protection (escape first, restore code blocks after). Supports: headers, bold/italic, tables, ordered/unordered lists, code blocks (with copy button), blockquotes, horizontal rules.
- **`TokenEstimator`** — static class. Cyrillic ~2 chars/token, Latin/code ~4 chars/token. Drives real-time token meter.
- **`Toast`** — notification system.
- **`Application`** — main controller. Pages: analysis, settings, history, help. Manages streaming with reasoning support, prompt CRUD, model type indicators, keyboard shortcuts.

### Data Flow

1. User selects Role → Language → Action → pastes code/text
2. `runAnalysis()` finds prompt, appends `contextContent` (instruction file) to system prompt with `--- Дополнительные инструкции ---` separator
3. `buildMessages()` constructs: `[system + instructions] + [language] + [attached file] + [user code]`
4. `callLLM()` streams SSE; `onChunk({ contentDelta, reasoningDelta, fullContent, fullReasoning })` updates UI in real-time
5. `updateStreamingMessage()` renders content via MarkdownRenderer, shows reasoning section with toggle if model produces `reasoning_content`
6. `finalizeStreamingMessage()` adds model badge: "С рассуждениями (~N токенов)" or "Без рассуждений" (local mode only)
7. Conversation history maintained for follow-ups; token meter updates after each exchange

### Reasoning/Thinking Model Support

- **SSE parsing**: `delta.reasoning_content` accumulated into `fullReasoning`, `delta.content` into `fullContent`
- **Return format**: `callLLM()` returns `{ content: string, reasoning: string }`
- **UI**: collapsible reasoning section (`.msg-reasoning`) with brain icon, pulsing animation during thinking, token count after completion
- **Model detection**: `isLikelyReasoningModel()` checks name patterns; actual detection confirmed by `reasoning_content` presence in stream
- **Settings indicator**: `updateLocalModelTypeIndicator()` shows "Рассуждающая модель (CoT)" or "Стандартная модель" with auto-detected context window

### Two File Attachment Systems

| | Main panel "Файл контекста" | Prompt → "Файл инструкций" |
|---|---|---|
| **What** | User data (code, specs) | Rules/standards/policies for AI |
| **Goes into** | `user` message | `system` message (appended to prompt) |
| **Lifetime** | One analysis session | Saved with prompt in localStorage |
| **Stored as** | `state.attachedFileContent` | `prompt.contextContent` |

### Token Budget System

Token meter in code panel footer tracks context window usage in real-time:
- **Segments**: system prompt (purple) + user input (blue) + attached file (yellow) + chat history (teal) + reserved for response (grey)
- **Budget**: `usedTokens + maxTokens` ≤ `contextWindow`; bar yellow >80%, red when exceeded
- **Context window**: client-side only (not sent to API); must match model's real context window for accurate meter. Auto-set to 8K for local, 64K for cloud on mode switch. Auto-detected from model metadata when available.

### API Configuration

- **Cloud**: DeepSeek API (OpenAI-compatible). `deepseek-chat` (fast) and `deepseek-reasoner` (CoT).
- **Local**: LM Studio/Ollama/Xinference at configurable URL. `/v1/chat/completions` for inference, `/v1/models` for discovery (with `context_length` extraction).
- **Shared settings**: `contextWindow` (4K–256K), `maxTokens` (256–16384, default 4096), `temperature` (0–2, default 0.3). All sent to API except `contextWindow`.

### localStorage Keys

| Key | Content |
|-----|---------|
| `codesentinel_settings` | API config, mode, model, temperature, maxTokens, contextWindow |
| `codesentinel_prompts` | User-customized prompts matrix (including contextContent) |
| `codesentinel_history` | Past analysis sessions (max 50) |
| `codesentinel_sidebar_collapsed` | Sidebar visibility state |

### Keyboard Shortcuts

- **Ctrl+Enter** in code textarea — run analysis
- **Escape** — close modals, stop generation
- **Tab** in code textarea — insert 4 spaces

## Design System

CSS custom properties in `:root`. Key tokens:
- Colors: `--primary: #135bec`, `--bg-body: #101622`, `--bg-surface: #1a2234`
- Role colors: `--role-infosec` (indigo), `--role-consultant` (amber), `--role-developer` (teal)
- Reasoning: purple theme (`#a855f7`) for reasoning UI elements
- All icons are inline SVG `<symbol>` in `index.html` (prefix `i-`), referenced via `<use href="#i-name"/>`

## Key Constraints

- **Fully autonomous**: no external CDN, fonts, or libraries. Must work in air-gapped corporate networks (КСПД).
- **No build step**: pure HTML5 + CSS3 + Vanilla JS (ES6+). Opens directly in browser from filesystem.
- **Russian UI**: all labels, prompts, messages in Russian. Respond to user in Russian.
- **File attachments**: only `.txt` and `.md`. Max 500KB. Binary rejected via heuristic check.
- **Copy buttons**: every AI response has copy-to-clipboard; code blocks inside responses have their own copy button.

## Reference Files

- `example/code1.html`, `example/code2.html` — design reference mockups
- `help.txt` — API documentation reference
- `.env` — DeepSeek API key (gitignored, never commit)
- `logo.png` — brand logo (compass)
