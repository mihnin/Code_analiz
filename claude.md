# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI сканер** — Role-Based AI Code Assistant SPA for enterprise analysis of source code, functional specifications (ФС), and technical requirements (ТЗ). Supports ABAP, 1C, Python, JavaScript. Three roles: InfoSec, Consultant, Developer. Connects to cloud API (DeepSeek) or local models (LM Studio, Ollama, Xinference) via OpenAI-compatible protocol.

## Running

No build tools, no npm, no bundlers. Open `index.html` directly in a browser. Fully autonomous — zero external dependencies.

**Deployment files** (air-gapped/КСПД): `index.html`, `styles.css`, `app.js`, `logo.png` — 4 files in one folder. `grep` confirms no other assets referenced anywhere.

**Syntax check**: `node -c app.js` (no runtime needed, just syntax validation). Run this after any non-trivial edit.

**Build deploy archive** (for handing to a colleague / server admin): a small Python snippet bundles the 4 essentials + a Russian-language README into `AI-scanner.zip` under a single `AI-scanner/` folder. The archive **is committed to the repo** for direct GitHub-download distribution — rebuild it after any change to `index.html` / `styles.css` / `app.js` / `logo.png` to keep it in sync. Trade-off acknowledged: binary churn in git history; if that becomes a problem, switch to a release-asset workflow.

## Architecture

Three-file SPA: `index.html` (structure + 30 inline SVG icons), `styles.css` (dark theme via CSS custom properties), `app.js` (all logic).

### app.js Structure

- **`REASONING_PATTERNS` + `isLikelyReasoningModel()`** — heuristic detection of thinking/reasoning models by name patterns (`r1`, `reasoner`, `qwen3`, `qwq`, `cot`, `thinking`).
- **`Schema`** — defensive validator for everything coming out of `localStorage`. Methods: `string`/`number`/`integer`/`boolean`/`oneOf`/`array`/`safeParse`. Used in `AppState.loadFromStorage` and `AdminManager._loadSettings` to type-check every field, clamp ranges, drop invalid array items silently, and fall back to defaults on corrupt JSON. **This is the second line of defense for XSS**: even if a malicious value slips into `localStorage` (manual tamper, sync from another browser, etc.), it's normalized before reaching any renderer.
- **`AppState`** — centralized state: settings, prompts, history, chat messages. Persists to `localStorage`. `getPromptsForRole(role, language)` filters prompts by role and optionally by programming language. `_pruneExpiredHistory(history)` drops entries older than `settings.historyTTLDays` (0 = no TTL). `addHistoryEntry()` no-ops when `settings.historyEnabled === false`.
- **`LLMService`** — **single OpenAI-compatible streaming client**, used by both `Application` (main analysis) and `AdminManager` (support chat). Constructor accepts any object with `.settings` of the right shape, so `AdminManager` instantiates `new LLMService(this)` and reuses the whole pipeline. `callLLM()` streams SSE, parses `delta.content`, `delta.reasoning_content`, and `delta.reasoning`, returns `{ content, reasoning }`. Uses **a single timer that doubles as TTFB-and-idle timeout**: armed initially, cleared on the first `data:`-line, re-armed on every subsequent `data:`. If it fires before any chunk → "Таймаут первого чанка"; if it fires mid-stream → "Idle-таймаут стрима". Headers arriving without data does NOT clear it. Has **DoS guards** during streaming: `MAX_BUFFER_BYTES = 1MB` between newlines (server cannot send one unbroken giant line) and `MAX_TOTAL_RESPONSE_BYTES = 5MB` total content+reasoning (server cannot make the tab OOM); both abort with a clear error preserving the partial response. Differentiates user-abort vs timeout vs network error (`TypeError`) and parses server error bodies for context-overflow keywords (`context length`, `n_ctx`, `max_position`, etc.) to surface actionable messages. `testConnection()` pings API. `fetchLocalModels()` discovers models via GET `/v1/models` (also extracts `context_length` metadata). Helpers: `_createTimeoutSignal(ms)` (polyfill for `AbortSignal.timeout()`), `_combineSignals(...signals)` (combines user-abort + timeout via `AbortSignal.any` with fallback).
- **`MarkdownRenderer`** — static class. Markdown→HTML with XSS protection (escape first, restore code blocks after). Supports: headers, bold/italic, tables, ordered/unordered lists, code blocks (with copy button via event delegation), blockquotes, horizontal rules. **`escapeHtml()`** is the canonical escaper used throughout `Application` (renderHistory, renderPromptsTable, renderActionButtons, renderChatMessage, viewHistoryEntry) — accepts any input via `String(v ?? '')`.
- **`TokenEstimator`** — static class. Cyrillic ~2 chars/token, Latin/code ~4 chars/token. Drives real-time token meter.
- **`Toast`** — notification system. Built entirely via DOM (`createElement` + `createElementNS` for SVG), message via `textContent` only. Never uses `innerHTML` for user-supplied data. Toast container has `role="status" aria-live="polite"` for screenreaders.
- **`_hashAdminPassword` / `_verifyAdminPassword`** — async SHA-256 via `crypto.subtle.digest`. `ADMIN_DEFAULT_PASSWORD_HASH` is the precomputed hash of `'admin123' + ADMIN_PASSWORD_SALT`. Custom hash stored in `localStorage[ADMIN_PASSWORD_HASH_KEY]`. Fallback for missing `crypto.subtle`: accept default password only if no custom hash set (degraded, but never silently bypasses).
- **`AdminManager`** — admin page controller. Password-gated via the async hash check above (UI gate, **not** real auth — DevTools bypass is trivial; this is documented in the admin UI). Manages support chat settings (API config, system prompt, generation params). Persists to `codesentinel_admin_settings`. **Owns its own `LLMService` instance** (`this.llm = new LLMService(this)`) — its settings have the same shape as `AppState.settings`, so the whole streaming pipeline is shared. Provides password change/reset UI inside admin page.
- **`SupportChat`** — floating support widget (bottom-right sphere button). **Reuses `this.admin.llm.callLLM` directly** — same TTFB/idle timeouts, same DoS guards, same overflow parsing as main analysis. Adapts `onChunk` signature inline (main passes `{ contentDelta, reasoningDelta, fullContent, fullReasoning }`, support only needs `fullContent`). Default system prompt knows the app internals; escalates complex questions to Мартьянов Николай.
- **`Application`** — main controller. Pages: analysis, settings, history, help, admin. Manages streaming with reasoning support, prompt CRUD, model type indicators, keyboard shortcuts. Key utilities:
  - `_validateTextFile(file)` / `_isBinaryContent(content)` / `_formatFileSize(size)` — shared file validation (extension whitelist + binary heuristic + size limit)
  - `_hasModalUnsavedChanges()` — protects against accidental modal close with unsaved data
  - `_openModal(overlayId, opts?)` / `_closeModal(overlayId)` — **single source of truth for modal show/hide**. Manages `aria-hidden`, saves previous focus, focuses first focusable element (or `opts.initialFocusId`), installs Tab/Shift+Tab focus trap, restores focus on close. All three modals (`modal-overlay`, `history-modal-overlay`, `admin-auth-overlay`) go through it.
  - `_startWaitingTimer(div)` / `_clearWaitingTimer()` — elapsed time indicator while waiting for first LLM response chunk
  - `bindCodeCopyDelegation()` — event delegation for dynamically created code block copy buttons (no inline `onclick`)
  - `updateStreamingMessage(div, info)` / `_renderStreamingMessage(div, info)` — **rAF-throttled** rendering pair. Public method captures latest state; private renderer runs at ~60fps via `requestAnimationFrame`. This is what prevents the tab from freezing on long answers where MarkdownRenderer.render would otherwise be invoked on every chunk.
  - `_askOverflowAction(opts)` — when pre-flight detects token overflow, presents a three-way confirm: `cancel` / `force` / `chunk`. Returns one of those strings.
  - `_chunkCode(code, maxTokensPerChunk, language)` — splits code into chunks targeting `maxTokensPerChunk`, preferring **logical boundaries**: language-specific block starts (`def`/`class`/`function`/`Procedure`/`FORM`/`Процедура`) and blank lines. Hard fallback: line-by-line. Pure function, no DOM.
  - `_runAnalysisChunked({ code, prompt, systemPrompt, meta, chunkBudget })` — sequential chunked analysis. Each chunk gets its own system-prompt suffix (`## КОНТЕКСТ ЧАНКОВАНИЯ — Это часть N из M ...`) so the model knows context boundaries. Final summary-message points user at follow-up for aggregation.

### Data Flow

1. User selects Role → Language → Action → pastes code/text
2. `runAnalysis()` finds prompt, appends `contextContent` (instruction file) to system prompt with `--- Дополнительные инструкции ---` separator
3. `buildMessages()` constructs: `[system + language instruction] + [language] + [attached file] + [user code]`. Language instruction ("ВАЖНО: Пользователь указал язык — X") enforces correct language detection by the LLM.
4. **Pre-flight budget check**: `runAnalysis()` sums `TokenEstimator.estimate(m.content)` over messages, compares to `contextWindow − maxTokens`. If exceeded, `_askOverflowAction()` shows **three-way confirm**: `cancel` (abort), `force` (send anyway — at user's risk), or `chunk` (delegate to `_runAnalysisChunked()`). The dialog is Xinference-aware when `mode === 'local'`. Chunk option only appears when `expectedChunks >= 2`.
5. `createStreamingMessage()` shows waiting indicator with elapsed timer ("Отправка запроса..." → "Ожидание ответа модели... (Xs)")
6. `callLLM()` streams SSE; `onChunk({ contentDelta, reasoningDelta, fullContent, fullReasoning })` updates UI in real-time via `updateStreamingMessage` (rAF-throttled). First `data:` line clears the waiting indicator and arms idle timeout.
7. `_renderStreamingMessage()` (called from the rAF callback) renders content via MarkdownRenderer, shows reasoning section with toggle if model produces `reasoning_content`.
8. `finalizeStreamingMessage()` adds model badge: "С рассуждениями (~N токенов)", "Без рассуждений", or "Рассуждения не получены" (when model detected as reasoning but no reasoning_content received).
9. **History save in separate try**: `addHistoryEntry` is wrapped so `QuotaExceededError` rolls back the in-memory `history.unshift` and shows a warning Toast — but the streamed answer stays on screen. Throws `Error` with `isHistorySaveError = true`.
10. Conversation history maintained for follow-ups; token meter updates after each exchange.

### Reasoning/Thinking Model Support

- **SSE parsing**: `delta.reasoning_content` OR `delta.reasoning` accumulated into `fullReasoning`, `delta.content` into `fullContent`
- **Return format**: `callLLM()` returns `{ content: string, reasoning: string }`
- **UI**: collapsible reasoning section (`.msg-reasoning`) with brain icon, pulsing animation during thinking, token count after completion
- **Model detection**: `isLikelyReasoningModel()` checks name patterns; actual detection confirmed by `reasoning_content` presence in stream
- **Settings indicator**: `updateLocalModelTypeIndicator()` shows "Рассуждающая модель (CoT)" or "Стандартная модель" with auto-detected context window
- **Edge case**: If model is heuristically detected as reasoning but no `reasoning_content` received, badge shows "Рассуждения не получены" with tooltip

### Prompt System

Prompts are stored in `AppState.prompts` array. Each prompt has: `id`, `role`, `language` (optional), `actionName`, `systemPrompt`, `contextContent` (instruction file).

- **Language-specific prompts**: `infosec_python` (Python), `infosec_abap` (ABAP), `infosec_1c` (1С) — concise security analysis tailored to each language's vulnerability surface (SQL injection variants, AUTHORITY-CHECK for ABAP, Выполнить/COM-objects for 1С, eval/SSTI/unsafe-deserialization for Python).
- **Language filtering**: prompts with `language` field only appear when matching language is selected; prompts without `language` appear for all languages
- **Modal editing**: language selector in prompt modal (`#modal-language`); unsaved changes protection via `_hasModalUnsavedChanges()` on overlay click / Escape
- **Instruction files**: `contextContent` appended to system prompt, persisted with prompt in localStorage
- **Prompt style (after v9 expert revision)**: all 11 default prompts use **telegraphic, no-fluff style**. No "ты — эксперт с N лет опыта" preambles. Every check is described as a measurable signal (e.g., "функция >50 строк, цикломатическая >10") rather than an abstract principle. Each prompt ends with an explicit output-format block + ЗАПРЕТЫ (anti-fluff: no "оценка X/10", no "топ-3 приоритета", no "заключение", no fabricated findings → "не обнаружено" instead). ИБ-промпты share a single output template via the **`INFOSEC_OUTPUT_TEMPLATE` constant** declared above `DEFAULT_PROMPTS`; the 5 ИБ-prompts interpolate it with `${INFOSEC_OUTPUT_TEMPLATE}`. When editing/adding ИБ-prompts, keep the template reference unless you have a reason to diverge.

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
- **Context window**: client-side only (not sent to API); must match model's real context window for accurate meter. Auto-set to 8K for local, 64K for cloud on mode switch. Auto-detected from model metadata when available (via `/v1/models` `context_length`).
- **Pre-flight enforcement**: `runAnalysis()` re-estimates the full `messages` payload and triggers `_askOverflowAction()` if `estimated > contextWindow − maxTokens`. The footer meter is informational; this check is the actual guard. Three outcomes: cancel / force / chunk (see Data Flow step 4).
- **Chunked path**: when user chooses `chunk`, `chunkBudget = max(2000, budget − overheadTokens − 500)` and the code is split into `Math.ceil(codeTokens / chunkBudget)` parts via `_chunkCode`. Each part runs as a fresh `callLLM` with system-prompt suffix indicating "часть N из M". Parts are processed sequentially, results streamed into the chat as separate assistant messages.
- **Safety**: division by zero guard when `contextWindow` is 0.

### API Configuration

- **Cloud**: DeepSeek API (OpenAI-compatible). `deepseek-chat` (fast) and `deepseek-reasoner` (CoT).
- **Local**: LM Studio/Ollama/Xinference at configurable URL (default `http://172.16.33.12:9997` — Xinference). `/v1/chat/completions` for inference, `/v1/models` for discovery (with `context_length` extraction).
- **Shared settings**: `contextWindow` (4K–256K, **client-side meter only, NOT sent to API**), `maxTokens` (256–16384, default 4096), `temperature` (0–2, default 0.3), `requestTimeoutSec` (30–1800, default 300 — TTFB only). Only `temperature` and `maxTokens` go to the API; `contextWindow` drives the token meter, `requestTimeoutSec` drives the TTFB timer.
- **Server-side n_ctx vs UI contextWindow**: the UI value is purely cosmetic. Real n_ctx is set at model load (Xinference `--context-length`, LM Studio Load Settings → Context Length, Ollama `num_ctx`). Mismatch is the #1 cause of "model hangs on big files" — surfaced via context-overflow detection in `callLLM` error parsing.

### localStorage Keys

All keys are loaded through `Schema.safeParse` — corrupt/tampered values fall back to defaults. Never read these directly without validation.

| Key | Content |
|-----|---------|
| `codesentinel_settings` | API config, mode, model, temperature, maxTokens, contextWindow, requestTimeoutSec, **historyEnabled**, **historyTTLDays**, **apiKeySessionOnly**. When `apiKeySessionOnly === true`, `cloudApiKey` is stripped before write — key stays in RAM only, gone on reload. |
| `codesentinel_prompts` | User-customized prompts matrix (including contextContent, language) |
| `codesentinel_history` | Past analysis sessions (max 50). Each entry includes `apiMessages` (full conversation for restore) plus visible `messages` (last two for preview). TTL-pruned on load. |
| `codesentinel_sidebar_collapsed` | Sidebar visibility state |
| `codesentinel_admin_settings` | Admin page settings (support chat API config, system prompt) |
| `codesentinel_admin_pwd_hash` | SHA-256(password + salt) when user has changed admin password. Absent = default. |

### Keyboard Shortcuts

- **Ctrl+Enter** in code textarea — run analysis
- **Escape** — close modals (with unsaved changes check), stop generation
- **Tab** in code textarea — insert 4 spaces
- **Tab / Shift+Tab** inside any modal — cycles focus within the modal (focus trap installed by `_openModal`)
- **Enter / Space** on `.token-meter` and `.reasoning-header` — toggles their expanded state

### Privacy & History

- `settings.historyEnabled` (default `true`) — opt-out of saving analyses to `localStorage`. When `false`, `addHistoryEntry` is a no-op; existing entries remain visible until manually purged.
- `settings.historyTTLDays` (default 30, range 0–365, 0 = never) — entries older than this are removed during `loadFromStorage` via `_pruneExpiredHistory`.
- `settings.apiKeySessionOnly` (default `false`) — when on, `saveSettings()` strips `cloudApiKey` before serialization; the key lives only in memory and disappears on page reload. Useful on shared machines.
- Manual purge: "Удалить всю историю сейчас" button in the privacy block of settings.
- History stores full conversation (`apiMessages`) plus a preview pair (`messages`). Restoring from history rehydrates `conversationHistory`, enabling follow-up. Pre-fix entries lacking `apiMessages` open in read-only mode with explicit Toast warning.
- **History save failures are isolated**: if `saveHistory` hits `QuotaExceededError`, the in-memory `history.unshift` is rolled back and a warning Toast is shown. The streamed response and chat state remain untouched.

### Security Hardening (UI-side only)

This is a client-side SPA with no backend. Treat all defenses as defense-in-depth for UX integrity, NOT as security boundaries.

- **XSS escape**: every place that renders user-controlled data via `innerHTML` (history list, prompts table, action buttons, chat messages, history modal) routes through `MarkdownRenderer.escapeHtml`. `Toast` uses pure DOM with `textContent`. New code touching `innerHTML` MUST escape user data — grep for `const esc = MarkdownRenderer.escapeHtml` to see the pattern.
- **localStorage validation**: see `Schema` above. Any new persisted field needs a validator entry.
- **Admin password**: SHA-256(password + salt) — see `_verifyAdminPassword`. The hash in source can be brute-forced offline; the gate is for UI containment, not secrets. Admin UI explicitly tells users this. Changing the password stores a custom hash in `codesentinel_admin_pwd_hash`.

### Accessibility

- All three modals have `role="dialog"`, `aria-modal="true"`, `aria-labelledby` (pointing at the modal's title `id`), `aria-hidden` toggled by `_openModal`/`_closeModal`.
- Focus trap (Tab/Shift+Tab cycle) installed/uninstalled by the modal manager. Focus is saved before open, restored on close.
- `.hint-card` is a `<button>` (not `<div>`) — keyboard-accessible by default. Rendered both in `index.html:245-256` (welcome card) and `app.js` chat-welcome HTML.
- `.token-meter` and `.reasoning-header` have `role="button"`, `tabindex="0"`, `aria-expanded`, and Enter/Space keyboard handlers.
- Toast container: `role="status" aria-live="polite" aria-atomic="true"` for screen reader announcements.

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
- **Browser compatibility**: `AbortSignal.timeout()` and `AbortSignal.any()` wrapped in polyfills (`_createTimeoutSignal`, `_combineSignals`); no inline `onclick` handlers (event delegation instead).
- **Russian UI**: all labels, prompts, messages in Russian. Respond to user in Russian.
- **File attachments**: only `.txt`, `.md`, `.markdown`. Max 500KB. Binary rejected via heuristic check. Extension validated in JS before reading. Note: 500KB of code ≈ up to 125K tokens — usually too big for local models; the pre-flight check is what protects users, not the file size limit.
- **Copy buttons**: every AI response has copy-to-clipboard; code blocks inside responses have their own copy button (bound via event delegation).
- **No inline event handlers**: use `addEventListener` or event delegation (`bindCodeCopyDelegation()`).
- **No `innerHTML` with raw user data**: always escape via `MarkdownRenderer.escapeHtml`, or build via `createElement`+`textContent`. The XSS surface has been audited and closed — don't reopen it.
- **Modal open/close**: use `_openModal`/`_closeModal` (never `style.display = 'flex'` directly) so ARIA state, focus trap, and focus restoration stay consistent.
- **Persisted-state changes**: when adding a field to `localStorage`, add a matching entry in the relevant `Schema.safeParse` validator. Skipping this leaves an unvalidated path that can crash the app on tampered data.

### Chunking Large Files

When user has a file too big for the model's context (typical case: 3000+ lines locally), the recommended path is **chunking, not raw `force`**:

- Triggered automatically when pre-flight detects overflow AND `canChunk` (real per-chunk budget ≥1500 tokens AND `expectedChunks ≥ 2`). If `attachedFileContent` overhead already eats the context, chunking is **not offered** — only cancel/force.
- `_chunkCode` prefers logical boundaries — language-specific function/class/procedure starts and blank lines — over arbitrary line counts. Each chunk targets `chunkBudget` tokens but may overflow up to 20% if no boundary is nearby.
- Each chunk runs as an **independent `callLLM`** with a system-prompt suffix telling the model "Это часть N из M ... не предполагай содержимое остальных частей".
- Sequential, not parallel — each chunk waits for the previous to complete. Aborting any chunk stops the whole run.
- **User-message in UI for chunked path** = compact marker (`[Большой файл: N строк, ~K токенов] Разбит на M частей`). Full code is **never** added to `chatMessages` — that's what prevents the follow-up context bomb.
- Final summary-message (added directly to chat, not via LLM) tells the user: "для получения единой сводки — задайте уточняющий вопрос «Объедини находки в одну таблицу»".
- **History entry for a chunked run** stores `apiMessages = compactHistory` — the same compact `conversationHistory` used in the live session: `system` + one short user marker + N assistant chunk-results. After `restoreFromHistory`, follow-up works and the model has access to all findings; only the original full code is absent (by design, to avoid restoring a 100K-token context).

## Reference Files

- `example/code1.html`, `example/code2.html` — design reference mockups
- `help.txt` — API documentation reference
- `.env` — DeepSeek API key (gitignored, never commit)
- `logo.png` — brand logo (compass)
- `prompts/infosec_universal_vulnerability_analysis.md` — comprehensive security prompt template (570 lines, all languages). **Note**: superseded by the in-app short prompts in `DEFAULT_PROMPTS` after v9 revision; kept as a reference for the security team. Not loaded by the app.
- `примеры плохих файлов/` — sample vulnerable Python files from InfoSec team (test reference for security prompts)
- `AI-scanner.zip` — pre-built deploy archive for end-users (tracked in git for easy GitHub download). Contains only the 4 essentials + a short Russian README.txt inside an `AI-scanner/` subfolder. **Rebuild after any change to the 4 essentials.**

## Verification Loop for Reviewers

When a reviewer reports a finding, before fixing **verify the claim against current `HEAD`** — don't trust line numbers alone:
1. `git log --oneline -5` to see the latest commits the reviewer might or might not have seen.
2. `grep`/`Read` the actual line numbers cited. v10→v11 reviews had **2 false positives out of 4** because the reviewer was checking an older revision.
3. If the finding is real, create a TaskCreate, fix it, and reference the specific line/function in the commit message.
