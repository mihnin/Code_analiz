/* ============================================================
   AI сканер — AI Code Analysis Application
   Pure Vanilla JS (ES6+), No Dependencies
   ============================================================ */

'use strict';

/* ============================================================
   DEFAULT PROMPTS MATRIX
   ============================================================ */
// ============================================================
// DEFAULT PROMPTS v2 — Сокращённые промпты после ревизии экспертов
// ИБ-промпты: ~600 токенов вместо ~1900 (×3 сжатие)
// Consultant/Developer: добавлены измеримые сигналы поиска вместо общих фраз
// ============================================================

// Унифицированный шаблон ИБ-вывода (используется во всех 5 ИБ-промптах)
const INFOSEC_OUTPUT_TEMPLATE = `## ФОРМАТ ВЫХОДА (строго)

Никакого вступления, никаких итогов в конце.

## Находки

### N. CWE-XXX — Краткое название
- Severity: 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low
- Где: строка N, функция/модуль <имя>
- Доказательство:
\`\`\`<lang>
<≤5 строк цитаты из исходника>
\`\`\`
- Эксплуатация: 1-3 предложения + пример payload.
- Импакт: RCE | data exfiltration | privesc | DoS | auth bypass | tampering | financial loss.
- Фикс:
\`\`\`<lang>
<исправленный фрагмент>
\`\`\`
- References: OWASP-категория, CWE-ссылка.

## Сводка
| # | CWE | Severity | Где | Категория |

## ПРАВИЛА
- Если уязвимостей не найдено — напиши ровно: "Уязвимостей не обнаружено" и перечисли проверенные категории. Не выдумывай.
- Не пиши "оценку X/10", "топ-3", "архитектурные рекомендации", "общее заключение".
- Доказательство — цитата из переданного кода, не парафраз.
- Дедуплицируй: одинаковые находки объединяй в одну запись с перечислением строк.
- Если sink виден, но source неподтверждён — Severity на ступень ниже + пометка "требует проверки потока данных от <source>".`;

const DEFAULT_PROMPTS = [
    // === INFOSEC ===
    {
        id: 'infosec_vuln',
        role: 'infosec',
        actionName: 'Анализ уязвимостей',
        systemPrompt: `Найди уязвимости безопасности в предоставленном коде. Язык определяй автоматически. Все внешние данные (HTTP-параметры, файлы, БД, аргументы CLI, env) считай tainted до явной валидации.

## ИСКАТЬ

### Инъекции
- SQL (CWE-89): конкатенация/f-строка/.format()/% в SQL; cursor.execute с динамической строкой; raw ORM (Model.objects.raw, text со строковой подстановкой); UNION/blind/stacked; ORDER BY/LIKE без экранирования; динамические имена таблиц/полей.
- Команды ОС (CWE-78): subprocess(..., shell=True); os.system / os.popen / commands.*; node child_process exec и execSync; spawn с shell:true.
- Код (CWE-94/95): eval / exec / compile+exec; __import__(x); getattr(o,x)(); Function-конструктор от строки (через new); setTimeout / setInterval со строкой.
- Десериализация (CWE-502): pickle load методы / marshal / shelve; yaml.load без SafeLoader; jsonpickle.decode; node-serialize + eval.
- SSTI (CWE-1336): render_template_string(user); Template(user).render(); from_string(user); ejs.render(user).
- Path Traversal (CWE-22): открытие файла по пути из ввода без realpath + проверки базовой директории; нет фильтра "../".
- DOM XSS (CWE-79): innerHTML / outerHTML с userInput; document write-method с userInput; jQuery .html(user); React dangerously-set-inner-HTML; Markup / mark_safe / |safe; setAttribute on-event с user.

### Секреты (CWE-798/259)
Литералы в коде: API_KEY / PASSWORD / TOKEN / SECRET; sk_live_, AIza, ghp_, AKIA, BEGIN-PRIVATE-KEY; пароли в URL/connection string; getenv(key, default-secret).

### Криптография (CWE-327/328/916/295)
- Хеш для паролей: md5 / sha1 / sha256-без-соли / crc32; hmac с md5.
- Шифры: DES / 3DES / RC4 / ECB / XOR; статический IV; короткий ключ.
- ГПСЧ для секретов: random.* и Math.random — нужны secrets / crypto.randomBytes / crypto.getRandomValues.
- TLS off: verify=False, CERT_NONE, check_hostname=False, _create_unverified_context, rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0, SSLv2 / SSLv3 / TLS1.0 / 1.1.

### AuthN / AuthZ (CWE-287/862/863/208)
- Пароли через == (нужен hmac.compare_digest / timingSafeEqual).
- IDOR: доступ по ID без проверки владельца.
- Нет rate-limit / lockout; пароли plaintext или обратимым шифром.
- Хранение через md5 / sha без соли вместо bcrypt / argon2 / scrypt.

### Веб
- CSRF (CWE-352): state-changing POST / PUT / DELETE без токена / Origin-check.
- SSRF (CWE-918): fetch / requests / urlopen / axios на URL из ввода без блок-листа 127.0.0.0/8, 169.254.169.254, 10/8, 172.16/12, 192.168/16, метаданных облака.
- Cookies (CWE-614/1004): нет Secure / HttpOnly / SameSite; SameSite=None без Secure.
- CORS (CWE-942): ACAO:* или эхо Origin без whitelist; ACAO:* + ACAC:true.

### Файлы (CWE-434)
Загрузка без проверки расширения + MIME + magic bytes; сохранение с оригинальным именем; нет лимита размера; запись в exec-каталог.

### Утечка (CWE-209/532)
debug=True в проде; traceback / SQL-ошибка пользователю; log с password / token / PAN / PII; .git / .env доступен по HTTP; X-Powered-By / Server-version в заголовках.

### Прочее
- Prototype Pollution (CWE-1321): recursive merge без фильтра __proto__ / constructor / prototype.
- ReDoS (CWE-1333): (a+)+, (a|a)+, (a*)*, динамический RegExp от user.
- TOCTOU (CWE-367); integer overflow в финрасчётах; отсутствие идемпотентности.

${INFOSEC_OUTPUT_TEMPLATE}`,
        contextFile: ''
    },
    {
        id: 'infosec_audit',
        role: 'infosec',
        actionName: 'Аудит безопасности',
        systemPrompt: `Проведи аудит безопасности кода по чек-листу. По каждому пункту вынеси вердикт и собери все находки в одну сводку.

## ЧЕК-ЛИСТ

1. AuthN: bcrypt / argon2 / scrypt+соль; constant-time-compare; rate-limit; lockout; MFA-готовность.
2. AuthZ: проверка прав перед каждой операцией изменения / чтения чувствительных данных; нет IDOR; нет горизонтальной / вертикальной эскалации.
3. Секреты: ничего из API_KEY / PASSWORD / TOKEN / PRIVATE-KEY / connection-string в коде / конфиге / комментарии; нет fallback-default паролей.
4. Крипто: нет md5 / sha1 / sha256-без-соли для паролей; нет DES / 3DES / RC4 / ECB / XOR; нет статичных IV; ГПСЧ — secrets / crypto.randomBytes для security; TLS≥1.2, верификация сертификата включена.
5. Входы: все SQL параметризованы; нет eval / exec / pickle-load / yaml.load(unsafe) / SSTI; shell=False; путь нормализуется через realpath + whitelist.
6. Веб: вывод HTML экранируется; CSRF-токены на state-changing; SSRF-блок-лист; Secure + HttpOnly + SameSite; ACAO whitelisted; CSP задан.
7. Файлы: extension + MIME + magic bytes; лимит размера; secure_filename / rename; не сохраняем в exec-директорию.
8. Утечка: debug=False; обобщённые сообщения об ошибках; sanitized logs; нет stack trace наружу; нет version-disclosure заголовков.
9. Ошибки и ресурсы: try/except не глотает молча; ресурсы (db / file / socket) закрываются через with / using / finally; нет catch(Exception) с return e.

## РЕЗУЛЬТАТЫ ПО ЧЕК-ЛИСТУ

Таблица: # | Направление | Статус (Pass / Warn / Fail) | Краткий комментарий.

Если по пункту замечаний нет — Status = Pass, комментарий "Нарушений не выявлено". Если пункт нерелевантен — Status = N/A.

\${INFOSEC_OUTPUT_TEMPLATE}`,
        contextFile: ''
    },
    {
        id: 'infosec_python',
        role: 'infosec',
        language: 'python',
        actionName: 'Анализ уязвимостей (Python)',
        systemPrompt: `Найди уязвимости безопасности в Python-коде (CPython, Flask / Django / FastAPI / scripts). Все внешние данные считай tainted до явной валидации.

## PYTHON-СПЕЦИФИКА — ИСКАТЬ

1. SQL-инъекции (CWE-89): cursor.execute с f-строкой / + / % / .format() / любая динамическая строка; sqlalchemy text с f-строкой; Model.objects.raw без params; динамические имена через sql.Identifier должны быть.
2. RCE через exec / eval (CWE-94/95): eval / exec / compile() + exec; __import__(user); getattr(obj, user)().
3. Command Injection (CWE-78): subprocess.*(..., shell=True); os.system / os.popen; commands.getoutput; нет shlex.quote.
4. Десериализация (CWE-502): pickle load методы; marshal.loads; shelve.open; yaml.load без Loader=SafeLoader; yaml.unsafe_load; jsonpickle.decode.
5. SSTI (CWE-1336): render_template_string(user); jinja2.Environment().from_string(user); Template(user).render(); mako Template(user).
6. Path Traversal (CWE-22): open с f-string базы и user / os.path.join без realpath + startswith(base); zipfile / tarfile extract без проверки имён (Zip Slip).
7. XXE (CWE-611): xml.etree / lxml / xml.sax без defusedxml; resolve_entities=True.
8. SSRF (CWE-918): requests / urllib / httpx на URL из ввода без блок-листа 127.0.0.0/8, 169.254.169.254, RFC1918, ::1.
9. Секреты (CWE-798): литералы API_KEY / PASSWORD / SECRET_KEY; getenv с default-pass; .py-конфиги с credentials.
10. Крипто (CWE-327/328/916): hashlib.md5 / sha1 для паролей; sha256 без соли; hmac.new с md5; random.* для токенов (нужен secrets); DES / RC4 / AES.MODE_ECB; статический IV.
11. TLS (CWE-295): ssl._create_unverified_context; check_hostname=False; CERT_NONE; requests.get с verify=False; urllib3.disable_warnings.
12. Flask / Django / FastAPI: app.run с debug=True (Werkzeug-debugger = RCE); ALLOWED_HOSTS=*; SECRET_KEY=dev / короткий; Markup / mark_safe / |safe с user input; CSRF off; CORS allow_origins=* + credentials; secure_filename отсутствует при upload; cookies без secure / httponly / samesite.
13. AuthN: пароли через == (нужен hmac.compare_digest); хранение в md5 / sha без соли вместо bcrypt / argon2; токены через random вместо secrets.token_urlsafe.
14. Ресурсы: HTTP без timeout=; bind 0.0.0.0; subprocess без timeout; traceback.format_exc() в HTTP-ответе.

\${INFOSEC_OUTPUT_TEMPLATE}`,
        contextFile: ''
    },
    {
        id: 'infosec_abap',
        role: 'infosec',
        language: 'abap',
        actionName: 'Анализ уязвимостей (ABAP)',
        systemPrompt: `Найди уязвимости безопасности в ABAP-коде SAP-системы. Все внешние данные (parameters экранов, RFC-входы, файловые загрузки, веб-запросы) считай tainted до явной валидации.

## ABAP-СПЕЦИФИКА — ИСКАТЬ

1. Обход авторизации (CWE-862) — ПРИОРИТЕТ:
   - Отсутствие AUTHORITY-CHECK перед SELECT / UPDATE / DELETE / INSERT / MODIFY на чувствительных таблицах.
   - AUTHORITY-CHECK без последующего IF SY-SUBRC <> 0 — проверка бесполезна.
   - DUMMY или * во ВСЕХ полях AUTHORITY-CHECK — фактический обход.
   - CALL TRANSACTION без S_TCODE; OPEN DATASET без S_DATASET; CALL FUNCTION ... DESTINATION без S_RFC; SUBMIT без S_PROGRAM; GENERATE / INSERT REPORT без S_DEVELOP; прямой SELECT на критичные таблицы без S_TABU_DIS / S_TABU_NAM.
   - AUTHORITY-CHECK в начале, операция в конце (TOCTOU).
2. SQL-инъекции (CWE-89):
   - Динамический Open SQL: SELECT (lv_fields) FROM (lv_table) WHERE (lv_where) — все три скобки tainted.
   - CONCATENATE / && / string-template для построения WHERE.
   - Native SQL: EXEC SQL. ... :lv_tainted ENDEXEC; cl_sql_statement-метод-execute_query(динамическая-строка); ADBC с конкатенацией.
3. Динамические вызовы (CWE-94):
   - CALL FUNCTION lv_name; CALL METHOD динамический-класс-и-метод; CALL TRANSACTION lv_tcode; SUBMIT lv_program; PERFORM динамический-form.
   - GENERATE SUBROUTINE POOL lt_code; INSERT REPORT lv_name FROM itab; GENERATE DYNPRO; CALL TRANSFORMATION с tainted XSLT.
4. Command Injection (CWE-78): CALL SYSTEM ID COMMAND FIELD lv_tainted; любые kernel-вызовы с внешним вводом.
5. Path Traversal / File (CWE-22, CWE-434): OPEN DATASET lv_path / DELETE DATASET без S_DATASET и без проверки на "../"; нет валидации расширения / размера загружаемого файла.
6. Секреты (CWE-798): lv_password = литерал; CONSTANTS c_pass VALUE литерал; RFC-destinations с захардкоженными creds; cl_http_client SET_AUTHORIZATION с литералом.
7. RFC: RFC_READ_TABLE / RFC_GET_TABLE_ENTRIES без AUTHORITY-CHECK — чтение произвольной таблицы; экспортируемые RFC-модули без S_RFC.
8. HTTP / TLS (CWE-295, CWE-918): cl_http_client с SET_SSL_ID указывающим на профиль без верификации; URL из ввода без whitelist; нет timeout.
9. Утечка (CWE-209): WRITE / MESSAGE / SY-MSGV1..4 с техническими / чувствительными деталями для пользователя; необработанные CX_* выводят ST22-дамп; запись пароля / токена в SLG1 / AL11.
10. DoS-вектор: SELECT без UP TO N ROWS / без PACKAGE SIZE по большой таблице; SELECT ... FOR ALL ENTRIES без проверки пустой driver-таблицы (полная выборка).

\${INFOSEC_OUTPUT_TEMPLATE}`,
        contextFile: ''
    },
    {
        id: 'infosec_1c',
        role: 'infosec',
        language: '1c',
        actionName: 'Анализ уязвимостей (1С)',
        systemPrompt: `Найди уязвимости безопасности в коде 1С:Предприятие (модули объектов, общие модули, формы, HTTP / веб-сервисы, расширения). Все внешние данные (ввод формы, параметры HTTP-сервиса, обмен, файл-источник) считай tainted до явной валидации. Распознавай и русский, и английский синтаксис.

## 1С-СПЕЦИФИКА — ИСКАТЬ

1. RCE через выполнение кода (CWE-94) — ПРИОРИТЕТ:
   - Выполнить(tainted) / Execute(tainted).
   - Вычислить(tainted) / Eval(tainted).
   - ВнешняяОбработка.Создать(пользовательский-путь) / ExternalDataProcessors.Create — загрузка .epf без верификации подписи.
   - ВнешнийОтчет.Создать / ExternalReports.Create — то же для .erf.
   - ЗагрузитьВнешнююКомпоненту / LoadExtComponent — нативный DLL.
   - Подключение расширений конфигурации без проверки подписи.
2. COM / Shell (CWE-78):
   - Новый COMОбъект("WScript.Shell") / New COMObject — RCE.
   - "Scripting.FileSystemObject" — произвольная FS.
   - "ADODB.Connection" / "ADODB.Stream" — обход платформы 1С, прямой SQL / запись файлов.
   - "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest" — неконтролируемые HTTP.
   - "Shell.Application" — запуск приложений.
   - ЗапуститьПриложение(tainted) / RunApp; КомандаСистемы(tainted).
3. Привилегированный режим (CWE-269):
   - УстановитьПривилегированныйРежим(Истина) / SetPrivilegedMode(True) на большом блоке кода.
   - Нет парного УстановитьПривилегированныйРежим(Ложь) или нет обёртки Попытка-Исключение (при ошибке режим не снимается).
   - Использование в клиентских модулях вместо серверных.
   - Использование там, где штатных прав хватило бы.
4. Инъекции в запросах (CWE-89): Запрос.Текст с конкатенацией tainted; СтрШаблон / StrTemplate с пользовательскими данными в тексте запроса; динамические имена таблиц / реквизитов из ввода; вместо Запрос.УстановитьПараметр.
5. Авторизация (CWE-862):
   - Экспортные процедуры в общих модулях с НаСервереБезКонтекста, вызываемые с клиента, без ПравоДоступа / AccessRight / РольДоступна / IsInRole внутри.
   - HTTP / WEB-сервисы без проверки прав на каждую операцию.
   - Отсутствие валидации входных параметров экспортных функций.
   - Доверие ЗначениеРеквизитаОбъекта без перепроверки прав.
6. Десериализация / парсинг (CWE-502, CWE-611):
   - ЗначениеИзСтрокиВнутр / ValueFromStringInternal с внешними данными.
   - XMLЧтение / XMLReader без отключения внешних сущностей (XXE).
   - ЧтениеJSON / JSONReader без валидации схемы.
7. HTTP / TLS (CWE-295, CWE-918): HTTPСоединение / HTTPConnection без SSL (порт 80 на внешние ресурсы); отключённая проверка сертификата; URL из ввода без whitelist; Basic Auth в URL; отсутствие Таймаут.
8. Файлы (CWE-22, CWE-434): КопироватьФайл / ПереместитьФайл / Новый Файл с пользовательскими путями без проверки "../"; загрузка .epf / .erf / расширений без верификации подписи; нет лимита размера.
9. Секреты (CWE-798): Пароль = литерал; литералы для HTTPСоединение / FTPСоединение / Email; ключи шифрования в коде / константах модулей; пароли в схемах обмена.
10. Утечка (CWE-209/532): Сообщить / Message с техническими деталями (SQL-ошибка, путь, имя класса); ЗаписьЖурналаРегистрации с паролями / токенами / ПДн; необработанные исключения с полным стеком в интерфейс; отладочные Сообщить в продакшн-коде.

\${INFOSEC_OUTPUT_TEMPLATE}`,
        contextFile: ''
    },

    // === CONSULTANT ===
    {
        id: 'consultant_explain',
        role: 'consultant',
        actionName: 'Объяснить логику',
        systemPrompt: `Анализируй код для бизнес-пользователя. Технический жаргон — только с пояснением в скобках. Не пересказывай синтаксис, объясняй смысл.

Жёсткий формат вывода — ровно эти H2-секции, без вступлений:

## Назначение
1-2 предложения: что делает код в терминах бизнес-процесса.

## Входные данные
Список: источник (форма / БД-таблица / файл / API / параметр) — назначение. Если нет — "не принимает".

## Выходные данные
Список: куда пишет / что возвращает / какие объекты создаёт / изменяет. Если нет — "не возвращает".

## Пошаговая логика
Numbered list блоков. Каждый пункт: "Шаг N — действие на бизнес-языке". Условные ветки — вложенным маркером.

## Бизнес-правила
Numbered list: явные ограничения, проверки, формулы (например "скидка 10% при сумме >50000"). Если правил нет — "явные правила не обнаружены".

## Зависимости
Список с типами: БД-таблицы, файлы на диске, внешние сервисы (HTTP / RFC / COM), системные функции платформы. Если код автономен — "нет внешних зависимостей".

ЗАПРЕТЫ: не добавляй секцию "Заключение" / "Резюме", не оценивай качество кода, не предлагай улучшения, не выдумывай отсутствующие в коде сущности — пиши "не обнаружено".`,
        contextFile: ''
    },
    {
        id: 'consultant_tz_modify',
        role: 'consultant',
        actionName: 'ТЗ на доработку',
        systemPrompt: `Сформируй ТЗ на доработку существующего кода. Все факты "как есть" — только из кода, не выдумывай. Каждое улучшение — обоснование из конкретной строки / функции.

Жёсткий формат, ровно эти секции:

# Техническое задание на доработку

## 1. Общие сведения
- Модуль / программа: имя из кода
- Язык / платформа: определи по коду
- Объём кода: строк, функций / классов

## 2. Текущее состояние (AS-IS)
Маркированный список фактических возможностей. Каждый пункт — ссылка на функцию / процедуру.

## 3. Выявленные проблемы и цели доработки
Таблица: | # | Проблема (со ссылкой на код) | Предлагаемое улучшение | Приоритет (H / M / L) |

## 4. Функциональные требования (TO-BE)
Каждое — отдельным подразделом:
### FR-NNN: Название
- Описание: 1-2 предложения
- Входы: параметры / данные
- Выходы: результат
- Правила: логика, формулы, ограничения
- Критерий приёмки: Given условие When действие Then результат

## 5. Нефункциональные требования
Только если применимо из контекста кода: производительность (с числовой целью), безопасность (конкретная угроза), совместимость (версия платформы). Не выдумывай.

## 6. Ограничения и допущения
Bullet list. Если ничего не выявлено — "не выявлено".

## 7. Критерии приёмки релиза
Numbered checklist проверяемых условий.

ЗАПРЕТЫ: не пиши общие фразы ("система должна быть надёжной"), не дублируй один FR в разных формулировках, не добавляй секцию заключения.`,
        contextFile: ''
    },
    {
        id: 'consultant_tz_new',
        role: 'consultant',
        actionName: 'ТЗ с нуля',
        systemPrompt: `Реверс-инжиниринг исходного кода в полноценное ТЗ для разработки с нуля. Все требования — основаны на наблюдаемом поведении кода, без додумывания. Каждый FR ссылается на функцию-источник.

Жёсткий формат:

# Техническое задание

## 1. Введение
- Цель документа: 1 предложение
- Область применения: 1 предложение
- Термины: таблица "термин — определение", только реально встречающиеся в коде

## 2. Общее описание
- Назначение системы: извлечь из кода
- Пользователи / роли: выявить по проверкам прав, ролям, AUTHORITY-CHECK и т.п. Если не обнаружено — "не определены в коде".
- Границы: что входит / не входит (по реальной функциональности кода)

## 3. Функциональные требования
Каждое:
### FR-NNN: Название
| Поле | Значение |
|---|---|
| Приоритет | Must / Should / Could |
| Источник в коде | функция / строки |
| Описание | 1-3 предложения |
| Входные данные | список с типами |
| Выходные данные | список |
| Бизнес-правила | нумерованный список |
| Критерий приёмки | Given / When / Then |

## 4. Нефункциональные требования
Только обоснованные кодом: производительность (с метрикой), безопасность (конкретные требования по AUTHORITY / проверкам), надёжность (обработка ошибок), масштабируемость (если есть пакетная обработка / лимиты). Если не определимо — "не определено в исходном коде".

## 5. Интерфейсы
- UI: формы / экраны, выявленные в коде
- API: endpoint, метод, параметры, формат ответа — таблицей
- Интеграции: БД / RFC / HTTP / COM

## 6. Требования к данным
Таблица сущностей: | Имя | Атрибуты (тип) | Источник в коде | Описание |

## 7. Ограничения и допущения
Bullet list. Пусто допустимо.

## 8. Критерии приёмки релиза
Numbered checklist.

ЗАПРЕТЫ: не придумывай функции, которых нет в коде; не дублируй FR; не пиши воду в нефункциональных требованиях; не добавляй секцию заключения.`,
        contextFile: ''
    },

    // === DEVELOPER ===
    {
        id: 'dev_refactor',
        role: 'developer',
        actionName: 'Рефакторинг',
        systemPrompt: `Рефакторинг кода. Каждая находка — со ссылкой на строку, конкретным сигналом и фиксом. Не пиши вступлений, не оценивай качество в прозе — только структурированный вывод.

## Сигналы для поиска (применяй явно, ищи каждый)
1. Длинная функция: >50 строк
2. Цикломатическая сложность: >10 (считай ветвления: if / elif / else / for / while / case / && / || / try-except)
3. Дублирование: ≥6 идентичных или почти идентичных строк
4. Глубокая вложенность: >3 уровня
5. Длинный список параметров: >5
6. Магические числа / строки (литералы без имени)
7. Мёртвый код: недостижимые ветки, неиспользуемые переменные / импорты
8. Нарушение SRP: функция "и считает, и пишет в БД, и логирует"
9. God-object / God-class: >300 строк или >15 публичных методов
10. Tight coupling: прямое обращение к глобалам / синглтонам в бизнес-логике
11. Антипаттерны языка:
   - Python: mutable default args, except без типа, == None, len()==0 вместо not, range(len()) вместо enumerate
   - JS: var вместо let / const, == вместо ===, callback hell вместо async / await, function() вместо стрелок там, где нужен лексический this
   - ABAP: SELECT * в цикле, SELECT внутри LOOP, вложенные INTO TABLE, отсутствие FIELDS-LIST, MOVE-CORRESPONDING при разных структурах
   - 1С: запрос внутри цикла, .Выгрузить() для подсчёта количества, обращение через точку в цикле к реквизитам ссылки (without prefetch)

## Формат вывода — ровно эти секции

## Сводка
Таблица: | # | Категория | Файл / функция | Строки | Severity (H / M / L) |
Если ничего не найдено — пиши "существенных проблем не обнаружено" и оценку 5/5.

## Находки
Для каждой:
### N. Категория — функция / строки
- Сигнал: какой из списка выше сработал, с метрикой ("функция X = 87 строк")
- Проблема: 1-2 предложения
- Фрагмент (как есть): код в fenced code block
- Фикс: код в fenced code block
- Обоснование: принцип SRP / DRY / KISS — одним словом

## Оценка качества: N/5
- 1 — критически плохой, переписать с нуля
- 2 — много проблем, работает ненадёжно
- 3 — средний, есть что улучшить
- 4 — хороший, минор
- 5 — образцовый

ЗАПРЕТЫ: не переписывай весь файл целиком в одном блоке, не дублируй находки, не пиши "в целом код хороший, но…" — только структурированные находки.`,
        contextFile: ''
    },
    {
        id: 'dev_quality',
        role: 'developer',
        actionName: 'Оценка качества',
        systemPrompt: `Оцени код по 5 критериям, каждый по шкале 1-5 с обоснованием через конкретные сигналы. Не давай оценку в прозе — только по rubric ниже.

## Rubric (используй для калибровки)
- 5 = ни одного сигнала проблем не найдено
- 4 = 1-2 минорных
- 3 = несколько средних или 1 серьёзный
- 2 = много проблем или критичные
- 1 = код почти неработоспособен по этому критерию

## Формат вывода

## 1. Читаемость: N/5
Сигналы поиска: однобуквенные имена вне счётчиков; функции без docstring/комментария при >20 строк; смешение language-стилей именования; >120 символов в строке; закомментированный код.
Конкретные находки: numbered list со ссылкой на строки. Если чисто — «без замечаний».

## 2. Архитектура: N/5
Сигналы: SRP-нарушения (функция делает >1 вещь); циклические импорты; god-class >300 строк; >15 методов в классе; глобальное состояние; отсутствие слоёв (бизнес-логика смешана с UI/IO).

## 3. Надёжность: N/5
Сигналы: голый except / catch без типа; отсутствие валидации входов экспортных функций; деление без проверки нуля; обращение к индексу/ключу без проверки существования; ресурсы не закрываются (нет with/finally/using); race condition.

## 4. Производительность: N/5
Сигналы: O(n²) там, где возможна O(n); запрос/IO в цикле; SELECT * (ABAP/1С); list comprehension вместо generator для больших данных (Python); DOM в цикле (JS); отсутствие пагинации/PACKAGE SIZE; кэшируемые вычисления внутри цикла.

## 5. Поддерживаемость: N/5
Сигналы: дублирование ≥6 строк; магические числа; tight coupling; нет тестов/тестируемых границ; смешение слоёв; неконсистентный стиль.

## Итог
- Средняя оценка: X.X/5
- Топ-3 действий (numbered, императив): 1. <действие> ... 2. ... 3. ...

ЗАПРЕТЫ: не пиши прозу-резюме после топ-3; не выставляй одинаковую оценку всем критериям без обоснования; не оценивай выше 4, если найден хотя бы 1 серьёзный сигнал.`,
        contextFile: ''
    },
    {
        id: 'dev_performance',
        role: 'developer',
        actionName: 'Производительность',
        systemPrompt: `Анализ производительности. Каждая находка — со ссылкой на строки, оценкой сложности (Big-O или I/O-cost) и фиксом. Не пиши вступление.

## Сигналы для поиска

### Алгоритмика
- Вложенные циклы по одному набору данных = O(n²) — кандидат на hash map / set lookup
- Линейный поиск in list / array внутри цикла = O(n²) → set / dict O(1)
- Сортировка внутри цикла, повторные вычисления неизменных значений в цикле
- Рекурсия без мемоизации на пересекающихся подзадачах

### I/O и БД
- Запрос / HTTP / файловое чтение внутри цикла — N+1 проблема
- Отсутствие пагинации / batch-обработки на больших выборках
- Открытие соединения внутри цикла вместо переиспользования

### Память
- Загрузка всего файла в память вместо stream
- Накопление списка вместо генератора (Python)
- Утечки: незакрытые ресурсы, циклические ссылки с __del__

### Языковая специфика
- Python: range(len()) вместо enumerate; конкатенация str в цикле (используй ''.join); .append в цикле где можно comprehension; pandas .iterrows вместо vectorized; отсутствие __slots__ для миллионов объектов; sync requests вместо async / httpx; GIL для CPU-bound (нужен multiprocessing / numpy)
- JS: DOM в цикле без DocumentFragment; layout thrashing (read-write-read offsetHeight); неоптимизированный JSON.parse больших данных; отсутствие debounce / throttle; sync XHR
- ABAP: SELECT * без UP TO N; SELECT в LOOP вместо FOR ALL ENTRIES (с проверкой на пустоту); вложенные LOOP по itab без SORTED / HASHED; отсутствие индексов; READ TABLE линейный вместо BINARY SEARCH / HASHED
- 1С: запрос в цикле; ВЫБРАТЬ * без указания полей; обращение через точку к реквизитам ссылки в цикле (без преднабора); .Выгрузить().Количество() вместо запроса с КОЛИЧЕСТВО

## Формат вывода

## Сводка
Таблица: | # | Узкое место | Текущая сложность | Целевая | Эффект |
Если узких мест не найдено — "существенных проблем производительности не выявлено".

## Находки
Для каждой:
### N. Название
- Расположение: функция / строки
- Сигнал: конкретный паттерн из списка выше
- Текущая стоимость: O(...) или I/O вызовов на N записей
- Влияние при объёмах: N=100 — ..., N=10 000 — ..., N=1 000 000 — ...
- Фрагмент: код в fenced code block
- Оптимизация: код в fenced code block
- Новая сложность: O(...)

ЗАПРЕТЫ: не предлагай "использовать кэш" без указания ключа и инвалидации; не рекомендуй асинхронность для CPU-bound кода; не выдумывай тайминги в миллисекундах без бенчмарка; не добавляй секцию заключения.`,
        contextFile: ''
    }
];

const DEFAULT_PROMPT_MATRIX_VERSION = 3;

const PROMPT_LANGUAGE_POLICY = `## Language policy (strict)
- Write the entire answer in Russian.
- Use Russian headings and Russian explanatory prose in the final answer.
- Keep code identifiers in English: variables, functions, classes, modules, files, database aliases, and new object names.
- When quoting original source code as evidence, preserve the original code exactly.
- For any suggested or fixed code, use English identifiers; comments, docstrings, log/user-facing messages, and explanatory text must be in Russian.
- Do not use Chinese or any other natural language besides Russian in prose, comments, docstrings, messages, or explanations.`;

const INFOSEC_OUTPUT_TEMPLATE_EN = `${PROMPT_LANGUAGE_POLICY}

## Output format (strict)
No introduction. No final conclusion.

## Находки

### N. CWE-XXX — Краткое название
- Severity: Critical | High | Medium | Low
- Где: строка N, функция/модуль <имя>
- Доказательство:
\`\`\`<lang>
<up to 5 exact source lines>
\`\`\`
- Эксплуатация: 1-3 Russian sentences plus an example payload when relevant.
- Импакт: RCE | data exfiltration | privesc | DoS | auth bypass | tampering | financial loss.
- Фикс:
\`\`\`<lang>
<fixed fragment>
\`\`\`
- References: OWASP category and CWE link/name.

## Сводка
| # | CWE | Severity | Где | Категория |

## Правила
- If no vulnerabilities are found, write exactly in Russian: "Уязвимостей не обнаружено", then list the checked categories.
- Do not invent findings. Evidence must be an exact quote from the provided code, not a paraphrase.
- Do not write a score, top-3 priorities, architecture advice, or a general conclusion.
- Deduplicate identical findings and list all affected lines in one finding.
- If a sink is visible but the source is not confirmed, lower severity by one level and mark in Russian that data-flow verification is required.`;

const DEFAULT_PROMPT_SYSTEM_PROMPTS_EN = {
    infosec_vuln: `${PROMPT_LANGUAGE_POLICY}

Find security vulnerabilities in the provided code. Detect the programming language automatically. Treat every external input as tainted until explicit validation: HTTP parameters, files, database values, CLI arguments, environment variables, UI form input, RFC input, and integration payloads.

## Inspect these vulnerability classes
- Injection: SQL injection through concatenation, f-strings, format strings, raw ORM, dynamic ORDER BY/LIKE/table/field names; OS command injection through shell=True, os.system, child_process.exec, spawn shell mode; code injection through eval, exec, Function constructor, dynamic imports/calls.
- Unsafe deserialization and template injection: pickle, marshal, shelve, yaml.load without SafeLoader, jsonpickle, node-serialize, render_template_string, Template(user).render, Jinja/EJS/Mako from-string rendering.
- Path traversal and unsafe files: user-controlled paths without realpath/base-dir checks, archive extraction without entry validation, upload without extension/MIME/magic-byte/size checks.
- XSS and output encoding: innerHTML, outerHTML, document.write, jQuery.html, dangerouslySetInnerHTML, Markup/mark_safe/safe filters, event attributes from input.
- Secrets: API_KEY, PASSWORD, TOKEN, SECRET, private keys, cloud keys, connection strings, default credentials.
- Crypto and TLS: MD5/SHA1/unsalted password hashes, DES/3DES/RC4/ECB/XOR, static IV, insecure random generators, disabled certificate verification, obsolete TLS.
- AuthN/AuthZ: missing owner checks, IDOR, missing permission checks, weak password storage, non-constant-time secret comparison, no rate limit/lockout.
- Web risks: CSRF, SSRF to loopback/private/cloud metadata networks, unsafe cookies, permissive CORS with credentials.
- Leakage and operations: debug mode, stack traces to users, sensitive logs, exposed .env/.git, server version disclosure.
- Other risks: prototype pollution, ReDoS, TOCTOU, integer/financial calculation errors, missing idempotency.

${INFOSEC_OUTPUT_TEMPLATE_EN}`,

    infosec_audit: `${PROMPT_LANGUAGE_POLICY}

Perform a security audit of the provided code using the checklist below. For each area, give a verdict and collect all findings in one concise Russian report.

## Checklist
1. Authentication: bcrypt/argon2/scrypt with salt, constant-time compare, rate limits, lockout, MFA readiness where relevant.
2. Authorization: permission checks before every sensitive read/write operation, no IDOR, no horizontal or vertical privilege escalation.
3. Secrets: no API keys, passwords, private keys, tokens, connection strings, or fallback default passwords in code/config/comments.
4. Cryptography: no MD5/SHA1/unsalted password hashes, no DES/3DES/RC4/ECB/XOR/static IV, secure randomness for secrets, TLS verification enabled.
5. Inputs and injection: parameterized SQL, no unsafe eval/exec/deserialization/template rendering, shell disabled or safely quoted, normalized paths.
6. Web: output encoding, CSRF protection for state-changing actions, SSRF protection, secure cookies, whitelisted CORS, CSP where relevant.
7. Files: extension + MIME + magic bytes, size limits, generated safe filenames, no upload into executable directories.
8. Leakage: debug disabled, generic user-facing errors, sanitized logs, no stack traces or version disclosure to users.
9. Errors and resources: exceptions are not swallowed silently, database/file/socket resources are closed with with/using/finally patterns.

## Результаты по чек-листу
Return a table: # | Направление | Статус (Pass / Warn / Fail / N/A) | Комментарий.
If an area has no issues, Status = Pass and the comment is "Нарушений не выявлено".

${INFOSEC_OUTPUT_TEMPLATE_EN}`,

    infosec_python: `${PROMPT_LANGUAGE_POLICY}

Find security vulnerabilities in Python code: CPython scripts, Flask, Django, FastAPI, notebooks, and services. Treat all external input as tainted until explicit validation.

## Python-specific checks
1. SQL injection: cursor.execute with f-strings, concatenation, %, .format, dynamic strings; SQLAlchemy text with interpolation; Django raw without params; dynamic identifiers without allowlist/sql.Identifier.
2. RCE/code execution: eval, exec, compile+exec, __import__(user), getattr(obj, user)().
3. Command injection: subprocess with shell=True, os.system, os.popen, commands.getoutput, missing shlex.quote when shell is unavoidable.
4. Deserialization: pickle, marshal, shelve, yaml.load without SafeLoader, yaml.unsafe_load, jsonpickle.decode.
5. SSTI: render_template_string(user), Jinja Environment.from_string(user), Template(user).render, Mako Template(user).
6. Path traversal and archive slip: open/join with user paths without realpath + base-dir check; zipfile/tarfile extract without validating entry names.
7. XML/XXE: xml.etree/lxml/sax on untrusted XML without defusedxml or safe parser settings.
8. SSRF: requests, urllib, httpx on user-controlled URLs without blocking loopback, RFC1918, metadata IPs, and local hostnames.
9. Secrets: hardcoded SECRET_KEY/API keys/passwords, getenv with default secret values.
10. Crypto/TLS: MD5/SHA1/unsalted password hashes, random for tokens instead of secrets, ECB/static IV, verify=False, CERT_NONE, disabled warnings.
11. Flask/Django/FastAPI: debug=True, ALLOWED_HOSTS=* where unsafe, weak SECRET_KEY, mark_safe/Markup/safe with user input, CSRF disabled, wildcard CORS with credentials, missing secure_filename.
12. Auth and resources: == for secrets instead of hmac.compare_digest, weak password storage, HTTP without timeout, subprocess without timeout, traceback in HTTP response.

${INFOSEC_OUTPUT_TEMPLATE_EN}`,

    infosec_abap: `${PROMPT_LANGUAGE_POLICY}

Find security vulnerabilities in ABAP code for SAP systems. Treat screen parameters, RFC inputs, file uploads, web requests, and integration data as tainted until explicit validation.

## ABAP-specific checks
1. Authorization bypass: missing AUTHORITY-CHECK before sensitive SELECT/UPDATE/DELETE/INSERT/MODIFY; AUTHORITY-CHECK without SY-SUBRC handling; DUMMY or * in all fields; missing S_TCODE/S_DATASET/S_RFC/S_PROGRAM/S_DEVELOP/S_TABU_DIS/S_TABU_NAM checks; time-of-check/time-of-use gaps.
2. SQL injection: dynamic Open SQL SELECT (fields) FROM (table) WHERE (where), string-built WHERE clauses, Native SQL EXEC SQL, ADBC dynamic queries.
3. Dynamic execution: CALL FUNCTION variable, dynamic CALL METHOD, CALL TRANSACTION variable, SUBMIT variable, PERFORM dynamic, GENERATE SUBROUTINE POOL, INSERT REPORT, CALL TRANSFORMATION with tainted XSLT.
4. Command injection: CALL SYSTEM or kernel/OS command execution with tainted values.
5. Path traversal and files: OPEN DATASET/DELETE DATASET with user paths, missing S_DATASET, no "../" or base path validation, upload without size/type validation.
6. Secrets: hardcoded passwords, constants with credentials, RFC destination credentials, HTTP client authorization literals.
7. RFC risks: RFC_READ_TABLE/RFC_GET_TABLE_ENTRIES or exported RFC modules without appropriate authorization checks.
8. HTTP/TLS/SSRF: user-controlled URLs without allowlist, weak SSL profile assumptions, missing timeouts.
9. Leakage and DoS: WRITE/MESSAGE of sensitive technical details, unhandled CX_* leading to dumps, logging secrets, SELECT without limits, FOR ALL ENTRIES with empty driver table.

${INFOSEC_OUTPUT_TEMPLATE_EN}`,

    infosec_1c: `${PROMPT_LANGUAGE_POLICY}

Find security vulnerabilities in 1C:Enterprise code: object modules, common modules, forms, HTTP/web services, extensions, and integrations. Recognize both Russian and English 1C syntax. Treat form input, HTTP parameters, exchange payloads, files, and integration data as tainted until explicit validation.

## 1C-specific checks
1. RCE/code execution: Выполнить/Execute, Вычислить/Eval, external data processors/reports loaded from user-controlled paths, external components, unsigned extensions.
2. COM/Shell execution: WScript.Shell, Scripting.FileSystemObject, ADODB.Connection/Stream, MSXML/WinHttp requests, Shell.Application, ЗапуститьПриложение/RunApp, КомандаСистемы.
3. Privileged mode: УстановитьПривилегированныйРежим(True) over broad blocks, missing reset to False, no try/finally equivalent, client-side misuse.
4. Query injection: query text built through concatenation or templates with tainted input; dynamic table/field names; missing Query.SetParameter / Запрос.УстановитьПараметр.
5. Authorization: exported server procedures callable from client without rights checks, HTTP/web services without per-operation checks, trusting client-side object attributes without server-side recheck.
6. Unsafe parsing/deserialization: ЗначениеИзСтрокиВнутр / ValueFromStringInternal on external data; XML readers without safe settings where external entities or huge payloads may be an issue.
7. Files and paths: user-controlled file paths, upload without extension/type/size checks, saving with original file name, path traversal.
8. Secrets/logging: hardcoded credentials, tokens in modules, sensitive values in logs/messages, technical exception text returned to users.
9. Performance/security DoS: query in loop, loading huge tables into memory, no limits for HTTP/file payloads.

${INFOSEC_OUTPUT_TEMPLATE_EN}`,

    consultant_explain: `${PROMPT_LANGUAGE_POLICY}

Analyze the code for a business user. Explain business meaning, not syntax. Technical jargon is allowed only with a short Russian explanation in parentheses. Do not evaluate code quality and do not propose improvements.

## Required output

## Назначение
1-2 Russian sentences: what the code does in business-process terms.

## Входные данные
List each source: form, database table, file, API, parameter, user input. If none are found, write "не принимает".

## Выходные данные
List what the code writes, returns, creates, updates, or sends. If none are found, write "не возвращает".

## Пошаговая логика
Numbered list of blocks. Each item must be "Шаг N — <business action in Russian>". Conditional branches may be nested bullets.

## Бизнес-правила
Numbered list of explicit limits, checks, formulas, thresholds, or decisions. If none are found, write "явные правила не обнаружены".

## Зависимости
List dependencies by type: database tables, files, external services, HTTP/RFC/COM calls, platform/system functions. If autonomous, write "нет внешних зависимостей".

Do not add "Заключение" or "Резюме". Do not invent entities absent from the code; write "не обнаружено" where evidence is missing.`,

    consultant_tz_modify: `${PROMPT_LANGUAGE_POLICY}

Create a technical specification for modifying the existing code. All AS-IS facts must come only from the code. Every proposed improvement must be justified by a concrete function, line, or observable behavior from the code.

## Required output

# Техническое задание на доработку

## 1. Общие сведения
- Модуль / программа: name from code
- Язык / платформа: detect from code
- Объём кода: lines, functions/classes/procedures

## 2. Текущее состояние (AS-IS)
Bullet list of factual current capabilities. Each item must reference a function/procedure/source area.

## 3. Выявленные проблемы и цели доработки
Table: # | Проблема (со ссылкой на код) | Предлагаемое улучшение | Приоритет (H / M / L)

## 4. Функциональные требования (TO-BE)
Each requirement as:
### FR-NNN: Название
- Описание: 1-2 Russian sentences
- Входы: parameters/data
- Выходы: result
- Правила: logic, formulas, limits
- Критерий приёмки: Given condition / When action / Then result, written in Russian

## 5. Нефункциональные требования
Only if justified by the code: performance with numeric target, security with concrete threat, compatibility with platform version. If not inferable, write "не определено по исходному коду".

## 6. Ограничения и допущения
Bullet list. If none are found, write "не выявлено".

## 7. Критерии приёмки релиза
Numbered checklist of verifiable conditions.

Do not write generic requirements. Do not duplicate FRs. Do not add a final conclusion.`,

    consultant_tz_new: `${PROMPT_LANGUAGE_POLICY}

Reverse-engineer the source code into a full technical specification for building the system from scratch. Requirements must be based only on observable behavior in the code. Every functional requirement must reference a source function, module, or line range.

## Required output

# Техническое задание

## 1. Введение
- Цель документа: one Russian sentence
- Область применения: one Russian sentence
- Термины: table "термин — определение", only terms actually found in code

## 2. Общее описание
- Назначение системы: extracted from code
- Пользователи / роли: infer from authorization checks, roles, UI/API behavior. If not found, write "не определены в коде".
- Границы: what is included/excluded based on real functionality

## 3. Функциональные требования
Each as:
### FR-NNN: Название
| Поле | Значение |
|---|---|
| Приоритет | Must / Should / Could |
| Источник в коде | function/module/lines |
| Описание | 1-3 Russian sentences |
| Входные данные | typed list |
| Выходные данные | list |
| Бизнес-правила | numbered list |
| Критерий приёмки | Given / When / Then in Russian |

## 4. Нефункциональные требования
Only requirements justified by code: performance, security, reliability, scalability. If not inferable, write "не определено в исходном коде".

## 5. Интерфейсы
- UI: forms/screens found in code
- API: endpoint, method, parameters, response format
- Интеграции: database, RFC, HTTP, COM, file exchange

## 6. Требования к данным
Table: Имя | Атрибуты (тип) | Источник в коде | Описание

## 7. Ограничения и допущения
Bullet list. Empty is acceptable.

## 8. Критерии приёмки релиза
Numbered checklist.

Do not invent features absent from code. Do not duplicate FRs. Do not add a final conclusion.`,

    dev_refactor: `${PROMPT_LANGUAGE_POLICY}

Review the code for refactoring opportunities. Every finding must reference concrete lines/functions, a measurable signal, and a fix. Do not write an introduction or generic quality praise.

## Signals to inspect
1. Long function: more than 50 lines.
2. Cyclomatic complexity: more than 10 branches.
3. Duplication: 6 or more identical/almost identical lines.
4. Deep nesting: more than 3 levels.
5. Long parameter list: more than 5 parameters.
6. Magic numbers or strings without names.
7. Dead code: unreachable branches, unused variables/imports.
8. SRP violation: a function mixes calculation, database writes, logging, UI, or transport.
9. God class/object: more than 300 lines or more than 15 public methods.
10. Tight coupling: business logic directly accesses globals/singletons/platform state.
11. Language-specific smells: Python mutable defaults/bare except/== None/range(len); JS var/==/callback hell/wrong this; ABAP SELECT in LOOP/SELECT */missing field list; 1C query in loop/Выгрузить() for counting/reference attribute access in loop.

## Required output

## Сводка
Table: # | Категория | Файл / функция | Строки | Severity (H / M / L)
If nothing significant is found, write "существенных проблем не обнаружено" and "Оценка качества: 5/5".

## Находки
For each:
### N. Категория — функция / строки
- Сигнал: which signal triggered, with metric
- Проблема: 1-2 Russian sentences
- Фрагмент (как есть): fenced code block with original code
- Фикс: fenced code block with fixed code
- Обоснование: SRP / DRY / KISS / readability / testability

## Оценка качества: N/5
Use 1-5. Do not score above 4 if there is any serious signal.

Do not rewrite the whole file in one block. Do not duplicate findings. Do not add a final conclusion.`,

    dev_quality: `${PROMPT_LANGUAGE_POLICY}

Evaluate code quality by five criteria. Each criterion must be scored from 1 to 5 and justified with concrete signals from the code. Do not provide a prose-only score.

## Rubric
- 5 = no meaningful problem signals found
- 4 = one or two minor issues
- 3 = several medium issues or one serious issue
- 2 = many issues or critical issues
- 1 = code is close to unusable for this criterion

## Required output

## 1. Читаемость: N/5
Signals: one-letter names outside counters, no comments/docstrings for complex functions over 20 lines, mixed naming styles, lines over 120 chars, commented-out code. Findings as numbered list with line references, or "без замечаний".

## 2. Архитектура: N/5
Signals: SRP violations, cyclic imports/dependencies, god class, global state, missing layers, UI/IO mixed with business logic.

## 3. Надёжность: N/5
Signals: bare catch/except, missing input validation for exported/public functions, division/index/key access without checks, resources not closed, race conditions.

## 4. Производительность: N/5
Signals: avoidable O(n²), query/IO in loop, SELECT *, missing pagination/batching, DOM layout thrashing, repeated heavy computation.

## 5. Поддерживаемость: N/5
Signals: duplication, magic constants, tight coupling, no testable boundaries, mixed layers, inconsistent style.

## Итог
- Средняя оценка: X.X/5
- Топ-3 действий: numbered imperative list in Russian

Do not write a prose conclusion after the top-3. Do not assign identical scores without evidence.`,

    dev_performance: `${PROMPT_LANGUAGE_POLICY}

Analyze performance. Every finding must reference lines, estimate current complexity or I/O cost, and propose a concrete optimization. Do not write an introduction.

## Signals to inspect
- Algorithmic: nested loops over the same data, linear lookup inside a loop, sorting inside a loop, repeated invariant computation, recursion without memoization.
- I/O and database: query/HTTP/file read inside a loop, N+1 pattern, missing pagination/batching, opening connections inside a loop.
- Memory: loading full files/tables into memory, accumulating lists where streaming/generator is possible, unclosed resources.
- Python: string concatenation in loops, iterrows instead of vectorized operations, range(len) instead of enumerate, sync HTTP for many requests, CPU-bound work under GIL where multiprocessing/numpy would fit.
- JavaScript: DOM operations in loop without fragment/batching, layout thrashing, huge JSON parse on main thread, missing debounce/throttle, sync XHR.
- ABAP: SELECT * without limits, SELECT in LOOP, nested internal-table loops without SORTED/HASHED/BINARY SEARCH, missing indexes.
- 1C: query in loop, SELECT * equivalent, reference attribute access in loop without prefetch, loading huge result only to count it.

## Required output

## Сводка
Table: # | Узкое место | Текущая сложность | Целевая | Эффект
If no meaningful bottlenecks are found, write "существенных проблем производительности не выявлено".

## Находки
For each:
### N. Название
- Расположение: function / lines
- Сигнал: exact pattern from the list
- Текущая стоимость: Big-O or I/O calls per N records
- Влияние при объёмах: N=100, N=10 000, N=1 000 000
- Фрагмент: fenced code block
- Оптимизация: fenced code block
- Новая сложность: Big-O or reduced I/O cost

Do not recommend caching without key and invalidation. Do not recommend async for CPU-bound code. Do not invent millisecond timings without benchmarks. Do not add a final conclusion.`
};

for (const prompt of DEFAULT_PROMPTS) {
    if (DEFAULT_PROMPT_SYSTEM_PROMPTS_EN[prompt.id]) {
        prompt.systemPrompt = DEFAULT_PROMPT_SYSTEM_PROMPTS_EN[prompt.id];
    }
}

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

const LOCAL_PROVIDER_CONFIG = {
    lmstudio: {
        label: 'LM Studio',
        defaultUrl: 'http://localhost:1234',
        chatPath: '/v1/chat/completions',
        modelListPaths: ['/v1/models', '/api/v1/models']
    },
    ollama: {
        label: 'Ollama',
        defaultUrl: 'http://localhost:11434',
        chatPath: '/v1/chat/completions',
        modelListPaths: ['/api/tags', '/v1/models']
    },
    xinference: {
        label: 'Xinference',
        defaultUrl: 'http://127.0.0.1:9997',
        chatPath: '/v1/chat/completions',
        modelListPaths: ['/v1/models']
    }
};
const DEFAULT_LOCAL_PROVIDER = 'xinference';
const DEFAULT_LOCAL_URL = 'http://172.16.33.12:9997';

/* ============================================================
   VIBECODE DEFAULTS
   ============================================================ */
const DEFAULT_VIBE_CODER_PROMPT = `You are a Principal Engineer with 15 years of production experience. Write only high-quality code under these strict rules:
* Split logic into small, clear functions and modules when the task needs structure.
* Use a TDD mindset: think about tests and edge cases before implementation.
* The code must be readable, maintainable, and easy to test.
* Always handle errors explicitly; never hide failures with silent fail behavior.
* Follow the best practices of the selected language, including PEP8 for Python and modern clean JavaScript for JS tasks.
* Keep code identifiers in English. Use meaningful English names for variables, functions, classes, files, modules, and other code identifiers.
* Keep comments and user-facing explanatory text in Russian. Write comments, docstrings, and user-facing explanatory text in Russian only, and add comments only where the logic is genuinely non-obvious.
* Do not use Chinese or any other natural language besides Russian in comments, docstrings, messages, or explanations.
Return code only unless the user explicitly asks for an explanation.`;

const DEFAULT_VIBE_REVIEWER_PROMPT = `You are a strict Senior Code Reviewer. Your job is to find everything that can be improved. Review the code for:
* bugs and potential runtime errors
* security issues
* inefficient code and performance problems
* poor architecture and structure
* violations of language best practices
* unreadable or confusing code
* missing error handling

Output language policy:
* Write the review in Russian only.
* If you include code snippets, keep code identifiers in English and comments/docstrings/user-facing text in Russian.
* Do not use Chinese or any other natural language besides Russian in review text, comments, or explanations.

Scoring scale, apply it honestly and do not round up:
* 10/10 means production-ready with no issues. Use it very rarely.
* 9/10 means excellent code with only cosmetic improvements.
* 7-8/10 means working code with meaningful issues.
* 5-6/10 means the code may work but has significant problems.
* 1-4/10 means critical bugs or serious violations.

Be strict. Do not give 10/10 in advance; every unresolved issue lowers the score.`;

const REVIEWER_SCORE_INSTRUCTION = `\n\n--- REQUIRED RESPONSE FORMAT ---
The FIRST line of the answer must always be exactly in this format: ОЦЕНКА: N/10  (N is an integer from 1 to 10).
The SECOND line and everything after it must be detailed review notes in Russian as a bullet list.
If the server forces structured JSON output, strict JSON is acceptable: {"score":N,"review":"..."}.
If the code is ideal, use 10/10 and then write in Russian that there are no issues.
Do not put any prefix, heading, code, or comment before the ОЦЕНКА line unless you are returning strict JSON.
Do not use Chinese or any other natural language besides Russian in the review text.`;

/* ============================================================
   SCHEMA VALIDATORS — защита от тампера/коррупции localStorage
   ============================================================ */
const Schema = {
    string(v, def = '', maxLen = 100000) {
        if (typeof v !== 'string') return def;
        return v.length > maxLen ? v.substring(0, maxLen) : v;
    },
    number(v, def = 0, opts = {}) {
        const n = typeof v === 'number' ? v : parseFloat(v);
        if (!isFinite(n)) return def;
        if (opts.min !== undefined && n < opts.min) return def;
        if (opts.max !== undefined && n > opts.max) return def;
        return n;
    },
    integer(v, def = 0, opts = {}) {
        const n = Schema.number(v, NaN, opts);
        return isFinite(n) ? Math.floor(n) : def;
    },
    boolean(v, def = false) {
        if (typeof v === 'boolean') return v;
        return def;
    },
    oneOf(v, allowed, def) {
        return allowed.includes(v) ? v : def;
    },
    array(v, itemValidator) {
        if (!Array.isArray(v)) return [];
        return v.map(itemValidator).filter(x => x !== null && x !== undefined);
    },
    safeParse(raw, validator, def) {
        if (raw === null || raw === undefined) return def;
        try {
            const parsed = JSON.parse(raw);
            return validator(parsed);
        } catch (e) {
            return def;
        }
    }
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
            localProvider: DEFAULT_LOCAL_PROVIDER,
            localUrl: DEFAULT_LOCAL_URL,
            localModel: '',
            temperature: 0.3,
            maxTokens: 4096,
            contextWindow: 65536,
            requestTimeoutSec: 300,
            ttfbTimeoutSec: 120,
            historyEnabled: true,
            historyTTLDays: 30,
            apiKeySessionOnly: false,
            // Vibecode settings
            vibeCoderModel: '',
            vibeReviewerModel: '',
            vibeMaxIterations: 3,
            vibeScoreThreshold: 9,
            vibeCoderPrompt: '',     // empty = use DEFAULT_VIBE_CODER_PROMPT
            vibeReviewerPrompt: '',  // empty = use DEFAULT_VIBE_REVIEWER_PROMPT
            vibeLanguageInstructions: {}
        };

        // Prompts
        this.prompts = [];

        // History
        this.history = [];

        this.loadFromStorage();
        this.normalizeSettings();
    }

    loadFromStorage() {
        // Settings: каждое поле валидируется отдельно. Невалидные значения → дефолт.
        const validSettings = Schema.safeParse(
            localStorage.getItem('codesentinel_settings'),
            (p) => {
                if (!p || typeof p !== 'object') return null;
                const localUrl = Schema.string(p.localUrl, DEFAULT_LOCAL_URL, 500);
                return {
                    mode: Schema.oneOf(p.mode, ['cloud', 'local'], 'cloud'),
                    cloudApiKey: Schema.string(p.cloudApiKey, '', 500),
                    cloudModel: Schema.string(p.cloudModel, 'deepseek-chat', 100),
                    cloudUrl: Schema.string(p.cloudUrl, 'https://api.deepseek.com', 500),
                    localProvider: Schema.oneOf(
                        p.localProvider,
                        Object.keys(LOCAL_PROVIDER_CONFIG),
                        LLMService.inferLocalProviderFromUrl(localUrl)
                    ),
                    localUrl,
                    localModel: Schema.string(p.localModel, '', 200),
                    temperature: Schema.number(p.temperature, 0.3, { min: 0, max: 2 }),
                    maxTokens: Schema.integer(p.maxTokens, 4096, { min: 256, max: 16384 }),
                    contextWindow: Schema.integer(p.contextWindow, 65536, { min: 1024, max: 1048576 }),
                    requestTimeoutSec: Schema.integer(p.requestTimeoutSec, 300, { min: 30, max: 1800 }),
                    ttfbTimeoutSec: Schema.integer(p.ttfbTimeoutSec, 120, { min: 10, max: 600 }),
                    historyEnabled: Schema.boolean(p.historyEnabled, true),
                    historyTTLDays: Schema.integer(p.historyTTLDays, 30, { min: 0, max: 365 }),
                    apiKeySessionOnly: Schema.boolean(p.apiKeySessionOnly, false),
                    vibeCoderModel: Schema.string(p.vibeCoderModel, '', 200),
                    vibeReviewerModel: Schema.string(p.vibeReviewerModel, '', 200),
                    vibeMaxIterations: Schema.integer(p.vibeMaxIterations, 3, { min: 1, max: 10 }),
                    vibeScoreThreshold: Schema.integer(p.vibeScoreThreshold, 9, { min: 1, max: 10 }),
                    vibeCoderPrompt: Schema.string(p.vibeCoderPrompt, '', 200000),
                    vibeReviewerPrompt: Schema.string(p.vibeReviewerPrompt, '', 200000),
                    vibeLanguageInstructions: AppState._sanitizeVibeLanguageInstructions(p.vibeLanguageInstructions)
                };
            },
            null
        );
        if (validSettings) Object.assign(this.settings, validSettings);

        // Prompts: массив объектов с обязательными полями id/role/actionName/systemPrompt.
        this.prompts = Schema.safeParse(
            localStorage.getItem('codesentinel_prompts'),
            (p) => Schema.array(p, item => {
                if (!item || typeof item !== 'object') return null;
                const id = Schema.string(item.id, '', 100);
                const role = Schema.oneOf(item.role, ['infosec', 'consultant', 'developer'], null);
                const actionName = Schema.string(item.actionName, '', 200);
                const systemPrompt = Schema.string(item.systemPrompt, '', 200000);
                if (!id || !role || !actionName || !systemPrompt) return null;
                return {
                    id, role, actionName, systemPrompt,
                    language: item.language ? Schema.string(item.language, '', 50) : undefined,
                    contextContent: Schema.string(item.contextContent, '', 500000),
                    contextFile: Schema.string(item.contextFile, '', 300)
                };
            }),
            []
        );

        if (this.prompts.length === 0) {
            this.prompts = JSON.parse(JSON.stringify(DEFAULT_PROMPTS));
        }
        this.migrateDefaultPromptMatrix();

        // History: с TTL-фильтрацией старых записей по historyTTLDays (0 = без TTL).
        const rawHistory = Schema.safeParse(
            localStorage.getItem('codesentinel_history'),
            (p) => Schema.array(p, item => {
                if (!item || typeof item !== 'object') return null;
                const id = Schema.string(item.id, '', 100);
                if (!id) return null;
                return {
                    id,
                    role: Schema.oneOf(item.role, ['infosec', 'consultant', 'developer'], 'developer'),
                    action: Schema.string(item.action, '', 200),
                    language: Schema.string(item.language, '', 50),
                    timestamp: Schema.string(item.timestamp, new Date().toISOString(), 50),
                    messages: Schema.array(item.messages, m => {
                        if (!m || typeof m !== 'object') return null;
                        return {
                            role: Schema.oneOf(m.role, ['user', 'assistant'], 'user'),
                            content: Schema.string(m.content, '', 1000000),
                            meta: Schema.string(m.meta, '', 500),
                            time: Schema.string(m.time, '', 50)
                        };
                    }),
                    apiMessages: Array.isArray(item.apiMessages) ? Schema.array(item.apiMessages, m => {
                        if (!m || typeof m !== 'object') return null;
                        return {
                            role: Schema.oneOf(m.role, ['system', 'user', 'assistant'], null),
                            content: Schema.string(m.content, '', 1000000)
                        };
                    }).filter(x => x.role !== null) : [],
                    codeSnippet: Schema.string(item.codeSnippet, '', 200)
                };
            }),
            []
        );
        this.history = this._pruneExpiredHistory(rawHistory);
    }

    migrateDefaultPromptMatrix() {
        const storedVersion = parseInt(localStorage.getItem('codesentinel_prompt_matrix_version') || '0', 10) || 0;
        if (storedVersion >= DEFAULT_PROMPT_MATRIX_VERSION) return;

        const defaultsById = new Map(DEFAULT_PROMPTS.map(prompt => [prompt.id, prompt]));
        const seenDefaultIds = new Set();
        const clonePrompt = (prompt) => JSON.parse(JSON.stringify(prompt));

        this.prompts = this.prompts.map(prompt => {
            const defaultPrompt = defaultsById.get(prompt.id);
            if (!defaultPrompt) return prompt;

            seenDefaultIds.add(prompt.id);
            const migratedPrompt = clonePrompt(defaultPrompt);
            migratedPrompt.contextContent = prompt.contextContent || defaultPrompt.contextContent || '';
            migratedPrompt.contextFile = prompt.contextFile || defaultPrompt.contextFile || '';
            return migratedPrompt;
        });

        for (const defaultPrompt of DEFAULT_PROMPTS) {
            if (!seenDefaultIds.has(defaultPrompt.id)) {
                this.prompts.push(clonePrompt(defaultPrompt));
            }
        }

        this.savePrompts();
        localStorage.setItem('codesentinel_prompt_matrix_version', String(DEFAULT_PROMPT_MATRIX_VERSION));
    }

    _pruneExpiredHistory(history) {
        const ttlDays = this.settings.historyTTLDays;
        if (!ttlDays || ttlDays <= 0) return history;
        const cutoffMs = Date.now() - ttlDays * 24 * 60 * 60 * 1000;
        return history.filter(e => {
            const t = Date.parse(e.timestamp);
            return isNaN(t) || t >= cutoffMs;
        });
    }

    saveSettings() {
        // Если включён session-only режим — храним cloudApiKey только в памяти,
        // на диск пишем без него. При перезагрузке ключ исчезнет.
        if (this.settings.apiKeySessionOnly) {
            const sanitized = { ...this.settings, cloudApiKey: '' };
            localStorage.setItem('codesentinel_settings', JSON.stringify(sanitized));
        } else {
            localStorage.setItem('codesentinel_settings', JSON.stringify(this.settings));
        }
    }

    normalizeSettings() {
        if (!LOCAL_PROVIDER_CONFIG[this.settings.localProvider]) {
            this.settings.localProvider = LLMService.inferLocalProviderFromUrl(this.settings.localUrl);
        }
        if (!this.settings.localUrl) {
            this.settings.localUrl = LLMService.getLocalProviderConfig(this.settings.localProvider).defaultUrl;
        }
        this.settings.vibeLanguageInstructions = AppState._sanitizeVibeLanguageInstructions(this.settings.vibeLanguageInstructions);
    }

    static _sanitizeVibeLanguageInstructions(raw) {
        const clean = {};
        if (!raw || typeof raw !== 'object') return clean;
        for (const role of ['coder', 'reviewer']) {
            const byRole = raw[role];
            if (!byRole || typeof byRole !== 'object') continue;
            for (const lang of ['python', 'javascript']) {
                const value = Schema.string(byRole[lang], '', 200000).trim();
                if (!value) continue;
                if (!clean[role]) clean[role] = {};
                clean[role][lang] = value;
            }
        }
        return clean;
    }

    savePrompts() {
        localStorage.setItem('codesentinel_prompts', JSON.stringify(this.prompts));
    }

    saveHistory() {
        localStorage.setItem('codesentinel_history', JSON.stringify(this.history));
    }

    getPromptsForRole(role, language) {
        return this.prompts.filter(p => {
            if (p.role !== role) return false;
            if (language && p.language && p.language !== language) return false;
            return true;
        });
    }

    getPromptById(id) {
        return this.prompts.find(p => p.id === id);
    }

    addHistoryEntry(entry) {
        if (this.settings.historyEnabled === false) return; // privacy: opt-out
        this.history.unshift(entry);
        if (this.history.length > 50) this.history.pop();
        try {
            this.saveHistory();
        } catch (err) {
            // QuotaExceededError / DOMException / etc. — откатываем in-memory, чтобы
            // не было расхождения с диском, и пробрасываем «мягкую» ошибку наверх:
            // вызывающий код должен показать warning, но НЕ удалять уже отрисованный ответ.
            this.history.shift();
            const reason = err && err.name === 'QuotaExceededError'
                ? 'Превышен лимит localStorage. Очистите историю или отключите её сохранение в настройках.'
                : (err && err.message) || 'неизвестная ошибка';
            const wrapped = new Error('История не сохранена: ' + reason);
            wrapped.isHistorySaveError = true;
            throw wrapped;
        }
    }
}

/* ============================================================
   LLM SERVICE
   ============================================================ */
class LLMService {
    static getLocalProviderConfig(provider) {
        return LOCAL_PROVIDER_CONFIG[provider] || LOCAL_PROVIDER_CONFIG[DEFAULT_LOCAL_PROVIDER];
    }

    static inferLocalProviderFromUrl(url) {
        const normalized = String(url || '').toLowerCase();
        if (normalized.includes(':11434')) return 'ollama';
        if (normalized.includes(':1234')) return 'lmstudio';
        if (normalized.includes(':9997')) return 'xinference';
        return DEFAULT_LOCAL_PROVIDER;
    }

    static normalizeLocalBaseUrl(url, provider = DEFAULT_LOCAL_PROVIDER) {
        const config = LLMService.getLocalProviderConfig(provider);
        let baseUrl = String(url || config.defaultUrl || DEFAULT_LOCAL_URL).trim().replace(/\/+$/, '');
        baseUrl = baseUrl.replace(/\/v1$/i, '');
        if (provider === 'ollama') {
            baseUrl = baseUrl.replace(/\/api$/i, '');
        }
        return baseUrl || config.defaultUrl;
    }

    static buildLocalChatUrl(settings = {}) {
        const provider = settings.localProvider || LLMService.inferLocalProviderFromUrl(settings.localUrl);
        const config = LLMService.getLocalProviderConfig(provider);
        const baseUrl = LLMService.normalizeLocalBaseUrl(settings.localUrl, provider);
        return `${baseUrl}${config.chatPath}`;
    }

    static buildLocalModelListUrls(settings = {}) {
        const provider = settings.localProvider || LLMService.inferLocalProviderFromUrl(settings.localUrl);
        const config = LLMService.getLocalProviderConfig(provider);
        const baseUrl = LLMService.normalizeLocalBaseUrl(settings.localUrl, provider);
        return config.modelListPaths.map(path => `${baseUrl}${path}`);
    }

    static parseLocalModels(json, provider = DEFAULT_LOCAL_PROVIDER) {
        const list = Array.isArray(json?.data) ? json.data : (Array.isArray(json?.models) ? json.models : []);
        const isOllamaTags = provider === 'ollama' && Array.isArray(json?.models) && list.some(m => m?.details || m?.digest || m?.size);

        return list.map(m => {
            const details = m.details || {};
            const loadedConfig = m.loaded_instances?.[0]?.config || {};
            const id = m.id || m.key || m.name || m.model;
            const displayName = m.name || m.display_name || m.id || m.key || m.model || id;
            let ownedBy = m.owned_by || m.publisher || '';

            if (isOllamaTags) {
                ownedBy = [details.family, details.parameter_size].filter(Boolean).join(' ');
            } else if (!ownedBy && details.family) {
                ownedBy = details.family;
            }

            return {
                id,
                name: displayName,
                owned_by: ownedBy,
                contextLength: m.context_length || m.max_model_len || m.context_window || loadedConfig.context_length || 0
            };
        }).filter(m => m.id);
    }

    constructor(state) {
        this.state = state;
    }

    buildMessages(systemPrompt, userCode, language, contextContent) {
        const langLabel = LANGUAGES[language] || language;

        // Усиливаем системный промпт указанием языка.
        const systemWithLang = `${systemPrompt}\n\nIMPORTANT: The user selected programming language: ${langLabel}. Analyze the submitted code as ${langLabel} code. If the actual code is written in another language, say this at the beginning of the final answer in Russian, then still perform the analysis. Write the final answer in Russian. For any suggested code, keep identifiers in English and use Russian only for comments, docstrings, log/user-facing messages, and explanatory prose. Do not use Chinese or any other natural language besides Russian in prose or comments.`;

        let userContent = `Язык программирования: ${langLabel}\n\n`;

        if (contextContent) {
            userContent += `Контекст (из прикреплённого файла):\n${contextContent}\n\n`;
        }

        userContent += `Код для анализа:\n\`\`\`${language}\n${userCode}\n\`\`\``;

        return [
            { role: 'system', content: systemWithLang },
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
            url: LLMService.buildLocalChatUrl(s),
            apiKey: '',
            model: s.localModel || 'local-model'
        };
    }

    async callLLM(messages, onChunk, abortSignal, options = {}) {
        // options: { modelOverride, endpointOverride: 'local' | 'cloud', temperature, maxTokens }
        let config;
        if (options.endpointOverride === 'local') {
            const s = this.state.settings;
            config = {
                url: LLMService.buildLocalChatUrl(s),
                apiKey: '',
                model: options.modelOverride || s.localModel || 'local-model'
            };
        } else {
            config = this.getEndpointConfig();
            if (options.modelOverride) config.model = options.modelOverride;
        }

        if (!options.endpointOverride && this.state.settings.mode === 'cloud' && !config.apiKey) {
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
            temperature: options.temperature ?? this.state.settings.temperature,
            max_tokens: options.maxTokens ?? this.state.settings.maxTokens
        };

        // Раздельные таймауты:
        //  - ttfbTimeoutSec (по умолчанию 120с) — на ожидание ПЕРВОГО чанка. Сервер
        //    может молча обрабатывать огромный промпт минутами; короткий TTFB-таймаут
        //    помогает быстрее показать пользователю, что что-то пошло не так
        //    (вероятно, n_ctx сервера не вмещает запрос).
        //  - requestTimeoutSec (по умолчанию 300с) — idle между чанками после старта
        //    стрима. Reasoning-модели могут думать долго между токенами.
        const ttfbTimeoutSec = this.state.settings.ttfbTimeoutSec || 120;
        const idleTimeoutSec = this.state.settings.requestTimeoutSec || 300;
        const timeoutController = new AbortController();
        let timeoutFired = false;
        let firstDataReceived = false;
        let timeoutId = null;
        const armTimeout = (sec) => {
            if (timeoutId) clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                timeoutFired = true;
                timeoutController.abort();
            }, sec * 1000);
        };
        const clearTtfbTimeout = () => {
            if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
        };
        // Стартуем с TTFB. На первом data:-чанке переармируемся на idle.
        armTimeout(ttfbTimeoutSec);
        const combinedSignal = LLMService._combineSignals(abortSignal, timeoutController.signal);

        let response;
        try {
            response = await fetch(config.url, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
                signal: combinedSignal
            });
        } catch (err) {
            clearTtfbTimeout();
            if (err.name === 'AbortError') {
                // Различаем пользовательский abort vs TTFB-таймаут на этапе fetch.
                if (timeoutFired) {
                    const isLocal = this.state.settings.mode === 'local';
                    const hint = isLocal
                        ? ` Возможные причины: модель не загружена в Xinference/LM Studio, превышен n_ctx сервера, либо сервер обрабатывает слишком большой запрос. Проверьте лог Xinference и уменьшите объём кода или включите чанкование.`
                        : ` Возможные причины: сетевая задержка или перегрузка API. Попробуйте повторить запрос.`;
                    throw new Error(`Таймаут до первого ответа сервера (${ttfbTimeoutSec} сек).${hint}`);
                }
                throw err;
            }
            // Сетевые ошибки (CORS, DNS, ECONNREFUSED) — fetch выбрасывает TypeError "Failed to fetch"
            if (err instanceof TypeError) {
                const isLocal = this.state.settings.mode === 'local';
                const target = isLocal ? config.url : 'облачный API';
                throw new Error(`Не удалось подключиться к ${target}. Проверьте: сервер запущен, адрес правильный, сеть/CORS разрешает запрос.`);
            }
            throw err;
        }

        // Headers получены, но для SSE это ещё не означает первый чанк данных — сервер мог
        // открыть stream и молчать. TTFB-таймер сбрасываем ниже, при первой реальной data:-строке.

        if (!response.ok) {
            clearTtfbTimeout();
            const errText = await response.text().catch(() => '');
            let detail = '';
            try {
                const errJson = JSON.parse(errText);
                detail = errJson.error?.message || errJson.message || errText;
            } catch { detail = errText; }

            // Специальная подсказка для типичных ошибок переполнения контекста
            const lowered = (detail || '').toLowerCase();
            const overflowHints = ['context length', 'context_length', 'max_position', 'n_ctx', 'maximum context', 'too long', 'token limit', 'context window'];
            const isOverflow = overflowHints.some(h => lowered.includes(h));
            if (isOverflow) {
                throw new Error(`Превышен контекст модели на сервере. ${detail || ''} → Уменьшите объём кода, либо увеличьте окно контекста при загрузке модели в Xinference/LM Studio/Ollama.`);
            }

            throw new Error(`API Error ${response.status}: ${detail || response.statusText}`);
        }

        // DoS-лимиты для защиты от сломанного/злонамеренного сервера, который шлёт
        // бесконечный поток или одну гигантскую строку без \n.
        const MAX_BUFFER_BYTES = 1024 * 1024;       // 1 MB на накапливаемую SSE-строку
        const MAX_TOTAL_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB total на content+reasoning

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let fullContent = '';
        let fullReasoning = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                if (buffer.length > MAX_BUFFER_BYTES) {
                    throw new Error(`Сервер отправил SSE-строку длиннее ${MAX_BUFFER_BYTES / 1024} КБ без разделителя — соединение прервано во избежание зависания.`);
                }
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed || !trimmed.startsWith('data:')) continue;

                    // Первый data: от сервера → переход от TTFB-таймера к idle-таймеру.
                    // Следующие data: → reset idle-таймера (модель «жива», просто думает между токенами).
                    if (!firstDataReceived) firstDataReceived = true;
                    armTimeout(idleTimeoutSec);

                    const data = trimmed.slice(5).trim();
                    if (data === '[DONE]') continue;

                    // Разделяем try: парсинг (где ожидаемы malformed-чанки) и применение
                    // дельты + onChunk (где ошибки должны всплывать наружу для диагностики,
                    // а не глушиться как "malformed chunk").
                    let parsed;
                    try {
                        parsed = JSON.parse(data);
                    } catch {
                        continue; // malformed chunk — это норма для SSE с keep-alive
                    }
                    const delta = parsed.choices?.[0]?.delta;
                    if (!delta) continue;

                    const reasoningDelta = delta.reasoning_content || delta.reasoning || null;
                    const contentDelta = delta.content || null;

                    if (reasoningDelta) fullReasoning += reasoningDelta;
                    if (contentDelta) fullContent += contentDelta;

                    if (fullContent.length + fullReasoning.length > MAX_TOTAL_RESPONSE_BYTES) {
                        throw new Error(`Ответ превысил ${MAX_TOTAL_RESPONSE_BYTES / (1024 * 1024)} МБ — соединение прервано. Частичный ответ сохранён.`);
                    }

                    if (reasoningDelta || contentDelta) {
                        // onChunk-ошибки (DOM, render) пробрасываем — не маскируем под malformed.
                        onChunk({ contentDelta, reasoningDelta, fullContent, fullReasoning });
                    }
                }
            }
        } catch (err) {
            // Различаем три случая abort'а из reader.read():
            // 1) Таймер сработал ДО первого чанка — TTFB-таймаут.
            // 2) Таймер сработал ПОСЛЕ первого чанка — idle-таймаут (модель замолчала).
            // 3) Пользовательский Stop.
            if (err.name === 'AbortError' && timeoutFired) {
                const isLocal = this.state.settings.mode === 'local';
                if (!firstDataReceived) {
                    const hint = isLocal
                        ? ` Сервер открыл стрим, но не прислал ни одного чанка за ${ttfbTimeoutSec} сек. Возможные причины: запрос слишком большой для n_ctx модели — сервер «думает» над промптом дольше TTFB-таймаута. Включите чанкование или уменьшите код.`
                        : ` Сервер открыл стрим, но не прислал данные за ${ttfbTimeoutSec} сек.`;
                    throw new Error(`Таймаут первого чанка (${ttfbTimeoutSec} сек).${hint}`);
                } else {
                    const hint = isLocal
                        ? ` Модель замолчала посреди генерации. Возможные причины: переполнение n_ctx во время вывода, OOM, сбой сервера. Частичный ответ сохранён.`
                        : ` Соединение зависло посреди стрима.`;
                    throw new Error(`Idle-таймаут стрима (${idleTimeoutSec} сек без данных).${hint}`);
                }
            }
            throw err;
        } finally {
            clearTtfbTimeout();
        }

        return { content: fullContent, reasoning: fullReasoning };
    }

    static _createTimeoutSignal(ms) {
        if (typeof AbortSignal.timeout === 'function') {
            return AbortSignal.timeout(ms);
        }
        const controller = new AbortController();
        setTimeout(() => controller.abort(), ms);
        return controller.signal;
    }

    static _combineSignals(...signals) {
        const filtered = signals.filter(Boolean);
        if (filtered.length === 0) return undefined;
        if (filtered.length === 1) return filtered[0];
        if (typeof AbortSignal.any === 'function') {
            return AbortSignal.any(filtered);
        }
        const controller = new AbortController();
        for (const s of filtered) {
            if (s.aborted) { controller.abort(s.reason); break; }
            s.addEventListener('abort', () => controller.abort(s.reason), { once: true });
        }
        return controller.signal;
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
            signal: LLMService._createTimeoutSignal(10000)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const json = await response.json();
        return json.model || config.model;
    }

    async fetchLocalModels() {
        const settings = this.state.settings;
        const provider = settings.localProvider || LLMService.inferLocalProviderFromUrl(settings.localUrl);
        const config = LLMService.getLocalProviderConfig(provider);
        let lastError = null;

        for (const url of LLMService.buildLocalModelListUrls(settings)) {
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    signal: LLMService._createTimeoutSignal(10000)
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const json = await response.json();
                return LLMService.parseLocalModels(json, provider);
            } catch (err) {
                lastError = err;
            }
        }

        throw new Error(`${config.label}: ${lastError?.message || 'не удалось получить список моделей'}`);
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
        html = html.replace(/```([\w+-]*)[ \t]*\r?\n([\s\S]*?)```/g, (_, lang, code) => {
            const idx = codeBlocks.length;
            codeBlocks.push({ lang, code: MarkdownRenderer.escapeHtml(code.trim()) });
            return `%%CODEBLOCK_${idx}%%`;
        });

        // During streaming a model can emit an opening fence before the closing ```.
        // Treat the rest as code so Python comments like "# Настройки" do not become H1.
        html = html.replace(/```([\w+-]*)[ \t]*\r?\n([\s\S]*)$/m, (_, lang, code) => {
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
            return `<div class="code-block-wrapper"><button class="btn-copy-code">Копировать</button><pre><code class="lang-${block.lang}">${block.code}</code></pre></div>`;
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
        if (str === null || str === undefined) return '';
        const s = typeof str === 'string' ? str : String(str);
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return s.replace(/[&<>"']/g, c => map[c]);
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
        if (!container) return;
        const iconMap = {
            success: '#i-check',
            error: '#i-warning',
            warning: '#i-warning'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        // Иконка — собирается через DOM (createElementNS для SVG), без innerHTML.
        const iconHref = iconMap[type] || '#i-check';
        const SVG_NS = 'http://www.w3.org/2000/svg';
        const XLINK_NS = 'http://www.w3.org/1999/xlink';
        const iconSpan = document.createElement('span');
        iconSpan.className = 'toast-icon';
        const svg = document.createElementNS(SVG_NS, 'svg');
        svg.setAttribute('class', 'icon');
        const useEl = document.createElementNS(SVG_NS, 'use');
        useEl.setAttribute('href', iconHref);
        useEl.setAttributeNS(XLINK_NS, 'xlink:href', iconHref);
        svg.appendChild(useEl);
        iconSpan.appendChild(svg);

        // Сообщение — только через textContent, никакого HTML от внешних источников.
        const msgSpan = document.createElement('span');
        msgSpan.textContent = message === null || message === undefined ? '' : String(message);

        toast.appendChild(iconSpan);
        toast.appendChild(msgSpan);
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'toastOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
}

/* ============================================================
   VIBECODING MANAGER
   ============================================================ */
class VibeCodingManager {
    constructor(app) {
        this.app = app;
        this.state = app.state;
        this.llm = app.llm;
        this.iterations = [];       // { num, code, review, score, coderModel, reviewerModel }
        this.isRunning = false;
        this.abortController = null;
        this.currentTask = '';
        this.currentLang = 'python';
        this._localModelsCache = {};
    }

    init() {
        this._bindUI();
        this._restorePromptsToUI();
        this._renderBanner();
        this._updateRunButton();
    }

    /* ---------- helpers ---------- */
    static _getLLMVisibleText(result) {
        const content = result?.content || '';
        if (content.trim()) return content;
        return result?.reasoning || '';
    }

    static _getIterationCopyText(column, visibleText, finalText = '') {
        const final = String(finalText || '').trim();
        if (column === 'coder' && final) return final;
        return String(visibleText || '').trim();
    }

    static _normalizeCoderCellText(text) {
        const raw = String(text || '').trim();
        if (!raw) return '';

        const matches = [...raw.matchAll(/```[\w+-]*\r?\n([\s\S]*?)```/g)];
        if (matches.length > 0) {
            let best = matches[0][1];
            for (const m of matches) {
                if (m[1].length > best.length) best = m[1];
            }
            return best.trim();
        }

        return raw
            .replace(/^```[\w+-]*\s*/i, '')
            .replace(/\s*```$/i, '')
            .trim();
    }

    static _renderCoderCellHtml(text) {
        const code = VibeCodingManager._normalizeCoderCellText(text) || '# Кодер пока не вернул код';
        return `<pre class="vibe-code-cell"><code>${MarkdownRenderer.escapeHtml(code)}</code></pre>`;
    }

    static _shouldAutoCollapseIteration(iterValue, currentIter) {
        const iter = Number.parseInt(iterValue, 10);
        return Number.isFinite(iter) && iter < currentIter;
    }

    static _buildDefaultVibeLanguageInstruction(role, language, langLabel) {
        const lang = language || '';
        const label = langLabel || lang || 'не указан';
        let instruction = role === 'reviewer'
            ? `\n\nProgramming language: ${label}. If you provide corrected code or a code fragment, put it into a separate fenced code block \`\`\`${lang || 'text'} … \`\`\` so it can be copied separately. Write the review in Russian. Write all review prose in Russian. Use English for code identifiers. Do not use Chinese or any other natural language besides Russian in prose, comments, docstrings, or explanations.`
            : `\n\nProgramming language: ${label}. Wrap the final code in a \`\`\`${lang || 'text'} … \`\`\` block. Use English for code identifiers. Write comments, docstrings, and user-facing explanatory text in Russian only. Do not use Chinese or any other natural language besides Russian in comments, docstrings, messages, or explanations.`;

        if (lang === 'javascript') {
            if (role === 'reviewer') {
                instruction += `\n\n--- JavaScript context ---
Review JavaScript-specific behavior, not abstract pseudocode: correct browser/Node runtime choice, no accidental mixing of DOM APIs with Node-only APIs, Promise rejection handling, async/await, and async error handling.
Review DOM safety: no XSS through innerHTML, insertAdjacentHTML, or document.write with user-controlled data; safe output should use textContent, DOM APIs, or explicit sanitization.
Review lifecycle and cleanup: event listeners should be removed when needed, timers and AbortController should be cleaned up, and global variables should not pollute window/globalThis.
Review JS quality: const/let instead of var, strict equality ===/!==, clear null/undefined handling, no unnecessary input mutation, and no hidden race conditions.
Do not lower the score only because there is no TypeScript, React, bundler, npm package, or test framework unless the user explicitly requested them. If you suggest corrected JS code, provide it in a separate \`\`\`javascript fenced code block.`;
                return instruction;
            }

            instruction += `\n\n--- JavaScript ---
Write modern JavaScript without TypeScript unless the user explicitly requested TypeScript.
Respect the runtime first: browser, Node.js, or universal JS. Do not mix DOM APIs and Node-only APIs without a clear reason.
Use const/let instead of var, strict equality ===/!==, small functions, explicit null/undefined handling, and meaningful English names.
For async code, use async/await with try/catch or explicit Promise rejection handling. Do not leave unhandled promises.
For browser code, do not insert user-controlled data through innerHTML; use textContent, DOM APIs, or explicit sanitization. Clean up event listeners, timers, and AbortController instances when they are created.
Do not add npm dependencies, CDN links, React/Vue, a bundler, or a file structure unless the user explicitly requested them. Return one complete copyable JS fragment.`;
            return instruction;
        }

        if (lang !== 'python') return instruction;

        if (role === 'reviewer') {
            instruction += `\n\n--- Python/Jupyter Notebook context ---
The code is intended to be copied into one Jupyter Notebook or JupyterLab cell, not necessarily into a standalone .py file.
Do not lower the score only because argparse, sys.argv, if __name__ == "__main__", or CLI structure is missing, unless the user explicitly requested a script or package.
Treat any plain prose without # inside Python code as a critical bug: a line like "Settings at the top of the cell" without # causes SyntaxError. Explanations inside code must be valid Python comments with #, or docstrings only where syntactically appropriate.
Review notebook ergonomics: input file variables should be clear and near the top of the cell; output should be explicit via display(...), .head(), or print(...) when appropriate; do not split into extra files unless asked.
Criticize real problems: bugs, security, data handling, readability, reproducibility, and notebook run ergonomics.`;
            return instruction;
        }

        instruction += `\n\n--- Python/Jupyter Notebook ---
Write Python as code for one Jupyter Notebook or JupyterLab cell, so the user can copy it and run it immediately in a notebook.
Inside the code block, do not write plain prose without #. Every explanatory line must be a valid Python comment with #, otherwise the cell will raise SyntaxError.
Keep the code compact: do not leave more than one blank line in a row.
Do not create CLI scaffolding unless explicitly requested: do not use argparse, sys.argv, or if __name__ == "__main__".
If Excel, CSV, or JSON input files are needed, define clear English variables near the top of the cell, for example file_path = "data.xlsx".
For tabular results, use pandas and show the result with display(...), .head(), or print(...) when appropriate.
Do not split the answer into several files; create separate files only if the user explicitly requested a full project or module.`;
        return instruction;
    }

    static _normalizeAutoInstruction(text) {
        return String(text || '').trim();
    }

    static _buildVibeLanguageInstruction(role, language, langLabel, customInstruction = null) {
        const custom = VibeCodingManager._normalizeAutoInstruction(customInstruction);
        if (custom) return `\n\n${custom}`;
        return VibeCodingManager._buildDefaultVibeLanguageInstruction(role, language, langLabel);
    }

    static _buildFinalSystemPrompt(role, basePrompt, language, langLabel, customInstruction = null) {
        const fallback = role === 'reviewer' ? DEFAULT_VIBE_REVIEWER_PROMPT : DEFAULT_VIBE_CODER_PROMPT;
        const rootPrompt = String(basePrompt || '').trim() || fallback;
        const languageInstruction = VibeCodingManager._buildVibeLanguageInstruction(role, language, langLabel, customInstruction);
        return role === 'reviewer'
            ? `${rootPrompt}${languageInstruction}${REVIEWER_SCORE_INSTRUCTION}`
            : `${rootPrompt}${languageInstruction}`;
    }

    static _getLanguageInstructionSummary(role, language, langLabel, customInstruction = null) {
        const label = langLabel || language || 'выбранный язык';
        if (VibeCodingManager._normalizeAutoInstruction(customInstruction)) {
            return `${label}: используется пользовательское автодополнение. Оно заменяет стандартный языковой блок для этой роли и языка.`;
        }
        if (language === 'python') {
            return role === 'reviewer'
                ? `${label}: проверка рассчитана на одну ячейку Jupyter, обычный текст без # внутри кода считается SyntaxError; исправленные фрагменты нужно отдавать отдельными code block.`
                : `${label}: итоговый код должен быть одной копируемой ячейкой Jupyter; пояснения внутри кода только через #, без CLI-обвязки без явной просьбы.`;
        }
        if (language === 'javascript') {
            return role === 'reviewer'
                ? `${label}: ревью учитывает browser/Node окружение, Promise/async ошибки, DOM XSS, lifecycle listener/timer и качество современного JS.`
                : `${label}: код пишется как modern JS без TypeScript/npm/CDN/фреймворков без просьбы, с учетом browser/Node окружения и async/error handling.`;
        }
        return `${label}: итоговый промпт дополняется выбранным языком и форматом ответа для роли.`;
    }

    static _coerceScore(value) {
        if (typeof value === 'number' && Number.isFinite(value)) {
            const rounded = Math.round(value);
            return rounded >= 1 && rounded <= 10 ? rounded : null;
        }
        if (typeof value !== 'string') return null;
        const clean = value.trim().replace(',', '.');
        const ratio = clean.match(/^(\d{1,2})(?:\.\d+)?\s*\/\s*10\b/);
        const plain = clean.match(/^(\d{1,2})(?:\.\d+)?$/);
        const score = ratio ? parseInt(ratio[1], 10) : (plain ? parseInt(plain[1], 10) : null);
        return score !== null && score >= 1 && score <= 10 ? score : null;
    }

    static _scoreFromJsonValue(value) {
        const scoreKeys = new Set(['score', 'rating', 'grade', 'оценка', 'балл', 'баллы']);
        if (Array.isArray(value)) {
            for (const item of value) {
                const score = VibeCodingManager._scoreFromJsonValue(item);
                if (score !== null) return score;
            }
            return null;
        }
        if (!value || typeof value !== 'object') return null;

        for (const [key, item] of Object.entries(value)) {
            if (scoreKeys.has(key.toLowerCase())) {
                const score = VibeCodingManager._coerceScore(item);
                if (score !== null) return score;
            }
        }
        for (const item of Object.values(value)) {
            const score = VibeCodingManager._scoreFromJsonValue(item);
            if (score !== null) return score;
        }
        return null;
    }

    static _findJsonCandidates(text) {
        const candidates = [];
        const raw = String(text || '');
        raw.replace(/```(?:json)?\s*([\s\S]*?)```/gi, (_, body) => {
            candidates.push(body.trim());
            return '';
        });

        const trimmed = raw.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            candidates.push(trimmed);
        }

        for (let i = 0; i < raw.length; i++) {
            if (raw[i] !== '{' && raw[i] !== '[') continue;
            const startChar = raw[i];
            const endChar = startChar === '{' ? '}' : ']';
            let depth = 0;
            let inString = false;
            let escape = false;
            for (let j = i; j < raw.length; j++) {
                const ch = raw[j];
                if (escape) {
                    escape = false;
                    continue;
                }
                if (ch === '\\') {
                    escape = true;
                    continue;
                }
                if (ch === '"') {
                    inString = !inString;
                    continue;
                }
                if (inString) continue;
                if (ch === startChar) depth++;
                if (ch === endChar) depth--;
                if (depth === 0) {
                    candidates.push(raw.slice(i, j + 1));
                    i = j;
                    break;
                }
            }
        }
        return [...new Set(candidates.filter(Boolean))];
    }

    static _extractScoreFromJson(text) {
        for (const candidate of VibeCodingManager._findJsonCandidates(text)) {
            try {
                const parsed = JSON.parse(candidate);
                const score = VibeCodingManager._scoreFromJsonValue(parsed);
                if (score !== null) return score;
            } catch { /* not strict JSON, try next candidate */ }
        }
        return null;
    }

    static _extractScoreLine(text) {
        const lines = (text || '').split('\n').slice(0, 10);
        for (const line of lines) {
            const clean = line.replace(/[*_]+/g, '').trim();
            const prefixed = clean.match(/^(ОЦЕНКА|SCORE)\s*[:：]\s*(\d{1,2})\s*\/\s*10\b/i);
            const bare = clean.match(/^(\d{1,2})\s*\/\s*10\b/);
            const score = prefixed ? parseInt(prefixed[2], 10) : (bare ? parseInt(bare[1], 10) : null);
            if (score !== null && score >= 1 && score <= 10) {
                return `ОЦЕНКА: ${score}/10`;
            }
        }
        const jsonScore = VibeCodingManager._extractScoreFromJson(text);
        if (jsonScore !== null) return `ОЦЕНКА: ${jsonScore}/10`;
        return '';
    }

    static _createRecoveredReview(scoreText, reviewText) {
        const scoreLine = VibeCodingManager._extractScoreLine(scoreText);
        if (!scoreLine) return reviewText || '';
        const review = (reviewText || '').trim();
        return `${scoreLine}\n\n_Оценка восстановлена отдельным коротким запросом, потому что ревьюер не вернул её первой строкой._\n\n${review}`;
    }

    static _buildScoreRecoveryMessages({ langLabel, task, code, review }) {
        return [
            {
                role: 'system',
                content: 'Ты нормализатор результата code review. По коду и тексту ревью выставь итоговую оценку. Предпочтительный ответ — ровно одна строка в формате: ОЦЕНКА: N/10. Если модель принудительно отвечает JSON, верни строго {"score":N}. N — целое число от 1 до 10. Никаких пояснений, markdown, заголовков и дополнительных строк.'
            },
            {
                role: 'user',
                content:
                    `Язык: ${langLabel}\n\n` +
                    `Задача:\n${task}\n\n` +
                    `Код:\n\`\`\`\n${code}\n\`\`\`\n\n` +
                    `Текст ревью без формальной оценки:\n${review}`
            }
        ];
    }

    _getScoreRecoveryModel(reviewerModel, coderModel) {
        return (coderModel && coderModel !== reviewerModel) ? coderModel : reviewerModel;
    }

    _getCoderPrompt() {
        return (this.state.settings.vibeCoderPrompt || '').trim() || DEFAULT_VIBE_CODER_PROMPT;
    }

    _getReviewerPrompt() {
        return (this.state.settings.vibeReviewerPrompt || '').trim() || DEFAULT_VIBE_REVIEWER_PROMPT;
    }

    _parseScore(reviewText) {
        if (!reviewText) return null;
        // Удаляем markdown-обёртки **_, чтобы паттерны были устойчивыми к "форматированию"
        const stripMd = (s) => s.replace(/[*_]+/g, '');
        const lines = reviewText.split('\n');
        const firstLine = stripMd(lines.find(l => l.trim()) || '');

        // Поиск строго в первой непустой строке — основной сценарий
        const strictPatterns = [
            /ОЦЕНКА\s*[:：]\s*(\d{1,2})\s*\/\s*10/i,
            /SCORE\s*[:：]\s*(\d{1,2})\s*\/\s*10/i,
            /^\s*(\d{1,2})\s*\/\s*10\b/
        ];
        for (const re of strictPatterns) {
            const m = firstLine.match(re);
            if (m) {
                const n = parseInt(m[1], 10);
                if (n >= 1 && n <= 10) return n;
            }
        }
        // Фолбэк: явный префикс «ОЦЕНКА:» в первых 5 строках
        const head = stripMd(lines.slice(0, 5).join('\n'));
        const fallbackMatch = head.match(/ОЦЕНКА\s*[:：]\s*(\d{1,2})\s*\/\s*10/i)
            || head.match(/SCORE\s*[:：]\s*(\d{1,2})\s*\/\s*10/i);
        if (fallbackMatch) {
            const n = parseInt(fallbackMatch[1], 10);
            if (n >= 1 && n <= 10) return n;
        }
        const jsonScore = VibeCodingManager._extractScoreFromJson(reviewText);
        if (jsonScore !== null) return jsonScore;
        return null;
    }

    _scoreClass(score) {
        if (score === null || score === undefined) return 'score-na';
        if (score >= 9) return 'score-good';
        if (score >= 7) return 'score-warn';
        return 'score-bad';
    }

    _extractCodeFromCoderOutput(text) {
        if (!text) return '';
        // \r?\n — некоторые серверы LM Studio/прокси возвращают CRLF.
        // Берём САМЫЙ ДЛИННЫЙ блок: модели часто показывают «было/стало», финальная версия длиннее.
        const matches = [...text.matchAll(/```[\w+-]*\r?\n([\s\S]*?)```/g)];
        if (matches.length === 0) return text.trim();
        let best = matches[0][1];
        for (const m of matches) {
            if (m[1].length > best.length) best = m[1];
        }
        return best.trim();
    }

    _getPromptElementId(which) {
        return which === 'reviewer' ? 'vibe-reviewer-prompt' : 'vibe-coder-prompt';
    }

    _getPromptFinalElementId(which) {
        return which === 'reviewer' ? 'vibe-reviewer-final-prompt' : 'vibe-coder-final-prompt';
    }

    _getPromptSummaryElementId(which) {
        return which === 'reviewer' ? 'vibe-reviewer-auto-summary' : 'vibe-coder-auto-summary';
    }

    _getAutoEditorElementId(which) {
        return which === 'reviewer' ? 'vibe-reviewer-auto-editor' : 'vibe-coder-auto-editor';
    }

    _getCurrentLanguagePair() {
        const langSelect = document.getElementById('vibe-lang');
        const language = langSelect?.value || this.currentLang || 'python';
        return { language, label: LANGUAGES[language] || language };
    }

    _getDefaultAutoInstruction(which, language, label) {
        return VibeCodingManager._buildDefaultVibeLanguageInstruction(which, language, label).trim();
    }

    _getSavedAutoInstruction(which, language) {
        const store = this.state.settings.vibeLanguageInstructions || {};
        const value = store?.[which]?.[language];
        return typeof value === 'string' && value.trim() ? value.trim() : '';
    }

    _normalizeAutoOverride(which, language, label, value) {
        const text = VibeCodingManager._normalizeAutoInstruction(value);
        const def = this._getDefaultAutoInstruction(which, language, label);
        return text && text !== def ? text : null;
    }

    _getAutoInstructionOverride(which, language, label) {
        const editor = document.getElementById(this._getAutoEditorElementId(which));
        if (editor) {
            return this._normalizeAutoOverride(which, language, label, editor.value);
        }
        return this._normalizeAutoOverride(which, language, label, this._getSavedAutoInstruction(which, language));
    }

    _populateAutoEditor(which) {
        const editor = document.getElementById(this._getAutoEditorElementId(which));
        if (!editor) return;
        const { language, label } = this._getCurrentLanguagePair();
        editor.value = this._getSavedAutoInstruction(which, language) || this._getDefaultAutoInstruction(which, language, label);
    }

    _populateAutoEditors() {
        this._populateAutoEditor('coder');
        this._populateAutoEditor('reviewer');
    }

    _saveAutoInstruction(which) {
        const { language, label } = this._getCurrentLanguagePair();
        const editor = document.getElementById(this._getAutoEditorElementId(which));
        if (!editor) return;

        const custom = this._normalizeAutoOverride(which, language, label, editor.value);
        if (!this.state.settings.vibeLanguageInstructions || typeof this.state.settings.vibeLanguageInstructions !== 'object') {
            this.state.settings.vibeLanguageInstructions = {};
        }

        if (custom) {
            if (!this.state.settings.vibeLanguageInstructions[which]) {
                this.state.settings.vibeLanguageInstructions[which] = {};
            }
            this.state.settings.vibeLanguageInstructions[which][language] = custom;
        } else if (this.state.settings.vibeLanguageInstructions[which]) {
            delete this.state.settings.vibeLanguageInstructions[which][language];
            if (Object.keys(this.state.settings.vibeLanguageInstructions[which]).length === 0) {
                delete this.state.settings.vibeLanguageInstructions[which];
            }
        }
    }

    _clearAutoInstruction(which, language = null) {
        const targetLang = language || this._getCurrentLanguagePair().language;
        const store = this.state.settings.vibeLanguageInstructions;
        if (!store?.[which]) return;
        delete store[which][targetLang];
        if (Object.keys(store[which]).length === 0) delete store[which];
    }

    _clearAutoInstructionsForRole(which) {
        const store = this.state.settings.vibeLanguageInstructions;
        if (store?.[which]) delete store[which];
    }

    _updatePromptPreview(which) {
        const source = document.getElementById(this._getPromptElementId(which));
        const target = document.getElementById(this._getPromptFinalElementId(which));
        const summary = document.getElementById(this._getPromptSummaryElementId(which));
        if (!source || !target || !summary) return;

        const { language, label } = this._getCurrentLanguagePair();
        const customInstruction = this._getAutoInstructionOverride(which, language, label);
        target.value = VibeCodingManager._buildFinalSystemPrompt(which, source.value, language, label, customInstruction);
        summary.textContent = VibeCodingManager._getLanguageInstructionSummary(which, language, label, customInstruction);
    }

    _updatePromptPreviews() {
        this._updatePromptPreview('coder');
        this._updatePromptPreview('reviewer');
    }

    _toggleFinalPrompt(which) {
        const box = document.querySelector(`[data-vibe-prompt-preview="${which}"]`);
        const btn = document.querySelector(`[data-vibe-final-toggle="${which}"]`);
        if (!box || !btn) return;

        this._updatePromptPreview(which);
        const opened = !box.classList.contains('is-open');
        box.classList.toggle('is-open', opened);
        btn.textContent = opened ? 'Скрыть итоговый промпт' : 'Показать итоговый промпт';
    }

    _toggleAutoEditor(which) {
        const box = document.querySelector(`[data-vibe-prompt-preview="${which}"]`);
        const btn = document.querySelector(`[data-vibe-auto-toggle="${which}"]`);
        if (!box || !btn) return;

        const opened = !box.classList.contains('is-editing');
        if (opened) {
            this._populateAutoEditor(which);
        }
        this._updatePromptPreview(which);
        box.classList.toggle('is-editing', opened);
        btn.textContent = opened ? 'Скрыть автодополнение' : 'Изменить автодополнение';
    }

    _resetAutoInstruction(which) {
        const { language, label } = this._getCurrentLanguagePair();
        this._clearAutoInstruction(which, language);
        const editor = document.getElementById(this._getAutoEditorElementId(which));
        if (editor) editor.value = this._getDefaultAutoInstruction(which, language, label);
        this.state.saveSettings();
        this._updatePromptPreview(which);
        Toast.show('Автодополнение восстановлено по умолчанию');
    }

    async _copyFinalPrompt(which) {
        this._updatePromptPreview(which);
        const target = document.getElementById(this._getPromptFinalElementId(which));
        const text = target?.value?.trim() || '';
        if (!text) {
            Toast.show('Пока нечего копировать', 'warning');
            return;
        }
        try {
            await this._writeClipboard(text);
            Toast.show('Итоговый промпт скопирован');
        } catch {
            Toast.show('Не удалось скопировать', 'warning');
        }
    }

    /* ---------- UI binding ---------- */
    _bindUI() {
        const taskInput = document.getElementById('vibe-task');
        const langSelect = document.getElementById('vibe-lang');
        const btnRun = document.getElementById('btn-vibe-run');
        const btnStop = document.getElementById('btn-vibe-stop');
        const btnReset = document.getElementById('btn-vibe-reset');
        const btnClearLog = document.getElementById('btn-vibe-clear-log');
        const btnGotoSettings = document.getElementById('vibe-goto-settings');

        taskInput.addEventListener('input', () => {
            const len = taskInput.value.length;
            document.getElementById('vibe-task-stats').textContent = `${len} символов`;
            this._updateRunButton();
        });

        langSelect.addEventListener('change', () => {
            this.currentLang = langSelect.value;
            this._populateAutoEditors();
            this._updatePromptPreviews();
        });
        this.currentLang = langSelect.value;

        ['coder', 'reviewer'].forEach(which => {
            document.getElementById(this._getPromptElementId(which))?.addEventListener('input', () => {
                this._updatePromptPreview(which);
            });
            document.querySelector(`[data-vibe-final-toggle="${which}"]`)?.addEventListener('click', () => {
                this._toggleFinalPrompt(which);
            });
            document.querySelector(`[data-vibe-final-copy="${which}"]`)?.addEventListener('click', () => {
                this._copyFinalPrompt(which);
            });
            document.getElementById(this._getAutoEditorElementId(which))?.addEventListener('input', () => {
                this._updatePromptPreview(which);
            });
            document.querySelector(`[data-vibe-auto-toggle="${which}"]`)?.addEventListener('click', () => {
                this._toggleAutoEditor(which);
            });
            document.querySelector(`[data-vibe-auto-reset="${which}"]`)?.addEventListener('click', () => {
                this._resetAutoInstruction(which);
            });
        });

        btnRun.addEventListener('click', () => this.runCycle());
        btnStop.addEventListener('click', () => this.stop());
        btnReset.addEventListener('click', () => this.resetIterations());
        btnClearLog.addEventListener('click', () => this._clearLog());

        btnGotoSettings.addEventListener('click', (e) => {
            e.preventDefault();
            this.app.navigateTo('settings');
            // Двойной rAF — гарантирует, что страница успела отрендериться
            requestAnimationFrame(() => requestAnimationFrame(() => {
                const card = document.querySelector('#page-settings .card h2 use[href="#i-sparkles"]');
                card?.closest('.card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }));
        });

        document.querySelectorAll('[data-vibe-save]').forEach(btn => {
            btn.addEventListener('click', () => this._saveColumnPrompt(btn.dataset.vibeSave));
        });
        document.querySelectorAll('[data-vibe-reset]').forEach(btn => {
            btn.addEventListener('click', () => this._resetColumnPrompt(btn.dataset.vibeReset));
        });

        document.getElementById('btn-vibe-continue').addEventListener('click', () => this._fallbackContinue());
        document.getElementById('btn-vibe-take-best').addEventListener('click', () => this._fallbackTake('best'));
        document.getElementById('btn-vibe-take-last').addEventListener('click', () => this._fallbackTake('last'));
        document.getElementById('btn-vibe-abort').addEventListener('click', () => this._fallbackAbort());

        // Закрытие fallback-модалки по клику на подложку
        const fallbackOverlay = document.getElementById('vibe-fallback-overlay');
        fallbackOverlay.addEventListener('click', (e) => {
            if (e.target === fallbackOverlay) this._hideFallbackModal();
        });
    }

    _restorePromptsToUI() {
        document.getElementById('vibe-coder-prompt').value = this._getCoderPrompt();
        document.getElementById('vibe-reviewer-prompt').value = this._getReviewerPrompt();
        this._populateAutoEditors();
        this._updatePromptPreviews();
    }

    _saveColumnPrompt(which) {
        const id = which === 'coder' ? 'vibe-coder-prompt' : 'vibe-reviewer-prompt';
        const field = which === 'coder' ? 'vibeCoderPrompt' : 'vibeReviewerPrompt';
        const val = document.getElementById(id).value.trim();
        const def = which === 'coder' ? DEFAULT_VIBE_CODER_PROMPT : DEFAULT_VIBE_REVIEWER_PROMPT;
        this.state.settings[field] = (val === def) ? '' : val;
        this._saveAutoInstruction(which);
        this.state.saveSettings();
        const settingsId = which === 'coder' ? 'vibe-coder-prompt-settings' : 'vibe-reviewer-prompt-settings';
        const settingsField = document.getElementById(settingsId);
        if (settingsField) settingsField.value = val || def;
        this._updatePromptPreview(which);
        Toast.show(`Промпт ${which === 'coder' ? 'Кодера' : 'Ревьюера'} сохранён`);
    }

    _resetColumnPrompt(which) {
        const id = which === 'coder' ? 'vibe-coder-prompt' : 'vibe-reviewer-prompt';
        const def = which === 'coder' ? DEFAULT_VIBE_CODER_PROMPT : DEFAULT_VIBE_REVIEWER_PROMPT;
        document.getElementById(id).value = def;
        const field = which === 'coder' ? 'vibeCoderPrompt' : 'vibeReviewerPrompt';
        this.state.settings[field] = '';
        this._clearAutoInstructionsForRole(which);
        this.state.saveSettings();
        const settingsId = which === 'coder' ? 'vibe-coder-prompt-settings' : 'vibe-reviewer-prompt-settings';
        const settingsField = document.getElementById(settingsId);
        if (settingsField) settingsField.value = def;
        this._populateAutoEditor(which);
        this._updatePromptPreview(which);
        Toast.show('Промпт и автодополнение восстановлены по умолчанию');
    }

    /* ---------- Banner / Run-button state ---------- */
    _renderBanner() {
        const coder = this.state.settings.vibeCoderModel;
        const reviewer = this.state.settings.vibeReviewerModel;
        const maxIter = this.state.settings.vibeMaxIterations || 3;
        const threshold = this.state.settings.vibeScoreThreshold || 9;

        const coderEl = document.getElementById('vibe-coder-name');
        const reviewerEl = document.getElementById('vibe-reviewer-name');
        if (!coderEl) return;
        coderEl.textContent = coder || 'не выбран';
        coderEl.classList.toggle('empty', !coder);
        reviewerEl.textContent = reviewer || 'не выбран';
        reviewerEl.classList.toggle('empty', !reviewer);

        document.getElementById('vibe-maxiter-name').textContent = String(maxIter);
        document.getElementById('vibe-threshold-name').textContent = `${threshold}/10`;

        // Бейджи моделей с предупреждением, если обе модели одинаковые
        const coderBadge = document.getElementById('vibe-coder-model-badge');
        const reviewerBadge = document.getElementById('vibe-reviewer-model-badge');
        const sameModel = coder && reviewer && coder === reviewer;
        coderBadge.textContent = coder || '—';
        reviewerBadge.textContent = reviewer || '—';
        coderBadge.title = sameModel ? 'Внимание: Кодер и Ревьюер используют одну и ту же модель — теряется независимость оценки' : '';
        reviewerBadge.title = coderBadge.title;
        coderBadge.classList.toggle('same-model-warn', !!sameModel);
        reviewerBadge.classList.toggle('same-model-warn', !!sameModel);
    }

    _updateRunButton() {
        const btn = document.getElementById('btn-vibe-run');
        if (!btn) return;
        const task = (document.getElementById('vibe-task').value || '').trim();
        const hasModels = !!(this.state.settings.vibeCoderModel && this.state.settings.vibeReviewerModel);
        const fallbackVisible = document.getElementById('vibe-fallback-overlay')?.style.display === 'flex';
        btn.disabled = !task || !hasModels || this.isRunning || fallbackVisible;
        if (fallbackVisible) {
            btn.title = 'Завершите выбор в окне «Порог не достигнут»';
        } else if (!hasModels) {
            btn.title = 'Сначала выберите модели Кодера и Ревьюера в Настройках';
        } else if (!task) {
            btn.title = 'Введите задачу';
        } else {
            btn.title = 'Запустить цикл';
        }
    }

    /* ---------- Logging ---------- */
    _log(text, level = 'info') {
        const log = document.getElementById('vibe-log');
        const empty = log.querySelector('.vibe-log-empty');
        if (empty) empty.remove();

        const entry = document.createElement('div');
        entry.className = `vibe-log-entry log-${level}`;
        const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const timeEl = document.createElement('span');
        timeEl.className = 'vibe-log-time';
        timeEl.textContent = time;
        const textEl = document.createElement('span');
        textEl.className = 'vibe-log-text';
        textEl.textContent = text;
        entry.appendChild(timeEl);
        entry.appendChild(textEl);
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    _clearLog() {
        const log = document.getElementById('vibe-log');
        log.innerHTML = '<div class="vibe-log-empty">Лог появится при запуске цикла</div>';
    }

    /* ---------- Iteration rendering ---------- */
    _resetIterationLists() {
        document.getElementById('vibe-coder-iters').innerHTML = '<div class="vibe-iter-empty">Кодер ещё не писал</div>';
        document.getElementById('vibe-reviewer-iters').innerHTML = '<div class="vibe-iter-empty">Ревьюер ещё не проверял</div>';
    }

    resetIterations() {
        if (this.isRunning) {
            Toast.show('Сначала остановите цикл', 'warning');
            return;
        }
        this.iterations = [];
        this._resetIterationLists();
        this._clearLog();
        Toast.show('Сессия Вайбкодинга сброшена');
    }

    _createIterBlock(column, num, label) {
        this._autoCollapsePreviousIterations(num);

        const list = document.getElementById(column === 'coder' ? 'vibe-coder-iters' : 'vibe-reviewer-iters');
        const empty = list.querySelector('.vibe-iter-empty');
        if (empty) empty.remove();

        const div = document.createElement('div');
        div.className = 'vibe-iter is-streaming';
        div.dataset.iter = String(num);
        div.dataset.column = column;
        const numSpan = document.createElement('span');
        numSpan.className = 'vibe-iter-num';
        numSpan.innerHTML = `<span class="vibe-streaming-dot"></span>`;
        numSpan.appendChild(document.createTextNode(` Итерация ${num} — ${label}`));

        const header = document.createElement('div');
        header.className = 'vibe-iter-header';
        header.appendChild(numSpan);

        const tools = document.createElement('span');
        tools.className = 'vibe-iter-tools';
        const badges = document.createElement('span');
        badges.className = 'vibe-iter-badges';
        tools.appendChild(badges);
        tools.appendChild(this._createIterCollapseButton());
        tools.appendChild(this._createIterCopyButton(column));
        header.appendChild(tools);

        const body = document.createElement('div');
        body.className = 'vibe-iter-body';

        div.appendChild(header);
        div.appendChild(body);
        list.appendChild(div);
        list.scrollTop = list.scrollHeight;
        return div;
    }

    _autoCollapsePreviousIterations(currentIter) {
        document.querySelectorAll('#page-vibecode .vibe-iter').forEach(div => {
            if (VibeCodingManager._shouldAutoCollapseIteration(div.dataset.iter, currentIter)) {
                this._setIterCollapsed(div, true);
            }
        });
    }

    _createIterCollapseButton() {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'vibe-collapse-widget';
        btn.innerHTML = '<svg class="icon"><use href="#i-chevron"/></svg>';
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const block = btn.closest('.vibe-iter');
            if (!block) return;
            this._setIterCollapsed(block, !block.classList.contains('is-collapsed'));
        });
        this._syncIterCollapseButton(btn, false);
        return btn;
    }

    _setIterCollapsed(div, collapsed) {
        if (!div) return;
        div.classList.toggle('is-collapsed', collapsed);
        this._syncIterCollapseButton(div.querySelector('.vibe-collapse-widget'), collapsed);
    }

    _syncIterCollapseButton(btn, collapsed) {
        if (!btn) return;
        const label = collapsed ? 'Развернуть итерацию' : 'Свернуть итерацию';
        btn.title = label;
        btn.setAttribute('aria-label', label);
        btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    }

    _createIterCopyButton(column) {
        const label = column === 'coder' ? 'Скопировать код' : 'Скопировать ревью';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'vibe-copy-widget';
        btn.title = label;
        btn.setAttribute('aria-label', label);
        btn.disabled = true;
        btn.innerHTML = '<svg class="icon"><use href="#i-copy"/></svg>';
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            this._copyIterText(btn.closest('.vibe-iter'));
        });
        return btn;
    }

    _setIterCopyText(div, text) {
        div._copyText = String(text || '').trim();
        const btn = div.querySelector('.vibe-copy-widget');
        if (btn) btn.disabled = !div._copyText;
    }

    _writeClipboard(text) {
        if (navigator.clipboard?.writeText) {
            return navigator.clipboard.writeText(text);
        }

        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.left = '-9999px';
        area.style.top = '0';
        document.body.appendChild(area);
        area.select();
        try {
            const ok = document.execCommand('copy');
            return ok ? Promise.resolve() : Promise.reject(new Error('copy command failed'));
        } finally {
            area.remove();
        }
    }

    async _copyIterText(div) {
        if (!div) return;
        const text = String(div._copyText || '').trim();
        if (!text) {
            Toast.show('Пока нечего копировать', 'warning');
            return;
        }

        const btn = div.querySelector('.vibe-copy-widget');
        const column = div.dataset.column;
        const successText = column === 'reviewer' ? 'Ревью скопировано' : 'Код скопирован';
        try {
            await this._writeClipboard(text);
            this._flashIterCopyButton(btn);
            Toast.show(successText);
        } catch {
            Toast.show('Не удалось скопировать', 'warning');
        }
    }

    _flashIterCopyButton(btn) {
        if (!btn) return;
        clearTimeout(btn._copyResetTimer);
        const icon = btn.querySelector('use');
        btn.classList.add('copied');
        if (icon) icon.setAttribute('href', '#i-check');
        btn._copyResetTimer = setTimeout(() => {
            btn.classList.remove('copied');
            if (icon) icon.setAttribute('href', '#i-copy');
        }, 1200);
    }

    _updateIterBody(div, text) {
        const body = div.querySelector('.vibe-iter-body');
        if (div.dataset.column === 'coder') {
            const code = VibeCodingManager._normalizeCoderCellText(text);
            this._setIterCopyText(div, code);
            body.innerHTML = VibeCodingManager._renderCoderCellHtml(text);
        } else {
            this._setIterCopyText(div, text);
            body.innerHTML = MarkdownRenderer.render(text || '*(пусто)*');
        }
        const list = div.parentElement;
        list.scrollTop = list.scrollHeight;
    }

    _finalizeCoderIter(div, num, code) {
        div.classList.remove('is-streaming');
        const numEl = div.querySelector('.vibe-iter-num');
        numEl.innerHTML = '';
        numEl.appendChild(document.createTextNode(`Итерация ${num}`));
        this._updateIterBody(div, code);
        this._setIterCopyText(div, VibeCodingManager._getIterationCopyText('coder', div._copyText, code));
    }

    _finalizeReviewerIter(div, num, score, reviewText = '') {
        div.classList.remove('is-streaming');
        const numEl = div.querySelector('.vibe-iter-num');
        numEl.innerHTML = '';
        numEl.appendChild(document.createTextNode(`Итерация ${num}`));
        this._setIterCopyText(div, VibeCodingManager._getIterationCopyText('reviewer', reviewText || div._copyText));
        const badges = div.querySelector('.vibe-iter-badges');
        badges.innerHTML = '';
        const span = document.createElement('span');
        span.className = `vibe-score-badge ${this._scoreClass(score)}`;
        span.textContent = score === null ? 'оценка не распознана' : `${score}/10`;
        badges.appendChild(span);
    }

    _markFinal(num) {
        document.querySelectorAll(`.vibe-iter[data-iter="${num}"]`).forEach(div => {
            div.classList.add('is-final');
            const badges = div.querySelector('.vibe-iter-badges');
            if (badges && !badges.querySelector('.vibe-final-badge')) {
                const span = document.createElement('span');
                span.className = 'vibe-final-badge';
                span.innerHTML = '<svg class="icon"><use href="#i-check"/></svg> Финал';
                badges.appendChild(span);
            }
        });
    }

    _markBest(num) {
        document.querySelectorAll(`.vibe-iter[data-iter="${num}"]`).forEach(div => {
            div.classList.add('is-best');
            const badges = div.querySelector('.vibe-iter-badges');
            if (badges && !badges.querySelector('.vibe-best-badge') && !badges.querySelector('.vibe-final-badge')) {
                const span = document.createElement('span');
                span.className = 'vibe-best-badge';
                span.textContent = 'Лучший';
                badges.appendChild(span);
            }
        });
    }

    /* ---------- Main cycle ---------- */
    async runCycle() {
        if (this.isRunning) return;

        const task = document.getElementById('vibe-task').value.trim();
        if (!task) { Toast.show('Введите задачу', 'warning'); return; }

        const coderModel = this.state.settings.vibeCoderModel;
        const reviewerModel = this.state.settings.vibeReviewerModel;
        if (!coderModel || !reviewerModel) {
            Toast.show('Выберите модели Кодера и Ревьюера в Настройках', 'warning');
            return;
        }

        this.iterations = [];
        this.currentTask = task;
        this.currentLang = document.getElementById('vibe-lang').value;
        this._resetIterationLists();

        const taskPreview = task.length > 80 ? task.slice(0, 80) + '…' : task;
        this._log(`Старт. Задача: «${taskPreview}»`, 'info');
        this._log(`Кодер: ${coderModel} | Ревьюер: ${reviewerModel} | Язык: ${LANGUAGES[this.currentLang] || this.currentLang}`, 'info');

        await this._loop(this.state.settings.vibeMaxIterations || 3);
    }

    async _loop(maxIterations) {
        this._setRunning(true);
        this.abortController = new AbortController();
        try {
            const startFrom = this.iterations.length;
            for (let i = 0; i < maxIterations; i++) {
                const iterNum = startFrom + i + 1;
                const prevIter = this.iterations[this.iterations.length - 1] || null;
                await this._doOneIteration(iterNum, prevIter);

                if (this.abortController.signal.aborted) {
                    this._log('Цикл остановлен пользователем', 'warn');
                    return;
                }

                const last = this.iterations[this.iterations.length - 1];
                if (last && last.score !== null && last.score >= this.state.settings.vibeScoreThreshold) {
                    this._log(`Порог ${this.state.settings.vibeScoreThreshold}/10 достигнут на итерации ${iterNum}. Финал.`, 'ok');
                    this._markFinal(iterNum);
                    return;
                }
            }
            this._showFallbackModal();
        } catch (err) {
            if (err.name === 'AbortError') {
                this._log('Цикл прерван', 'warn');
            } else {
                this._log(`Ошибка: ${err.message}`, 'err');
                Toast.show(err.message, 'error', 6000);
            }
        } finally {
            // Снимаем оставшиеся "пульсирующие" блоки — если abort/error прервали итерацию
            this._cleanupOrphanStreamingBlocks();
            this._setRunning(false);
            this.abortController = null;
        }
    }

    _cleanupOrphanStreamingBlocks() {
        document.querySelectorAll('#page-vibecode .vibe-iter.is-streaming').forEach(div => {
            div.classList.remove('is-streaming');
            const numEl = div.querySelector('.vibe-iter-num');
            if (numEl) {
                const iter = div.dataset.iter;
                numEl.innerHTML = '';
                numEl.appendChild(document.createTextNode(`Итерация ${iter} — прервано`));
            }
            const badges = div.querySelector('.vibe-iter-badges');
            if (badges && !badges.querySelector('.vibe-score-badge') && !badges.querySelector('.vibe-final-badge')) {
                const span = document.createElement('span');
                span.className = 'vibe-score-badge score-na';
                span.textContent = 'прервано';
                badges.appendChild(span);
            }
        });
    }

    async _doOneIteration(iterNum, prevIter) {
        const coderModel = this.state.settings.vibeCoderModel;
        const reviewerModel = this.state.settings.vibeReviewerModel;
        const langLabel = LANGUAGES[this.currentLang] || this.currentLang;

        /* --- Step 1: Coder --- */
        this._log(`Итерация ${iterNum} — Кодер (${coderModel}) пишет…`, 'info');
        const coderBlock = this._createIterBlock('coder', iterNum, 'Кодер пишет…');

        const coderSystem = VibeCodingManager._buildFinalSystemPrompt(
            'coder',
            document.getElementById('vibe-coder-prompt').value,
            this.currentLang,
            langLabel,
            this._getAutoInstructionOverride('coder', this.currentLang, langLabel)
        );

        let coderUser;
        if (prevIter && prevIter.code) {
            const prevScoreLabel = prevIter.score === null ? '?' : `${prevIter.score}/10`;
            // Очищаем замечания: убираем первую строку с «ОЦЕНКА: N/10», она для парсера, не для модели.
            // Поддерживаем markdown-обёртки (**ОЦЕНКА**, _ОЦЕНКА_), которые иногда генерят модели.
            const reviewClean = (prevIter.review || '')
                .replace(/^\s*[*_]*\s*(ОЦЕНКА|SCORE)\s*[*_]*\s*[:：]\s*[*_]*\s*\d{1,2}\s*\/\s*10\s*[*_]*[^\n]*\n?/i, '')
                .trim() || '(без замечаний)';
            coderUser =
                `Исходная задача:\n${this.currentTask}\n\n` +
                `Предыдущая версия кода (итерация ${prevIter.num}, оценка ${prevScoreLabel}):\n` +
                `\`\`\`${this.currentLang}\n${prevIter.code}\n\`\`\`\n\n` +
                `Замечания Ревьюера:\n${reviewClean}\n\n` +
                `Исправь код согласно замечаниям. Верни ПОЛНУЮ исправленную версию (не дифф).`;
        } else {
            coderUser = `Задача: ${this.currentTask}`;
        }

        const coderMessages = [
            { role: 'system', content: coderSystem },
            { role: 'user', content: coderUser }
        ];

        const coderResult = await this.llm.callLLM(
            coderMessages,
            ({ fullContent, fullReasoning }) => this._updateIterBody(
                coderBlock,
                VibeCodingManager._getLLMVisibleText({ content: fullContent, reasoning: fullReasoning })
            ),
            this.abortController.signal,
            { endpointOverride: 'local', modelOverride: coderModel }
        );

        if (this.abortController.signal.aborted) return;

        const coderVisibleText = VibeCodingManager._getLLMVisibleText(coderResult);
        const codeOnly = this._extractCodeFromCoderOutput(coderVisibleText);
        this._finalizeCoderIter(coderBlock, iterNum, codeOnly);
        this._log(`Итерация ${iterNum} — Кодер закончил (${codeOnly.split('\n').length} строк)`, 'info');

        /* --- Step 2: Reviewer --- */
        this._log(`Итерация ${iterNum} — Ревьюер (${reviewerModel}) проверяет…`, 'info');
        const reviewerBlock = this._createIterBlock('reviewer', iterNum, 'Ревьюер анализирует…');

        const reviewerSystem = VibeCodingManager._buildFinalSystemPrompt(
            'reviewer',
            document.getElementById('vibe-reviewer-prompt').value,
            this.currentLang,
            langLabel,
            this._getAutoInstructionOverride('reviewer', this.currentLang, langLabel)
        );

        const reviewerUser =
            `Язык: ${langLabel}\n\nЗадача автора:\n${this.currentTask}\n\n` +
            `Код на ревью:\n\`\`\`${this.currentLang}\n${codeOnly}\n\`\`\``;

        const reviewerMessages = [
            { role: 'system', content: reviewerSystem },
            { role: 'user', content: reviewerUser }
        ];

        const reviewerResult = await this.llm.callLLM(
            reviewerMessages,
            ({ fullContent, fullReasoning }) => this._updateIterBody(
                reviewerBlock,
                VibeCodingManager._getLLMVisibleText({ content: fullContent, reasoning: fullReasoning })
            ),
            this.abortController.signal,
            { endpointOverride: 'local', modelOverride: reviewerModel }
        );

        if (this.abortController.signal.aborted) return;

        let reviewerVisibleText = VibeCodingManager._getLLMVisibleText(reviewerResult);
        let score = this._parseScore(reviewerVisibleText);

        if (score === null && reviewerVisibleText.trim()) {
            const recoveryModel = this._getScoreRecoveryModel(reviewerModel, coderModel);
            this._log(`Итерация ${iterNum} — ревьюер не вернул оценку, запрашиваю короткую оценку через ${recoveryModel}…`, 'warn');

            const recoveryResult = await this.llm.callLLM(
                VibeCodingManager._buildScoreRecoveryMessages({
                    langLabel,
                    task: this.currentTask,
                    code: codeOnly,
                    review: reviewerVisibleText
                }),
                () => {},
                this.abortController.signal,
                {
                    endpointOverride: 'local',
                    modelOverride: recoveryModel,
                    temperature: 0,
                    maxTokens: 512
                }
            );

            if (this.abortController.signal.aborted) return;

            const recoveredReview = VibeCodingManager._createRecoveredReview(
                VibeCodingManager._getLLMVisibleText(recoveryResult),
                reviewerVisibleText
            );
            const recoveredScore = this._parseScore(recoveredReview);
            if (recoveredScore !== null) {
                reviewerVisibleText = recoveredReview;
                score = recoveredScore;
                this._updateIterBody(reviewerBlock, reviewerVisibleText);
                this._log(`Итерация ${iterNum} — оценка восстановлена: ${score}/10`, 'info');
            }
        }

        this._finalizeReviewerIter(reviewerBlock, iterNum, score, reviewerVisibleText);

        if (score === null) {
            this._log(`Итерация ${iterNum} — оценку распарсить не удалось (ожидаю «ОЦЕНКА: N/10» в первой строке)`, 'warn');
        } else {
            const lvl = score >= this.state.settings.vibeScoreThreshold ? 'ok' : (score >= 7 ? 'info' : 'warn');
            this._log(`Итерация ${iterNum} — оценка ${score}/10`, lvl);
        }

        this.iterations.push({
            num: iterNum,
            code: codeOnly,
            review: reviewerVisibleText,
            score: score,
            coderModel,
            reviewerModel
        });
    }

    stop() {
        if (this.abortController) {
            this.abortController.abort();
        }
    }

    _setRunning(isRunning) {
        this.isRunning = isRunning;
        const btnRun = document.getElementById('btn-vibe-run');
        const btnStop = document.getElementById('btn-vibe-stop');
        const btnReset = document.getElementById('btn-vibe-reset');
        const btnClearLog = document.getElementById('btn-vibe-clear-log');
        const taskInput = document.getElementById('vibe-task');
        const langSelect = document.getElementById('vibe-lang');
        if (isRunning) {
            btnRun.style.display = 'none';
            btnStop.style.display = 'inline-flex';
            taskInput.disabled = true;
            langSelect.disabled = true;
            if (btnReset) btnReset.disabled = true;
            if (btnClearLog) btnClearLog.disabled = true;
        } else {
            btnRun.style.display = 'inline-flex';
            btnStop.style.display = 'none';
            taskInput.disabled = false;
            langSelect.disabled = false;
            if (btnReset) btnReset.disabled = false;
            if (btnClearLog) btnClearLog.disabled = false;
            this._updateRunButton();
        }
    }

    /* ---------- Fallback modal ---------- */
    _showFallbackModal() {
        const best = this.iterations.reduce((acc, it) =>
            (it.score !== null && (!acc || it.score > acc.score)) ? it : acc, null);
        const last = this.iterations[this.iterations.length - 1];
        const threshold = this.state.settings.vibeScoreThreshold || 9;
        const more = this.state.settings.vibeMaxIterations || 3;

        const bestNum = best ? String(best.num) : '?';
        const bestScoreLabel = best ? `${best.score}/10` : '—';
        const lastScoreLabel = last && last.score !== null ? `${last.score}/10` : 'не определена';

        // Строим текст безопасно через createElement — без innerHTML с переменными
        const textEl = document.getElementById('vibe-fallback-text');
        textEl.innerHTML = '';
        const sentence1 = document.createElement('span');
        sentence1.append('За ');
        const b1 = document.createElement('b'); b1.textContent = String(this.iterations.length); sentence1.appendChild(b1);
        sentence1.append(' итераций оценка так и не достигла порога ');
        const b2 = document.createElement('b'); b2.textContent = `${threshold}/10`; sentence1.appendChild(b2);
        sentence1.append('. Лучшая попытка — итерация ');
        const b3 = document.createElement('b'); b3.textContent = bestNum; sentence1.appendChild(b3);
        sentence1.append(' с оценкой ');
        const b4 = document.createElement('b'); b4.textContent = bestScoreLabel; sentence1.appendChild(b4);
        sentence1.append('. Последняя оценка — ');
        const b5 = document.createElement('b'); b5.textContent = lastScoreLabel; sentence1.appendChild(b5);
        sentence1.append('.');
        textEl.appendChild(sentence1);

        // Динамический текст кнопки «Продолжить»
        const continueBtn = document.getElementById('btn-vibe-continue');
        if (continueBtn) continueBtn.textContent = `Продолжить ещё ${more} итер.`;

        document.getElementById('vibe-fallback-overlay').style.display = 'flex';
        this._log(`Порог не достигнут за ${this.iterations.length} итераций. Жду решения пользователя.`, 'warn');
        this._updateRunButton();
    }

    _hideFallbackModal() {
        document.getElementById('vibe-fallback-overlay').style.display = 'none';
        this._updateRunButton();
    }

    async _fallbackContinue() {
        this._hideFallbackModal();
        const more = this.state.settings.vibeMaxIterations || 3;
        this._log(`Пользователь выбрал: ещё ${more} итераций`, 'info');
        await this._loop(more);
    }

    _fallbackTake(which) {
        this._hideFallbackModal();
        let target;
        if (which === 'best') {
            target = this.iterations.reduce((acc, it) =>
                (it.score !== null && (!acc || it.score > acc.score)) ? it : acc, null) || this.iterations[this.iterations.length - 1];
        } else {
            target = this.iterations[this.iterations.length - 1];
        }
        if (!target) return;
        // Маркируем «Лучший» только если оценка известна и это не последняя итерация
        const isLast = target === this.iterations[this.iterations.length - 1];
        if (which === 'best' && target.score !== null && !isLast) {
            this._markBest(target.num);
            this._log(`Принят лучший вариант: итерация ${target.num} (${target.score}/10)`, 'ok');
        } else {
            this._markFinal(target.num);
            const scoreLabel = target.score === null ? '?' : `${target.score}/10`;
            // Если "best" сошёлся с последней — это и есть финал, говорим прямо.
            const labelKind = (which === 'best' && !isLast) ? 'лучший' : 'финальный';
            this._log(`Принят ${labelKind} вариант: итерация ${target.num} (${scoreLabel})`, 'ok');
        }
        Toast.show(`Готово — итерация ${target.num} выбрана как финал`);
    }

    _fallbackAbort() {
        this._hideFallbackModal();
        this._log('Пользователь завершил без принятия результата', 'warn');
    }

    /* ---------- Settings page integration ---------- */
    bindSettingsCard() {
        const fetchBtn = document.getElementById('btn-vibe-fetch');
        if (!fetchBtn) return;

        fetchBtn.addEventListener('click', () => this._fetchModels());

        document.getElementById('vibe-coder-model').addEventListener('change', (e) => {
            this.state.settings.vibeCoderModel = e.target.value;
            this.state.saveSettings();
            this._renderBanner();
            this._updateRunButton();
        });
        document.getElementById('vibe-reviewer-model').addEventListener('change', (e) => {
            this.state.settings.vibeReviewerModel = e.target.value;
            this.state.saveSettings();
            this._renderBanner();
            this._updateRunButton();
        });

        document.getElementById('vibe-max-iter').addEventListener('change', (e) => {
            this.state.settings.vibeMaxIterations = parseInt(e.target.value, 10) || 3;
            this.state.saveSettings();
            this._renderBanner();
        });
        document.getElementById('vibe-threshold').addEventListener('change', (e) => {
            this.state.settings.vibeScoreThreshold = parseInt(e.target.value, 10) || 9;
            this.state.saveSettings();
            this._renderBanner();
        });

        const coderTA = document.getElementById('vibe-coder-prompt-settings');
        const reviewerTA = document.getElementById('vibe-reviewer-prompt-settings');
        coderTA.addEventListener('blur', () => {
            const val = coderTA.value.trim();
            this.state.settings.vibeCoderPrompt = (val === DEFAULT_VIBE_CODER_PROMPT) ? '' : val;
            this.state.saveSettings();
            document.getElementById('vibe-coder-prompt').value = val || DEFAULT_VIBE_CODER_PROMPT;
            this._updatePromptPreview('coder');
        });
        reviewerTA.addEventListener('blur', () => {
            const val = reviewerTA.value.trim();
            this.state.settings.vibeReviewerPrompt = (val === DEFAULT_VIBE_REVIEWER_PROMPT) ? '' : val;
            this.state.saveSettings();
            document.getElementById('vibe-reviewer-prompt').value = val || DEFAULT_VIBE_REVIEWER_PROMPT;
            this._updatePromptPreview('reviewer');
        });

        document.querySelectorAll('[data-vibe-reset-settings]').forEach(btn => {
            btn.addEventListener('click', () => {
                const which = btn.dataset.vibeResetSettings;
                const def = which === 'coder' ? DEFAULT_VIBE_CODER_PROMPT : DEFAULT_VIBE_REVIEWER_PROMPT;
                const taId = which === 'coder' ? 'vibe-coder-prompt-settings' : 'vibe-reviewer-prompt-settings';
                document.getElementById(taId).value = def;
                const field = which === 'coder' ? 'vibeCoderPrompt' : 'vibeReviewerPrompt';
                this.state.settings[field] = '';
                this._clearAutoInstructionsForRole(which);
                this.state.saveSettings();
                document.getElementById(which === 'coder' ? 'vibe-coder-prompt' : 'vibe-reviewer-prompt').value = def;
                this._populateAutoEditor(which);
                this._updatePromptPreview(which);
                Toast.show('Промпт и автодополнение восстановлены по умолчанию');
            });
        });
    }

    renderSettingsCard() {
        const s = this.state.settings;
        const maxIterEl = document.getElementById('vibe-max-iter');
        if (!maxIterEl) return;
        maxIterEl.value = String(s.vibeMaxIterations || 3);
        document.getElementById('vibe-threshold').value = String(s.vibeScoreThreshold || 9);
        document.getElementById('vibe-coder-prompt-settings').value = (s.vibeCoderPrompt || '').trim() || DEFAULT_VIBE_CODER_PROMPT;
        document.getElementById('vibe-reviewer-prompt-settings').value = (s.vibeReviewerPrompt || '').trim() || DEFAULT_VIBE_REVIEWER_PROMPT;

        // Если основная карточка уже загрузила модели, переиспользуем её кэш
        if (this.app._localModelsCache && Object.keys(this.app._localModelsCache).length > 0
            && Object.keys(this._localModelsCache || {}).length === 0) {
            this._localModelsCache = { ...this.app._localModelsCache };
            const hint = document.getElementById('vibe-fetch-hint');
            if (hint) hint.textContent = `найдено: ${Object.keys(this._localModelsCache).length}`;
        }

        this._renderModelDropdowns();
    }

    _renderModelDropdowns() {
        const cache = this._localModelsCache || {};
        const ids = Object.keys(cache);
        const coderSel = document.getElementById('vibe-coder-model');
        const reviewerSel = document.getElementById('vibe-reviewer-model');
        if (!coderSel || !reviewerSel) return;

        const s = this.state.settings;

        // Сборка через appendChild — без сериализации в HTML, XSS-безопасно.
        const populate = (sel, selected) => {
            sel.innerHTML = '';
            const placeholder = document.createElement('option');
            placeholder.value = '';
            if (ids.length === 0) {
                placeholder.textContent = '-- Нажмите «Обновить» --';
                sel.appendChild(placeholder);
                if (selected) {
                    const opt = document.createElement('option');
                    opt.value = selected;
                    opt.textContent = `${selected} (сохранено, не загружено)`;
                    opt.selected = true;
                    sel.appendChild(opt);
                }
                return;
            }
            placeholder.textContent = `-- Выберите модель (${ids.length}) --`;
            sel.appendChild(placeholder);
            ids.forEach(id => {
                const m = cache[id];
                let label = m.name;
                if (m.contextLength) label += ` [${Math.round(m.contextLength / 1024)}K]`;
                const opt = document.createElement('option');
                opt.value = id;
                opt.textContent = label;
                if (id === selected) opt.selected = true;
                sel.appendChild(opt);
            });
            if (selected && !ids.includes(selected)) {
                const opt = document.createElement('option');
                opt.value = selected;
                opt.textContent = `${selected} (сохранено, не в списке)`;
                opt.selected = true;
                sel.appendChild(opt);
            }
        };

        populate(coderSel, s.vibeCoderModel);
        populate(reviewerSel, s.vibeReviewerModel);
    }

    async _fetchModels() {
        const urlInput = document.getElementById('setting-local-url');
        if (urlInput && urlInput.value.trim()) {
            this.state.settings.localUrl = urlInput.value.trim();
        }

        const btn = document.getElementById('btn-vibe-fetch');
        const hint = document.getElementById('vibe-fetch-hint');
        const orig = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Загрузка...';
        btn.disabled = true;
        hint.textContent = '';

        try {
            const models = await this.llm.fetchLocalModels();
            this._localModelsCache = {};
            models.forEach(m => this._localModelsCache[m.id] = m);
            this._renderModelDropdowns();
            hint.textContent = `найдено: ${models.length}`;

            // Синхронизация с основной карточкой настроек
            this.app._localModelsCache = { ...this._localModelsCache };
            const mainSelect = document.getElementById('setting-local-model-select');
            const mainHint = document.getElementById('local-model-hint');
            if (mainSelect) {
                mainSelect.innerHTML = '';
                const placeholder = document.createElement('option');
                placeholder.value = '';
                placeholder.textContent = models.length === 0
                    ? 'Модели не найдены'
                    : `-- Выберите модель (${models.length}) --`;
                mainSelect.appendChild(placeholder);
                models.forEach(m => {
                    const opt = document.createElement('option');
                    opt.value = m.id;
                    let label = m.name;
                    if (m.contextLength) label += ` [${Math.round(m.contextLength / 1024)}K]`;
                    if (m.owned_by) label += ` (${m.owned_by})`;
                    opt.textContent = label;
                    mainSelect.appendChild(opt);
                });
                const current = this.state.settings.localModel;
                if (current) mainSelect.value = current;
                if (this.app.updateLocalModelTypeIndicator) {
                    this.app.updateLocalModelTypeIndicator(mainSelect.value);
                }
            }
            if (mainHint) mainHint.textContent = `(найдено: ${models.length})`;

            Toast.show(`Найдено моделей: ${models.length}`);
        } catch (err) {
            hint.textContent = `ошибка: ${err.message}`;
            Toast.show(`Не удалось загрузить модели: ${err.message}`, 'error', 6000);
        } finally {
            btn.innerHTML = orig;
            btn.disabled = false;
        }
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

        // Vibecoding
        this.vibe = new VibeCodingManager(this);
        this.vibe.init();
        this.vibe.bindSettingsCard();

        this.renderActionButtons();
        this.renderSettingsForm();
        this.renderPromptsTable();
        this.renderHistory();
        this.updateConnectionStatus();
        this.selectFirstAction();
        this.bindTokenMeter();
        this.bindGlobalKeys();
        this.bindCodeCopyDelegation();
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

        // Refresh page-specific state
        if (page === 'vibecode' && this.vibe) {
            this.vibe._renderBanner();
            this.vibe._updateRunButton();
        }
        if (page === 'settings' && this.vibe) {
            this.vibe.renderSettingsCard();
        }

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

    _isKnownLocalDefaultUrl(url) {
        const normalize = (value) => String(value || '').trim()
            .replace(/\/+$/, '')
            .replace(/\/v1$/i, '')
            .replace(/\/api$/i, '');
        const current = normalize(url);
        try {
            const parsed = new URL(current);
            const loopbackHosts = ['localhost', '127.0.0.1', '[::1]', '::1'];
            const defaultPorts = Object.values(LOCAL_PROVIDER_CONFIG)
                .map(p => new URL(p.defaultUrl).port)
                .filter(Boolean);
            if (loopbackHosts.includes(parsed.hostname) && defaultPorts.includes(parsed.port)) {
                return true;
            }
        } catch { /* ignore malformed/incomplete input */ }
        return [DEFAULT_LOCAL_URL, ...Object.values(LOCAL_PROVIDER_CONFIG).map(p => p.defaultUrl)]
            .map(normalize)
            .includes(current);
    }

    _setLocalProviderControlState({ providerSelectId, urlInputId, modelSelectId, hintId, settings, replaceDefaultUrl = false }) {
        const providerSelect = document.getElementById(providerSelectId);
        const urlInput = document.getElementById(urlInputId);
        const provider = providerSelect?.value || settings.localProvider || LLMService.inferLocalProviderFromUrl(settings.localUrl);
        const config = LLMService.getLocalProviderConfig(provider);

        if (providerSelect) providerSelect.value = provider;
        settings.localProvider = provider;

        if (urlInput) {
            const currentUrl = urlInput.value.trim();
            urlInput.placeholder = config.defaultUrl;
            if (replaceDefaultUrl && (!currentUrl || this._isKnownLocalDefaultUrl(currentUrl))) {
                urlInput.value = config.defaultUrl;
            } else if (!currentUrl) {
                urlInput.value = settings.localUrl || config.defaultUrl;
            }
            settings.localUrl = urlInput.value.trim();
        }

        if (replaceDefaultUrl) {
            settings.localModel = '';
            const modelSelect = document.getElementById(modelSelectId);
            if (modelSelect) modelSelect.innerHTML = '<option value="">-- Нажмите "Загрузить" --</option>';
            const hint = document.getElementById(hintId);
            if (hint) hint.textContent = '';
        }
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
            this.state.selectedAction = null;
            this.renderActionButtons();
            this.selectFirstAction();
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

    static _validateTextFile(file) {
        const MAX_FILE_SIZE = 512 * 1024;
        const ALLOWED_EXTENSIONS = ['.txt', '.md', '.markdown'];
        const ext = '.' + (file.name.split('.').pop() || '').toLowerCase();

        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            return `Неподдерживаемый формат файла (${ext}). Допустимые: .txt, .md`;
        }
        if (file.size > MAX_FILE_SIZE) {
            return `Файл слишком большой (${(file.size / 1024 / 1024).toFixed(1)} МБ). Максимум: 500 КБ`;
        }
        return null;
    }

    static _isBinaryContent(content) {
        const sample = content.substring(0, 1000);
        const nonPrintable = (sample.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
        return nonPrintable > sample.length * 0.1;
    }

    static _formatFileSize(size) {
        return size < 1024 ? `${size} Б` : `${(size / 1024).toFixed(1)} КБ`;
    }

    handleFileAttach(file) {
        const error = Application._validateTextFile(file);
        if (error) {
            Toast.show(error, 'error', 5000);
            document.getElementById('file-input').value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            if (Application._isBinaryContent(content)) {
                Toast.show('Файл содержит бинарные данные. Поддерживаются только текстовые форматы (.txt, .md)', 'error', 5000);
                document.getElementById('file-input').value = '';
                return;
            }

            this.state.attachedFile = file.name;
            this.state.attachedFileContent = content;
            const info = document.getElementById('attached-file-info');
            const sizeLabel = Application._formatFileSize(file.size);
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
        const pct = (v) => contextWindow > 0 ? Math.min((v / contextWindow) * 100, 100) : 0;
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
        // Toggle details on click + keyboard (a11y).
        const meter = document.querySelector('.token-meter');
        const details = document.getElementById('token-details');
        meter.setAttribute('role', 'button');
        meter.setAttribute('tabindex', '0');
        meter.setAttribute('aria-expanded', 'false');
        meter.setAttribute('aria-controls', 'token-details');
        const toggle = (e) => {
            if (e.target.closest('.btn-analyze')) return;
            const visible = details.style.display !== 'none';
            details.style.display = visible ? 'none' : 'block';
            meter.setAttribute('aria-expanded', String(!visible));
        };
        meter.addEventListener('click', toggle);
        meter.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggle(e);
            }
        });

        // Update token meter when action changes
        // (already triggered by updateCodeStats on code input)
        this.updateTokenMeter();
    }

    renderActionButtons() {
        const container = document.getElementById('action-buttons');
        const prompts = this.state.getPromptsForRole(this.state.selectedRole, this.state.selectedLang);

        const esc = MarkdownRenderer.escapeHtml;
        container.innerHTML = prompts.map(p => {
            const actionId = esc(p.id);
            const actionName = esc(p.actionName || '');
            return `
                <button class="action-btn ${this.state.selectedAction === p.id ? 'active' : ''}"
                        data-action-id="${actionId}">
                    ${actionName}
                </button>
            `;
        }).join('');

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
        const prompts = this.state.getPromptsForRole(this.state.selectedRole, this.state.selectedLang);
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
        const time = MarkdownRenderer.escapeHtml(msg.time || '');

        const esc = MarkdownRenderer.escapeHtml;
        const metaHtml = msg.meta ? `<span class="msg-meta">${esc(msg.meta)}</span>` : '';
        const copyBtn = msg.role === 'assistant'
            ? `<button class="btn-copy-msg" title="Скопировать ответ"><svg class="icon"><use href="#i-copy"/></svg></button>`
            : '';

        div.innerHTML = `
            <div class="msg-avatar">${esc(avatarText)}</div>
            <div class="msg-body">
                <div class="msg-header">
                    <span class="msg-name">${esc(name)}</span>
                    <span class="msg-time">${time}</span>
                    ${metaHtml}
                    ${copyBtn}
                </div>
                <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : esc(msg.content)}</div>
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
                <div class="msg-content">
                    <div class="waiting-indicator">
                        <div class="waiting-spinner"></div>
                        <span class="waiting-text">Отправка запроса...</span>
                    </div>
                </div>
            </div>
        `;

        this.bindMsgCopyBtn(div);
        this.bindReasoningToggle(div);

        container.appendChild(div);
        container.scrollTop = container.scrollHeight;

        this._startWaitingTimer(div);

        return div;
    }

    _startWaitingTimer(streamDiv) {
        this._waitingStartTime = Date.now();
        this._waitingFirstChunk = false;

        this._waitingTimerId = setInterval(() => {
            if (this._waitingFirstChunk) {
                this._clearWaitingTimer();
                return;
            }
            const elapsed = Math.floor((Date.now() - this._waitingStartTime) / 1000);
            const textEl = streamDiv.querySelector('.waiting-text');
            if (textEl && elapsed >= 1) {
                textEl.textContent = `Ожидание ответа модели... (${elapsed} сек)`;
            }
        }, 1000);
    }

    _clearWaitingTimer() {
        if (this._waitingTimerId) {
            clearInterval(this._waitingTimerId);
            this._waitingTimerId = null;
        }
    }

    updateStreamingMessage(div, info) {
        // Throttle через requestAnimationFrame: парсить markdown на каждый чанк дорого
        // (на ответе в 50KB это сотни полных переparse'ов). Накапливаем последнее состояние,
        // рендерим максимум раз в кадр (~60 fps).
        this._pendingStreamInfo = { div, info };
        if (this._streamRafId) return;
        this._streamRafId = requestAnimationFrame(() => {
            this._streamRafId = null;
            const pending = this._pendingStreamInfo;
            this._pendingStreamInfo = null;
            if (pending) this._renderStreamingMessage(pending.div, pending.info);
        });
    }

    _renderStreamingMessage(div, info) {
        const { fullContent, fullReasoning } = info;

        // Clear waiting indicator on first chunk
        if (!this._waitingFirstChunk) {
            this._waitingFirstChunk = true;
            this._clearWaitingTimer();
            const waitingEl = div.querySelector('.waiting-indicator');
            if (waitingEl) waitingEl.remove();
        }

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
            const text = msgDiv.querySelector('.msg-content')?.innerText || '';
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
        header.setAttribute('role', 'button');
        header.setAttribute('tabindex', '0');
        header.setAttribute('aria-expanded', 'false');
        const action = () => {
            const content = div.querySelector('.reasoning-content');
            const toggle = div.querySelector('.reasoning-toggle');
            const isVisible = content.style.display !== 'none';
            content.style.display = isVisible ? 'none' : 'block';
            toggle.textContent = isVisible ? 'Показать' : 'Скрыть';
            header.setAttribute('aria-expanded', String(!isVisible));
        };
        header.addEventListener('click', action);
        header.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                action();
            }
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
                const modelName = this.state.settings.localModel || '';
                if (isLikelyReasoningModel(modelName)) {
                    badgeArea.innerHTML = `<span class="msg-model-badge no-reasoning" title="Модель определена как рассуждающая, но reasoning_content не получен в ответе. Возможно, сервер не поддерживает этот формат.">Рассуждения не получены</span>`;
                } else {
                    badgeArea.innerHTML = `<span class="msg-model-badge no-reasoning">Без рассуждений</span>`;
                }
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
                    <button type="button" class="hint-card" data-role="infosec"><svg class="icon"><use href="#i-security"/></svg><span>ИБ-аудит</span></button>
                    <button type="button" class="hint-card" data-role="consultant"><svg class="icon"><use href="#i-consultant"/></svg><span>Консалтинг</span></button>
                    <button type="button" class="hint-card" data-role="developer"><svg class="icon"><use href="#i-developer"/></svg><span>Разработка</span></button>
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

        try {
            const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `codesentinel_${Date.now()}.md`;
            a.click();
            URL.revokeObjectURL(url);
            Toast.show('Чат экспортирован');
        } catch (err) {
            Toast.show('Не удалось экспортировать чат: ' + err.message, 'error');
        }
    }

    /* ------ Chunking for large files ------ */
    /**
     * Спрашивает пользователя что делать при переполнении контекста.
     * Возвращает 'cancel' | 'force' | 'chunk'.
     */
    _askOverflowAction({ used, ctxLabel, reservedLabel, isLocal, canChunk, expectedChunks, mismatch }) {
        // Mismatch предупреждение — самое важное: значит UI-значение завышено относительно
        // реального n_ctx модели. Без этого предупреждения pre-flight check мог бы пропустить
        // overflow и пользователь увидел бы зависание/таймаут вместо понятного сообщения.
        const mismatchHint = mismatch
            ? `\n\n⚠ ВАЖНО: «Окно контекста» в настройках = ${mismatch.uiCtx}, но загруженная модель сообщает ${mismatch.realCtx}. Расчёт ведётся по реальному значению модели. Чтобы избежать повторных предупреждений — нажмите «Загрузить список моделей» в настройках, нужное значение проставится автоматически.`
            : '';

        const serverHint = isLocal && !mismatch
            ? `\n\nДля локальных моделей значение «Окно контекста» должно совпадать с n_ctx модели в Xinference/LM Studio/Ollama. Если сервер загружен с меньшим контекстом — увеличьте при перезапуске.`
            : '';

        const chunkOption = canChunk
            ? `\n\n[ОК] = Разбить на ~${expectedChunks} частей и проанализировать каждую отдельно (рекомендуется для больших файлов).\n[Отмена] = Не отправлять.`
            : `\n\n[ОК] = Отправить как есть (может оборваться по контексту).\n[Отмена] = Не отправлять.`;

        const msg = `Запрос ~${used} токенов превышает доступный бюджет (${ctxLabel} контекст − ${reservedLabel} резерв ответа).${mismatchHint}${serverHint}${chunkOption}`;

        if (!canChunk) {
            return confirm(msg) ? 'force' : 'cancel';
        }
        // Для случая "может чанковать" — двухшаговый диалог.
        if (!confirm(msg)) return 'cancel';
        // ОК = чанкование; для force даём отдельный confirm.
        return 'chunk';
    }

    /**
     * Разбивает код на чанки по ~maxTokensPerChunk. Старается резать на логических границах:
     * пустые строки, объявления функций/классов. Fall-back: построчно.
     */
    _chunkCode(code, maxTokensPerChunk, language) {
        const lines = code.split('\n');
        const chunks = [];
        let currentLines = [];
        let currentTokens = 0;

        // Языко-специфичные регексы начала "большого блока"
        const blockStartPatterns = {
            python: /^\s*(def |class |async def )/,
            javascript: /^\s*(function |class |const \w+\s*=\s*\(|export |async function )/,
            js: /^\s*(function |class |const \w+\s*=\s*\(|export |async function )/,
            abap: /^\s*(FORM|FUNCTION|METHOD|CLASS|REPORT|MODULE|START-OF-SELECTION)/i,
            '1c': /^\s*(Процедура|Функция|Procedure|Function)/i
        };
        const isBlockStart = blockStartPatterns[language] || /^\s*[A-Za-zА-Яа-я_]/;

        const flush = () => {
            if (currentLines.length > 0) {
                chunks.push(currentLines.join('\n'));
                currentLines = [];
                currentTokens = 0;
            }
        };

        for (const line of lines) {
            const lineTokens = TokenEstimator.estimate(line);
            // Если добавление строки переполнит чанк И текущая строка — начало блока,
            // или если чанк УЖЕ большой и пришла пустая строка — flush.
            const wouldOverflow = currentTokens + lineTokens > maxTokensPerChunk;
            const isBoundary = isBlockStart.test(line) || line.trim() === '';

            if (wouldOverflow && currentLines.length > 0 && (isBoundary || currentTokens > maxTokensPerChunk * 0.8)) {
                flush();
            }
            currentLines.push(line);
            currentTokens += lineTokens;

            // Жёсткая граница: если чанк уже сильно превысил — flush принудительно.
            if (currentTokens > maxTokensPerChunk * 1.2) {
                flush();
            }
        }
        flush();
        return chunks;
    }

    /**
     * Выполняет анализ кода чанками. Каждый чанк — отдельный запрос с префиксом
     * "Часть N из M". Результаты складываются в чат как отдельные сообщения,
     * после всех чанков — сводное сообщение со ссылкой на полный список.
     */
    async _runAnalysisChunked({ code, prompt, systemPrompt, meta, chunkBudget }) {
        const chunks = this._chunkCode(code, chunkBudget, this.state.selectedLang);
        if (chunks.length === 0) return;

        // Маркер-сообщение для UI вместо полного кода (полный код = context bomb для follow-up).
        const codeTokens = TokenEstimator.formatCount(TokenEstimator.estimate(code));
        const codeLines = code.split('\n').length;
        const markerText = `[Большой файл: ${codeLines} строк, ~${codeTokens} токенов]\nРазбит на ${chunks.length} частей. См. ответы по каждой ниже.`;
        this.addChatMessage('user', markerText, meta);

        Toast.show(`Разбито на ${chunks.length} частей. Начинаю последовательный анализ...`, 'success', 4000);

        this.setGenerating(true);
        const allResults = [];

        try {
            for (let i = 0; i < chunks.length; i++) {
                const chunk = chunks[i];
                const chunkMeta = `${meta} | часть ${i + 1}/${chunks.length}`;
                // В UI чанковое user-сообщение показывает только заголовок + строки/токены,
                // НЕ полный код чанка. Сам код летит в API messages, но не остаётся в чате.
                const chunkLines = chunk.split('\n').length;
                const chunkTokens = TokenEstimator.formatCount(TokenEstimator.estimate(chunk));
                this.addChatMessage('user',
                    `[Часть ${i + 1}/${chunks.length}: ${chunkLines} строк, ~${chunkTokens} токенов]`,
                    chunkMeta);

                // Для каждого чанка строим свой messages с явным контекстом про часть.
                const chunkSystemPrompt = systemPrompt + `\n\n## Chunking context\nThis is part ${i + 1} of ${chunks.length} from a large file. Analyze ONLY this fragment. Do not infer the content of the other fragments. Do not write "continued in the next part"; the final summary will be prepared separately. Keep the final answer in Russian and keep code identifiers in English.`;
                const messages = this.llm.buildMessages(
                    chunkSystemPrompt,
                    chunk,
                    this.state.selectedLang,
                    this.state.attachedFileContent
                );

                const streamDiv = this.createStreamingMessage();
                this.state.abortController = new AbortController();

                try {
                    const result = await this.llm.callLLM(
                        messages,
                        (info) => this.updateStreamingMessage(streamDiv, info),
                        this.state.abortController.signal
                    );
                    this.finalizeStreamingMessage(streamDiv, result);
                    this.state.chatMessages.push({
                        role: 'assistant',
                        content: result.content,
                        meta: `Часть ${i + 1}/${chunks.length}`,
                        time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
                    });
                    allResults.push({ index: i + 1, content: result.content });
                } catch (err) {
                    const contentEl = streamDiv.querySelector('.msg-content');
                    const hasPartial = contentEl && contentEl.textContent && contentEl.textContent.trim().length > 0;
                    const isAbort = err.name === 'AbortError';
                    if (hasPartial && !isAbort) {
                        streamDiv.removeAttribute('id');
                        const errNote = document.createElement('div');
                        errNote.className = 'msg-error-note';
                        errNote.style.cssText = 'margin-top:8px;padding:8px;border-left:3px solid #ef4444;background:rgba(239,68,68,0.08);color:#fca5a5;font-size:13px';
                        errNote.textContent = `⚠ Часть ${i + 1} прервана: ${err.message}`;
                        contentEl.appendChild(errNote);
                    } else {
                        streamDiv.remove();
                        this.addChatMessage('assistant', `**Ошибка на части ${i + 1}/${chunks.length}:** ${err.message}${isAbort ? '' : '\n\nПрерываю чанкованный анализ.'}`);
                    }
                    if (isAbort) {
                        Toast.show('Прервано пользователем', 'warning');
                    }
                    return;
                }
            }

            // Финальный summary-message (без LLM, просто инфо).
            this.addChatMessage('assistant',
                `**Анализ завершён.** Обработано частей: ${allResults.length} из ${chunks.length}.\n\nКаждая часть проанализирована независимо. Для получения единой сводки по всему файлу — задайте уточняющий вопрос: "Объедини находки из всех частей в одну сводную таблицу".`,
                `Сводка чанкования`
            );

            // Follow-up context: ТОЛЬКО system prompt + краткий маркер + assistant-ответы по чанкам.
            // НЕ включаем полный код, НЕ включаем chunk user-messages — иначе следующий запрос
            // моментально пробьёт контекст (это была HIGH-находка ревьюера).
            // ВАЖНО: строим conversationHistory ДО addHistoryEntry, чтобы записать его в apiMessages
            // и сохранить возможность follow-up после restoreFromHistory.
            const compactHistory = [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: `Я загрузил большой файл (${codeLines} строк, ~${codeTokens} токенов), разбили на ${chunks.length} частей. Ниже — независимые результаты анализа каждой части. Используй их для ответа на мои уточняющие вопросы. Полный код в контексте недоступен — если для ответа нужен конкретный фрагмент, попроси меня его прислать отдельно.` },
                ...allResults.map(r => ({
                    role: 'assistant',
                    content: `## Результаты части ${r.index}/${chunks.length}\n\n${r.content}`
                }))
            ];
            this.state.conversationHistory = compactHistory;

            // Сохраняем в history с реальным apiMessages (компактным, без full-code).
            try {
                this.state.addHistoryEntry({
                    id: Date.now().toString(),
                    role: this.state.selectedRole,
                    action: prompt.actionName + ' (чанкованный)',
                    language: this.state.selectedLang,
                    timestamp: new Date().toISOString(),
                    messages: this.state.chatMessages.slice(-Math.min(this.state.chatMessages.length, chunks.length * 2 + 1)),
                    apiMessages: compactHistory,
                    codeSnippet: code.substring(0, 100)
                });
                this.renderHistory();
            } catch (saveErr) {
                Toast.show(saveErr.message, 'warning', 5000);
            }

            document.getElementById('chat-followup').disabled = false;
            document.getElementById('btn-send-followup').disabled = false;
        } finally {
            this.setGenerating(false);
            this.state.abortController = null;
            const stale = document.getElementById('streaming-msg');
            if (stale) stale.removeAttribute('id');
        }
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

        // Build system prompt with optional instruction file
        let systemPrompt = prompt.systemPrompt;
        if (prompt.contextContent) {
            systemPrompt += '\n\n--- Additional instructions ---\n' + prompt.contextContent;
        }

        // Build API messages для pre-flight оценки. User-message ДОБАВЛЯЕМ ПОСЛЕ pre-flight,
        // чтобы при выборе chunking не оставлять полный код в чате (он бы попал в
        // conversationHistory и пробил контекст на follow-up).
        const messages = this.llm.buildMessages(
            systemPrompt,
            code,
            this.state.selectedLang,
            this.state.attachedFileContent
        );

        // Pre-flight проверка бюджета токенов. Считаем не на глазок, а по реальным messages.
        const estimatedTokens = messages.reduce((sum, m) => sum + TokenEstimator.estimate(m.content || ''), 0);
        const uiCtx = this.state.settings.contextWindow || 0;
        const reserved = this.state.settings.maxTokens || 0;

        // Если есть кэш моделей и реальный contextLength модели < UI-значения,
        // считаем по реальному (защита от рассинхрона UI vs server n_ctx).
        const isLocal = this.state.settings.mode === 'local';
        const cachedModel = isLocal ? this._localModelsCache?.[this.state.settings.localModel] : null;
        const realCtx = cachedModel?.contextLength && cachedModel.contextLength < uiCtx
            ? cachedModel.contextLength
            : uiCtx;
        const mismatchDetected = realCtx !== uiCtx && realCtx > 0;
        const ctx = realCtx > 0 ? realCtx : uiCtx;
        const budget = Math.max(0, ctx - reserved);

        if (ctx > 0 && estimatedTokens > budget) {
            const used = TokenEstimator.formatCount(estimatedTokens);
            const ctxLabel = TokenEstimator.formatCount(ctx);
            const reservedLabel = TokenEstimator.formatCount(reserved);
            const overheadTokens = estimatedTokens - TokenEstimator.estimate(code);
            // Реальный per-chunk budget: вычитаем overhead (system + language instr + attached file).
            // Каждый чанк-запрос будет содержать тот же overhead + content чанка.
            const realChunkBudget = budget - overheadTokens - 500;
            const codeTokens = TokenEstimator.estimate(code);
            // canChunk: реальный бюджет ≥ 1500 токенов на чанк (минимум для осмысленного анализа)
            // И ожидается ≥2 чанков. Если overhead уже съел контекст — chunking не поможет.
            const canChunk = realChunkBudget >= 1500 && Math.ceil(codeTokens / realChunkBudget) >= 2;
            const expectedChunks = canChunk ? Math.ceil(codeTokens / realChunkBudget) : 0;
            const chunkBudget = canChunk ? realChunkBudget : 0;

            const choice = await this._askOverflowAction({
                used, ctxLabel, reservedLabel,
                isLocal: this.state.settings.mode === 'local',
                canChunk,
                expectedChunks,
                mismatch: mismatchDetected ? {
                    realCtx: TokenEstimator.formatCount(realCtx),
                    uiCtx: TokenEstimator.formatCount(uiCtx)
                } : null
            });
            if (choice === 'cancel') return;
            if (choice === 'chunk') {
                // Делегируем в чанкованный путь, не добавляя full-code user message.
                return this._runAnalysisChunked({ code, prompt, systemPrompt, meta, chunkBudget });
            }
            // 'force' — продолжаем с риском обрыва.
        }

        // Pre-flight пройден (или force) — теперь добавляем user-message с полным кодом.
        this.addChatMessage('user', code, meta);

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

            // Save to history. ВАЖНО: сбой сохранения НЕ должен ронять уже отрисованный
            // ответ — оборачиваем в отдельный try и просто показываем warning.
            try {
                this.state.addHistoryEntry({
                    id: Date.now().toString(),
                    role: this.state.selectedRole,
                    action: prompt.actionName,
                    language: this.state.selectedLang,
                    timestamp: new Date().toISOString(),
                    messages: this.state.chatMessages.slice(-2),
                    // Сохраняем conversationHistory для возможности продолжить диалог из истории.
                    apiMessages: [...this.state.conversationHistory],
                    codeSnippet: code.substring(0, 100)
                });
                this.renderHistory();
            } catch (saveErr) {
                Toast.show(saveErr.message || 'Не удалось сохранить в историю', 'warning', 6000);
            }

            // Enable follow-up
            document.getElementById('chat-followup').disabled = false;
            document.getElementById('btn-send-followup').disabled = false;

        } catch (err) {
            if (err.name === 'AbortError') {
                streamDiv.removeAttribute('id');
                this.updateStreamingMessage(streamDiv, { fullContent: '*Генерация остановлена пользователем*', fullReasoning: '' });
            } else {
                // Если в streamDiv уже есть отрисованный частичный ответ — НЕ удаляем его,
                // только аппендим error-note. Иначе пользователь теряет ответ модели,
                // даже если callLLM явно сказал "Частичный ответ сохранён" (idle/total-bytes).
                const contentEl = streamDiv.querySelector('.msg-content');
                const hasPartial = contentEl && contentEl.textContent && contentEl.textContent.trim().length > 0;
                if (hasPartial) {
                    streamDiv.removeAttribute('id');
                    const errNote = document.createElement('div');
                    errNote.className = 'msg-error-note';
                    errNote.style.cssText = 'margin-top:8px;padding:8px;border-left:3px solid #ef4444;background:rgba(239,68,68,0.08);color:#fca5a5;font-size:13px';
                    errNote.textContent = `⚠ Стрим прерван: ${err.message}`;
                    contentEl.appendChild(errNote);
                } else {
                    streamDiv.remove();
                    this.addChatMessage('assistant', `**Ошибка:** ${err.message}\n\nПроверьте настройки подключения к API.`);
                }
                Toast.show(err.message, 'error', 6000);
            }
        } finally {
            this.setGenerating(false);
            this.state.abortController = null;
            // Защита от двух элементов с одинаковым ID, если abort/error случился до finalize.
            const stale = document.getElementById('streaming-msg');
            if (stale) stale.removeAttribute('id');
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
                streamDiv.removeAttribute('id');
                this.updateStreamingMessage(streamDiv, { fullContent: '*Генерация остановлена*', fullReasoning: '' });
            } else {
                const contentEl = streamDiv.querySelector('.msg-content');
                const hasPartial = contentEl && contentEl.textContent && contentEl.textContent.trim().length > 0;
                if (hasPartial) {
                    streamDiv.removeAttribute('id');
                    const errNote = document.createElement('div');
                    errNote.className = 'msg-error-note';
                    errNote.style.cssText = 'margin-top:8px;padding:8px;border-left:3px solid #ef4444;background:rgba(239,68,68,0.08);color:#fca5a5;font-size:13px';
                    errNote.textContent = `⚠ Стрим прерван: ${err.message}`;
                    contentEl.appendChild(errNote);
                } else {
                    streamDiv.remove();
                    this.addChatMessage('assistant', `**Ошибка:** ${err.message}`);
                }
                Toast.show(err.message, 'error', 5000);
            }
        } finally {
            this.setGenerating(false);
            this.state.abortController = null;
            const stale = document.getElementById('streaming-msg');
            if (stale) stale.removeAttribute('id');
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
            this._clearWaitingTimer();
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

        document.getElementById('setting-local-provider').addEventListener('change', () => {
            this._setLocalProviderControlState({
                providerSelectId: 'setting-local-provider',
                urlInputId: 'setting-local-url',
                modelSelectId: 'setting-local-model-select',
                hintId: 'local-model-hint',
                settings: this.state.settings,
                replaceDefaultUrl: true
            });
            this.updateLocalModelTypeIndicator('');
            this.updateConnectionStatus();
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

        const timeoutInput = document.getElementById('setting-request-timeout');
        if (timeoutInput) {
            timeoutInput.addEventListener('input', () => {
                const label = document.getElementById('request-timeout-value');
                if (label) label.textContent = timeoutInput.value;
            });
        }
        const ttfbInput = document.getElementById('setting-ttfb-timeout');
        if (ttfbInput) {
            ttfbInput.addEventListener('input', () => {
                const label = document.getElementById('ttfb-timeout-value');
                if (label) label.textContent = ttfbInput.value;
            });
        }

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

        // Privacy: history toggle + TTL + purge button.
        const historyTTL = document.getElementById('setting-history-ttl');
        if (historyTTL) {
            historyTTL.addEventListener('change', (e) => {
                const v = parseInt(e.target.value) || 0;
                const label = document.getElementById('history-ttl-value');
                if (label) label.textContent = v === 0 ? 'Никогда' : `${v} дн.`;
            });
        }
        const purgeBtn = document.getElementById('btn-purge-history-now');
        if (purgeBtn) {
            purgeBtn.addEventListener('click', () => {
                if (!confirm('Удалить всю историю анализов? Это действие необратимо.')) return;
                this.state.history = [];
                this.state.saveHistory();
                this.renderHistory();
                Toast.show('История очищена');
            });
        }
    }

    renderSettingsForm() {
        const s = this.state.settings;
        document.getElementById('setting-api-key').value = s.cloudApiKey || '';
        document.getElementById('setting-cloud-url').value = s.cloudUrl || 'https://api.deepseek.com';
        document.getElementById('setting-local-provider').value = s.localProvider || LLMService.inferLocalProviderFromUrl(s.localUrl);
        document.getElementById('setting-local-url').value = s.localUrl || LLMService.getLocalProviderConfig(s.localProvider).defaultUrl;
        this._setLocalProviderControlState({
            providerSelectId: 'setting-local-provider',
            urlInputId: 'setting-local-url',
            modelSelectId: 'setting-local-model-select',
            hintId: 'local-model-hint',
            settings: s
        });

        // Если есть сохранённая локальная модель — пре-наполняем select временной опцией,
        // чтобы пользователь видел текущий выбор без клика на "Загрузить список".
        const localSelect = document.getElementById('setting-local-model-select');
        if (localSelect && s.localModel) {
            const existing = [...localSelect.options].find(o => o.value === s.localModel);
            if (!existing) {
                const opt = document.createElement('option');
                opt.value = s.localModel;
                opt.textContent = s.localModel + ' (сохранённая)';
                localSelect.appendChild(opt);
            }
            localSelect.value = s.localModel;
        }

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
        const timeoutEl = document.getElementById('setting-request-timeout');
        if (timeoutEl) timeoutEl.value = s.requestTimeoutSec ?? 300;
        const ttfbEl = document.getElementById('setting-ttfb-timeout');
        if (ttfbEl) ttfbEl.value = s.ttfbTimeoutSec ?? 120;
        const ttfbLabel = document.getElementById('ttfb-timeout-value');
        if (ttfbLabel && ttfbEl) ttfbLabel.textContent = ttfbEl.value;

        // Privacy: history toggle + TTL.
        const histToggle = document.getElementById('setting-history-enabled');
        if (histToggle) histToggle.checked = s.historyEnabled !== false;
        const histTTL = document.getElementById('setting-history-ttl');
        if (histTTL) {
            histTTL.value = String(s.historyTTLDays ?? 30);
            const v = parseInt(histTTL.value) || 0;
            const ttlLabel = document.getElementById('history-ttl-value');
            if (ttlLabel) ttlLabel.textContent = v === 0 ? 'Никогда' : `${v} дн.`;
        }
        const sessionOnlyEl = document.getElementById('setting-key-session-only');
        if (sessionOnlyEl) sessionOnlyEl.checked = !!s.apiKeySessionOnly;

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

        // Vibecode card
        if (this.vibe) this.vibe.renderSettingsCard();
    }

    saveSettingsFromForm() {
        this.state.settings.cloudApiKey = document.getElementById('setting-api-key').value.trim();
        const checkedRadio = document.querySelector('input[name="deepseek-model"]:checked');
        this.state.settings.cloudModel = checkedRadio ? checkedRadio.value : 'deepseek-chat';
        this.state.settings.cloudUrl = document.getElementById('setting-cloud-url').value.trim() || 'https://api.deepseek.com';
        this.state.settings.localProvider = document.getElementById('setting-local-provider').value || DEFAULT_LOCAL_PROVIDER;
        this.state.settings.localUrl = document.getElementById('setting-local-url').value.trim()
            || LLMService.getLocalProviderConfig(this.state.settings.localProvider).defaultUrl;
        // Не перезаписываем localModel пустым значением: если пользователь открыл настройки
        // без "Загрузить список", select пуст — оставляем сохранённое значение.
        const localModelVal = document.getElementById('setting-local-model-select').value;
        if (localModelVal) {
            this.state.settings.localModel = localModelVal;
        }
        this.state.settings.temperature = parseFloat(document.getElementById('setting-temperature').value) || 0.3;
        this.state.settings.maxTokens = parseInt(document.getElementById('setting-max-tokens').value) || 4096;
        this.state.settings.contextWindow = parseInt(document.getElementById('setting-context-window').value) || 65536;
        const timeoutEl = document.getElementById('setting-request-timeout');
        if (timeoutEl) {
            const t = parseInt(timeoutEl.value);
            this.state.settings.requestTimeoutSec = (isNaN(t) || t < 30) ? 300 : Math.min(t, 1800);
        }
        const ttfbSaveEl = document.getElementById('setting-ttfb-timeout');
        if (ttfbSaveEl) {
            const t = parseInt(ttfbSaveEl.value);
            this.state.settings.ttfbTimeoutSec = (isNaN(t) || t < 10) ? 120 : Math.min(t, 600);
        }
        const histToggleEl = document.getElementById('setting-history-enabled');
        if (histToggleEl) this.state.settings.historyEnabled = !!histToggleEl.checked;
        const histTTLEl = document.getElementById('setting-history-ttl');
        if (histTTLEl) {
            const t = parseInt(histTTLEl.value);
            this.state.settings.historyTTLDays = isNaN(t) ? 30 : Math.max(0, Math.min(t, 365));
        }
        const sessionOnlyEl = document.getElementById('setting-key-session-only');
        if (sessionOnlyEl) this.state.settings.apiKeySessionOnly = !!sessionOnlyEl.checked;
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
        // Save the current provider and URL first
        this.state.settings.localProvider = document.getElementById('setting-local-provider').value || DEFAULT_LOCAL_PROVIDER;
        this.state.settings.localUrl = document.getElementById('setting-local-url').value.trim()
            || LLMService.getLocalProviderConfig(this.state.settings.localProvider).defaultUrl;

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

            // Синхронизация кэша моделей с Vibecode-карточкой —
            // чтобы пользователю не пришлось жать «Обновить» дважды
            if (this.vibe) {
                this.vibe._localModelsCache = { ...this._localModelsCache };
                this.vibe._renderModelDropdowns();
                const vibeHint = document.getElementById('vibe-fetch-hint');
                if (vibeHint) vibeHint.textContent = `найдено: ${models.length}`;
            }

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

        // Auto-set context window from model metadata if available.
        // ВАЖНО: выбираем largest option ≤ contextLength (не closest), чтобы НЕ завысить
        // оценку относительно реального n_ctx сервера. Завышение → pre-flight check
        // пропускает overflow → запрос виснет на сервере.
        const modelData = this._localModelsCache?.[modelName];
        let ctxInfo = '';
        if (modelData?.contextLength) {
            const ctxK = Math.round(modelData.contextLength / 1024);
            ctxInfo = ` | Контекст: ${ctxK}K`;
            const ctxSelect = document.getElementById('setting-context-window');
            const options = [...ctxSelect.options].map(o => parseInt(o.value)).sort((a, b) => a - b);
            const fitOptions = options.filter(v => v <= modelData.contextLength);
            const target = fitOptions.length > 0 ? fitOptions[fitOptions.length - 1] : options[0];
            ctxSelect.value = String(target);
            const ctxVal = parseInt(ctxSelect.value);
            document.getElementById('context-window-value').textContent = ctxVal >= 1024 ? (ctxVal / 1024) + 'K' : ctxVal;
            // Сразу синхронизируем state.settings — иначе pre-flight check в runAnalysis
            // продолжит использовать старое значение до клика "Сохранить настройки".
            this.state.settings.contextWindow = target;
            this.state.saveSettings();
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

        const esc = MarkdownRenderer.escapeHtml;
        tbody.innerHTML = this.state.prompts.map(p => {
            const roleKey = ROLES[p.role] ? p.role : 'developer';
            const role = ROLES[roleKey];
            const promptId = esc(p.id);
            const actionName = esc(p.actionName || '');
            const languageName = p.language ? esc(LANGUAGES[p.language] || p.language) : '';
            const systemPrompt = String(p.systemPrompt || '');
            const contextFile = String(p.contextFile || '');
            return `
                <tr data-prompt-id="${promptId}">
                    <td>
                        <div class="table-role-cell">
                            <div class="table-role-icon ${esc(roleKey)}">
                                <svg class="icon"><use href="#${esc(role.icon)}"/></svg>
                            </div>
                            <div>
                                <div class="table-role-name">${esc(role.name)}</div>
                                <div class="table-role-sub">${esc(role.team)}</div>
                            </div>
                        </div>
                    </td>
                    <td><span class="table-badge ${esc(roleKey)}">${actionName}</span>${p.language ? ` <span class="label-badge">${languageName}</span>` : ''}</td>
                    <td><div class="table-prompt-text" title="${esc(systemPrompt)}">${esc(systemPrompt.substring(0, 150))}...</div></td>
                    <td>${contextFile
                        ? `<span class="table-file-badge"><svg class="icon"><use href="#i-attach"/></svg>${esc(contextFile)}</span>`
                        : '<span style="color:var(--text-muted)">—</span>'
                    }</td>
                    <td>
                        <div class="table-actions">
                            <button class="table-action-btn edit" data-id="${promptId}" title="Редактировать">
                                <svg class="icon"><use href="#i-edit"/></svg>
                            </button>
                            <button class="table-action-btn delete" data-id="${promptId}" title="Удалить">
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

    /* ------ Modal a11y helpers (focus trap, ARIA, Escape) ------ */
    _modalFocusableSelector() {
        return 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    }

    _openModal(overlayId, opts = {}) {
        const overlay = document.getElementById(overlayId);
        if (!overlay) return;
        overlay._previousFocus = document.activeElement;
        overlay.style.display = 'flex';
        overlay.setAttribute('aria-hidden', 'false');

        const focusables = overlay.querySelectorAll(this._modalFocusableSelector());
        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        // Focus first focusable элемент (или явно указанный)
        const initialFocus = opts.initialFocusId ? overlay.querySelector('#' + opts.initialFocusId) : first;
        if (initialFocus) setTimeout(() => initialFocus.focus(), 30);

        // Focus trap через Tab/Shift+Tab.
        overlay._trapHandler = (e) => {
            if (e.key !== 'Tab') return;
            if (focusables.length === 0) { e.preventDefault(); return; }
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        };
        overlay.addEventListener('keydown', overlay._trapHandler);
    }

    _closeModal(overlayId) {
        const overlay = document.getElementById(overlayId);
        if (!overlay) return;
        overlay.style.display = 'none';
        overlay.setAttribute('aria-hidden', 'true');
        if (overlay._trapHandler) {
            overlay.removeEventListener('keydown', overlay._trapHandler);
            overlay._trapHandler = null;
        }
        if (overlay._previousFocus && typeof overlay._previousFocus.focus === 'function') {
            overlay._previousFocus.focus();
            overlay._previousFocus = null;
        }
    }

    /* ------ Prompt Modal ------ */
    bindModals() {
        document.getElementById('btn-modal-close').addEventListener('click', () => this.closePromptModal());
        document.getElementById('btn-modal-cancel').addEventListener('click', () => this.closePromptModal());
        document.getElementById('btn-modal-save').addEventListener('click', () => this.savePromptFromModal());

        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) {
                if (this._hasModalUnsavedChanges()) {
                    if (!confirm('Есть несохранённые изменения. Закрыть без сохранения?')) return;
                }
                this.closePromptModal();
            }
        });

        // Modal context file picker
        document.getElementById('modal-context-file').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const error = Application._validateTextFile(file);
            if (error) {
                Toast.show(error, 'error', 5000);
                e.target.value = '';
                return;
            }
            const reader = new FileReader();
            reader.onload = (ev) => {
                const content = ev.target.result;
                if (Application._isBinaryContent(content)) {
                    Toast.show('Файл содержит бинарные данные', 'error');
                    return;
                }
                this._modalContextFile = file.name;
                this._modalContextContent = content;
                const sizeLabel = Application._formatFileSize(file.size);
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

    _hasModalUnsavedChanges() {
        const action = document.getElementById('modal-action').value.trim();
        const prompt = document.getElementById('modal-prompt').value.trim();
        const language = document.getElementById('modal-language').value;
        if (this.editingPromptId) {
            const orig = this.state.getPromptById(this.editingPromptId);
            if (!orig) return false;
            return orig.actionName !== action || orig.systemPrompt !== prompt
                || orig.role !== document.getElementById('modal-role').value
                || (orig.language || '') !== language
                || (orig.contextFile || '') !== this._modalContextFile;
        }
        return !!(action || prompt || this._modalContextFile);
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
            document.getElementById('modal-language').value = prompt.language || '';
            this._modalContextFile = prompt.contextFile || '';
            this._modalContextContent = prompt.contextContent || '';
        } else {
            title.textContent = 'Новый промпт';
            document.getElementById('modal-role').value = 'infosec';
            document.getElementById('modal-action').value = '';
            document.getElementById('modal-prompt').value = '';
            document.getElementById('modal-language').value = '';
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

        this._openModal('modal-overlay', { initialFocusId: 'modal-action' });
    }

    closePromptModal() {
        this._closeModal('modal-overlay');
        this.editingPromptId = null;
        this._modalContextFile = '';
        this._modalContextContent = '';
    }

    savePromptFromModal() {
        const role = document.getElementById('modal-role').value;
        const actionName = document.getElementById('modal-action').value.trim();
        const systemPrompt = document.getElementById('modal-prompt').value.trim();
        const language = document.getElementById('modal-language').value;

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
                prompt.language = language || '';
                prompt.contextFile = this._modalContextFile;
                prompt.contextContent = this._modalContextContent;
            }
        } else {
            this.state.prompts.push({
                id: 'custom_' + Date.now(),
                role,
                actionName,
                systemPrompt,
                language: language || '',
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

        const esc = MarkdownRenderer.escapeHtml;
        container.innerHTML = this.state.history.map(entry => {
            const roleKey = ROLES[entry.role] ? entry.role : 'developer';
            const role = ROLES[roleKey];
            const date = new Date(entry.timestamp);
            const dateStr = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
            const timeStr = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            const lang = MarkdownRenderer.escapeHtml(LANGUAGES[entry.language] || entry.language || '');
            const action = MarkdownRenderer.escapeHtml(entry.action || '');
            const snippet = entry.codeSnippet ? MarkdownRenderer.escapeHtml(entry.codeSnippet.substring(0, 60) + '...') : '';
            const historyId = MarkdownRenderer.escapeHtml(entry.id);

            return `
                <div class="history-item" data-history-id="${historyId}">
                    <div class="history-item-icon ${esc(roleKey)}">
                        <svg class="icon"><use href="#${esc(role.icon)}"/></svg>
                    </div>
                    <div class="history-item-body">
                        <div class="history-item-title">${esc(role.name)} — ${action}</div>
                        <div class="history-item-meta">
                            <span>${esc(lang)}</span>
                            <span>${esc(dateStr)} ${esc(timeStr)}</span>
                            <span>${esc(snippet)}</span>
                        </div>
                    </div>
                    <div class="history-item-actions">
                        <button class="table-action-btn delete history-delete-btn" data-id="${historyId}" title="Удалить">
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

            const esc = MarkdownRenderer.escapeHtml;
            div.innerHTML = `
                <div class="msg-avatar">${esc(avatarText)}</div>
                <div class="msg-body">
                    <div class="msg-header">
                        <span class="msg-name">${esc(name)}</span>
                        <span class="msg-time">${esc(msg.time || '')}</span>
                        ${copyBtn}
                    </div>
                    <div class="msg-content">${msg.role === 'assistant' ? MarkdownRenderer.render(msg.content) : esc(msg.content)}</div>
                </div>
            `;
            this.bindMsgCopyBtn(div);
            container.appendChild(div);
        });

        this._openModal('history-modal-overlay');
    }

    closeHistoryModal() {
        this._closeModal('history-modal-overlay');
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

        // Восстанавливаем conversationHistory для follow-up. Если в записи нет apiMessages
        // (старая запись из истории до этого фикса) — follow-up отключаем с пояснением.
        const followupInput = document.getElementById('chat-followup');
        const followupBtn = document.getElementById('btn-send-followup');
        const defaultPlaceholder = followupInput.dataset.defaultPlaceholder
            || (followupInput.dataset.defaultPlaceholder = followupInput.placeholder || 'Задайте уточняющий вопрос...');
        if (Array.isArray(entry.apiMessages) && entry.apiMessages.length > 0) {
            this.state.conversationHistory = [...entry.apiMessages];
            followupInput.disabled = false;
            followupBtn.disabled = false;
            followupInput.placeholder = defaultPlaceholder;
            Toast.show('Сессия восстановлена — можно продолжить диалог');
        } else {
            this.state.conversationHistory = [];
            followupInput.disabled = true;
            followupBtn.disabled = true;
            followupInput.placeholder = 'Диалог из старой записи нельзя продолжить. Запустите новый анализ.';
            Toast.show('Сессия восстановлена (только просмотр, без follow-up)', 'warning');
        }

        this.closeHistoryModal();
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
                // Admin auth overlay — проверяем первым
                const adminOverlay = document.getElementById('admin-auth-overlay');
                if (adminOverlay && adminOverlay.style.display !== 'none') {
                    this._closeModal('admin-auth-overlay');
                    const pwInput = document.getElementById('admin-password-input');
                    if (pwInput) pwInput.value = '';
                    const pwErr = document.getElementById('admin-auth-error');
                    if (pwErr) pwErr.style.display = 'none';
                    return;
                }

                // Close modals first
                const promptModal = document.getElementById('modal-overlay');
                if (promptModal && promptModal.style.display !== 'none' && promptModal.style.display !== '') {
                    if (this._hasModalUnsavedChanges()) {
                        if (!confirm('Есть несохранённые изменения. Закрыть без сохранения?')) return;
                    }
                    this.closePromptModal();
                    return;
                }
                const historyModal = document.getElementById('history-modal-overlay');
                if (historyModal && historyModal.style.display !== 'none' && historyModal.style.display !== '') {
                    this.closeHistoryModal();
                    return;
                }
                // Vibecode fallback modal — закрываем через менеджер,
                // чтобы корректно обновилось состояние Run-кнопки.
                const vibeFallback = document.getElementById('vibe-fallback-overlay');
                if (vibeFallback && vibeFallback.style.display !== 'none' && vibeFallback.style.display !== '') {
                    if (this.vibe) {
                        this.vibe._hideFallbackModal();
                    } else {
                        vibeFallback.style.display = 'none';
                    }
                    return;
                }

                // Stop generation
                if (this.state.isGenerating) {
                    this.stopGeneration();
                }
                // Stop vibecode cycle
                if (this.vibe && this.vibe.isRunning) {
                    this.vibe.stop();
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

    /* ------ Copy Code Helper (event delegation) ------ */
    bindCodeCopyDelegation() {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.btn-copy-code');
            if (!btn) return;
            this.copyCode(btn);
        });
    }

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
   ADMIN CONSTANTS
   ВНИМАНИЕ: это UI-gate, не реальная аутентификация. Любой пользователь
   с доступом к DevTools может обойти проверку. Реальная защита возможна
   только при наличии бэкенда. Хешируем пароль, чтобы убрать строку из
   исходника, но это не security boundary.
   ============================================================ */
const ADMIN_PASSWORD_SALT = 'codesentinel/v1/admin-gate/2025';
// SHA-256 хеш от ('admin123' + ADMIN_PASSWORD_SALT). Можно сменить через UI.
const ADMIN_DEFAULT_PASSWORD_HASH = 'd67de7e7a4af627059b8491cda964dbd262ec446c801123de25c48165c211cb3';
const ADMIN_PASSWORD_HASH_KEY = 'codesentinel_admin_pwd_hash';

async function _sha256Hex(input) {
    if (!crypto?.subtle?.digest) {
        // Fallback: без SubtleCrypto не можем хешировать. Возвращаем raw — gate деградирует
        // в plaintext-сравнение, что не хуже исходного варианта.
        return 'plain:' + input;
    }
    const data = new TextEncoder().encode(input);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function _hashAdminPassword(password) {
    return _sha256Hex(password + ADMIN_PASSWORD_SALT);
}

async function _verifyAdminPassword(password) {
    if (typeof password !== 'string' || password.length === 0 || password.length > 200) return false;
    const storedHash = localStorage.getItem(ADMIN_PASSWORD_HASH_KEY);

    // Fallback на старых браузерах без crypto.subtle: разрешаем только дефолтный
    // пароль и только если пользователь не менял его. Иначе — отказываем (безопаснее).
    if (!crypto?.subtle?.digest) {
        if (storedHash) return false;
        return password === 'admin123';
    }

    const expected = storedHash || ADMIN_DEFAULT_PASSWORD_HASH;
    const actual = await _hashAdminPassword(password);
    return actual === expected;
}

const DEFAULT_SUPPORT_SYSTEM_PROMPT = `Ты — виртуальный ассистент первой линии технической поддержки группы УПФЭ. Твоя задача — помочь пользователям разобраться в работе приложения "AI сканер".

## О приложении "AI сканер"

"AI сканер" — корпоративный AI-инструмент для анализа исходного кода, функциональных спецификаций (ФС) и технических заданий (ТЗ). Работает полностью автономно, без внешних зависимостей — достаточно открыть файл в браузере. Поддерживает работу в закрытых сетях (КСПД).

## Возможности системы

**Поддерживаемые языки:** ABAP, 1С, Python, JavaScript

**Три роли анализа:**
- **Информационная безопасность (ИБ)** — анализ уязвимостей по OWASP Top 10, аудит безопасности, поиск CWE-уязвимостей. Для ABAP: проверки AUTHORITY-CHECK, SQL-инъекции. Для 1С: привилегированный режим, внешние обработки.
- **Консультант** — объяснение логики кода бизнес-пользователям, генерация ТЗ на доработку, ТЗ с нуля по ГОСТ/IEEE.
- **Разработчик** — рефакторинг (SOLID, DRY, KISS), оценка качества кода по шкале 1-5, анализ производительности и узких мест.

**Типы подключения к AI:**
- Облачный API DeepSeek (deepseek-chat, deepseek-reasoner) — требует API-ключ
- Локальные модели (LM Studio / Ollama / Xinference) — данные не покидают инфраструктуру

## Как начать работу

1. Перейти в раздел **"Анализ кода"** (первый пункт меню)
2. Выбрать **роль** (ИБ / Консультант / Разработчик)
3. Выбрать **язык программирования** (ABAP, 1С, Python, JavaScript)
4. Нажать на **кнопку действия** (тип анализа)
5. Вставить исходный код или текст ТЗ в поле
6. Нажать **"Анализировать"** или **Ctrl+Enter**
7. Задавать уточняющие вопросы в поле ввода внизу чата

## Настройка подключения

**Для облака (DeepSeek):**
- Перейти в Настройки → указать API-ключ DeepSeek (sk-...)
- Ключ получить на сайте deepseek.com в личном кабинете
- Нажать "Проверить подключение"

**Для локальных моделей:**
- Выбрать тип локального API: LM Studio, Ollama или Xinference
- Указать фактический адрес API-сервера (LM Studio: http://localhost:1234, Ollama: http://localhost:11434, Xinference: http://127.0.0.1:9997 или корпоративный адрес)
- Нажать "Загрузить список" для автообнаружения моделей
- Выбрать модель из списка

## Экономические эффекты

- Ускорение код-ревью в **5-10 раз** (часы → минуты)
- Снижение стоимости ИБ-аудита на **70%**
- Подготовка ТЗ в **2-3 раза** быстрее
- Рост качества кода на **40%** за счёт регулярной обратной связи

## Промпты и настройка

В разделе **"Настройки" → "Матрица промптов"** можно:
- Редактировать системные промпты для каждой роли
- Добавлять новые действия и промпты
- Прикреплять файлы инструкций (.txt, .md) к промптам

## Файлы контекста

Можно прикрепить файл (.txt, .md, до 500 КБ) как контекст к запросу — например, стандарты кодирования, нормативы безопасности или регламенты компании.

## Важное

Для сложных вопросов по **расширению функционала приложения**, доработке или организационным вопросам — обращаться к **Мартьянову Николаю из УПФЭ**.

## Стиль общения

- Всегда отвечай дружелюбно, профессионально и по существу
- Давай конкретные пошаговые инструкции
- Если вопрос выходит за рамки поддержки приложения — вежливо перенаправь к Мартьянову Николаю
- Отвечай только на русском языке`;

const DEFAULT_SUPPORT_WELCOME = `Добро пожаловать! 👋 Я — ассистент первой линии группы поддержки УПФЭ.

Помогу разобраться с приложением **AI сканер**: как начать работу, как настроить подключение к AI-модели, какие возможности есть и какие эффекты это приносит.

Чем могу помочь?`;

/* ============================================================
   ADMIN MANAGER
   ============================================================ */
class AdminManager {
    constructor(app) {
        this.app = app;
        this.isAuthenticated = false;
        this.settings = this._loadSettings();
        this._localModelsCache = {};
        // AdminManager имеет .settings нужной формы (mode/cloud*/local*/temperature/maxTokens/
        // requestTimeoutSec), поэтому может быть передан в LLMService как state-like контекст.
        // requestTimeoutSec на admin-settings нет — используем default 90 сек для поддержки
        // через виртуальное поле.
        if (this.settings.requestTimeoutSec === undefined) this.settings.requestTimeoutSec = 90;
        this.llm = new LLMService(this);
    }

    _loadSettings() {
        const defaults = {
            mode: 'cloud',
            cloudApiKey: '',
            cloudModel: 'deepseek-chat',
            cloudUrl: 'https://api.deepseek.com',
            localProvider: DEFAULT_LOCAL_PROVIDER,
            localUrl: DEFAULT_LOCAL_URL,
            localModel: '',
            temperature: 0.2,
            maxTokens: 768,
            contextWindow: 4096,
            systemPrompt: DEFAULT_SUPPORT_SYSTEM_PROMPT,
            welcomeMessage: DEFAULT_SUPPORT_WELCOME
        };
        const parsed = Schema.safeParse(
            localStorage.getItem('codesentinel_admin_settings'),
            (p) => {
                if (!p || typeof p !== 'object') return null;
                const localUrl = Schema.string(p.localUrl, defaults.localUrl, 500);
                return {
                    mode: Schema.oneOf(p.mode, ['cloud', 'local'], defaults.mode),
                    cloudApiKey: Schema.string(p.cloudApiKey, defaults.cloudApiKey, 500),
                    cloudModel: Schema.string(p.cloudModel, defaults.cloudModel, 100),
                    cloudUrl: Schema.string(p.cloudUrl, defaults.cloudUrl, 500),
                    localProvider: Schema.oneOf(
                        p.localProvider,
                        Object.keys(LOCAL_PROVIDER_CONFIG),
                        LLMService.inferLocalProviderFromUrl(localUrl)
                    ),
                    localUrl,
                    localModel: Schema.string(p.localModel, defaults.localModel, 200),
                    temperature: Schema.number(p.temperature, defaults.temperature, { min: 0, max: 2 }),
                    maxTokens: Schema.integer(p.maxTokens, defaults.maxTokens, { min: 64, max: 16384 }),
                    contextWindow: Schema.integer(p.contextWindow, defaults.contextWindow, { min: 1024, max: 1048576 }),
                    requestTimeoutSec: Schema.integer(p.requestTimeoutSec, 90, { min: 30, max: 1800 }),
                    ttfbTimeoutSec: Schema.integer(p.ttfbTimeoutSec, 60, { min: 10, max: 600 }),
                    systemPrompt: Schema.string(p.systemPrompt, defaults.systemPrompt, 200000),
                    welcomeMessage: Schema.string(p.welcomeMessage, defaults.welcomeMessage, 50000),
                    apiKeySessionOnly: Schema.boolean(p.apiKeySessionOnly, false)
                };
            },
            null
        );
        return parsed || defaults;
    }

    saveSettings() {
        // session-only режим: ключ остаётся только в RAM, не пишется на диск.
        if (this.settings.apiKeySessionOnly) {
            const sanitized = { ...this.settings, cloudApiKey: '' };
            localStorage.setItem('codesentinel_admin_settings', JSON.stringify(sanitized));
        } else {
            localStorage.setItem('codesentinel_admin_settings', JSON.stringify(this.settings));
        }
    }

    init() {
        this._bindPasswordModal();
        this._bindAdminPage();
        this._bindTogglePasswordBtns();
    }

    _bindPasswordModal() {
        const overlay = document.getElementById('admin-auth-overlay');
        const submitBtn = document.getElementById('admin-auth-submit');
        const cancelBtn = document.getElementById('admin-auth-cancel');
        const input = document.getElementById('admin-password-input');
        const errorEl = document.getElementById('admin-auth-error');

        const closeAuth = () => {
            this.app._closeModal('admin-auth-overlay');
            input.value = '';
            errorEl.style.display = 'none';
        };

        const submit = async () => {
            const val = input.value;
            // Защита от двойного клика во время async-проверки.
            if (submitBtn.disabled) return;
            submitBtn.disabled = true;
            try {
                const ok = await _verifyAdminPassword(val);
                if (ok) {
                    this.isAuthenticated = true;
                    closeAuth();
                    this.app.navigateTo('admin');
                } else {
                    errorEl.style.display = 'flex';
                    input.value = '';
                    input.focus();
                }
            } finally {
                submitBtn.disabled = false;
            }
        };

        submitBtn.addEventListener('click', submit);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

        cancelBtn.addEventListener('click', closeAuth);

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeAuth();
        });
    }

    showPasswordModal() {
        this.app._openModal('admin-auth-overlay', { initialFocusId: 'admin-password-input' });
    }

    _renderForm() {
        const s = this.settings;

        // Mode
        document.querySelectorAll('#admin-env-toggle .toggle-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.mode === s.mode);
        });
        this._applyModeUI(s.mode);

        // Cloud
        document.getElementById('admin-api-key').value = s.cloudApiKey || '';
        const adminSessionOnly = document.getElementById('admin-key-session-only');
        if (adminSessionOnly) adminSessionOnly.checked = !!s.apiKeySessionOnly;
        document.getElementById('admin-cloud-url').value = s.cloudUrl || 'https://api.deepseek.com';
        document.querySelectorAll('input[name="admin-deepseek-model"]').forEach(r => {
            r.checked = r.value === (s.cloudModel || 'deepseek-chat');
            r.closest('.model-card').classList.toggle('active', r.checked);
        });

        // Local
        document.getElementById('admin-local-provider').value = s.localProvider || LLMService.inferLocalProviderFromUrl(s.localUrl);
        document.getElementById('admin-local-url').value = s.localUrl || LLMService.getLocalProviderConfig(s.localProvider).defaultUrl;
        this.app._setLocalProviderControlState({
            providerSelectId: 'admin-local-provider',
            urlInputId: 'admin-local-url',
            modelSelectId: 'admin-local-model-select',
            hintId: 'admin-local-model-hint',
            settings: s
        });
        const select = document.getElementById('admin-local-model-select');
        if (s.localModel) {
            const existing = select.querySelector(`option[value="${CSS.escape(s.localModel)}"]`);
            if (!existing) {
                const opt = document.createElement('option');
                opt.value = s.localModel;
                opt.textContent = s.localModel + ' (сохранённая)';
                select.appendChild(opt);
            }
            select.value = s.localModel;
        }

        // Generation params
        const tempSlider = document.getElementById('admin-temperature');
        const tokensSlider = document.getElementById('admin-max-tokens');
        const ctxSelect = document.getElementById('admin-context-window');
        tempSlider.value = s.temperature ?? 0.2;
        tokensSlider.value = s.maxTokens ?? 768;
        ctxSelect.value = s.contextWindow ?? 4096;
        document.getElementById('admin-temperature-value').textContent = tempSlider.value;
        document.getElementById('admin-max-tokens-value').textContent = tokensSlider.value;
        const ctxVal = parseInt(ctxSelect.value);
        document.getElementById('admin-context-window-value').textContent = ctxVal >= 1024 ? (ctxVal / 1024) + 'K' : ctxVal;

        // Prompts
        document.getElementById('admin-system-prompt').value = s.systemPrompt || DEFAULT_SUPPORT_SYSTEM_PROMPT;
        document.getElementById('admin-welcome-message').value = s.welcomeMessage || DEFAULT_SUPPORT_WELCOME;
    }

    _applyModeUI(mode) {
        const cloudSettings = document.getElementById('admin-cloud-settings');
        const localSettings = document.getElementById('admin-local-settings');
        const badge = document.getElementById('admin-local-badge');

        if (mode === 'cloud') {
            cloudSettings.classList.remove('disabled');
            localSettings.classList.add('disabled');
            if (badge) badge.textContent = 'Отключено';
        } else {
            localSettings.classList.remove('disabled');
            cloudSettings.classList.add('disabled');
            if (badge) badge.textContent = 'Активно';
        }
    }

    _saveFromForm() {
        this.settings.mode = document.querySelector('#admin-env-toggle .toggle-btn.active')?.dataset.mode || 'cloud';
        this.settings.cloudApiKey = document.getElementById('admin-api-key').value.trim();
        this.settings.cloudUrl = document.getElementById('admin-cloud-url').value.trim() || 'https://api.deepseek.com';
        const checkedRadio = document.querySelector('input[name="admin-deepseek-model"]:checked');
        this.settings.cloudModel = checkedRadio ? checkedRadio.value : 'deepseek-chat';
        this.settings.localProvider = document.getElementById('admin-local-provider').value || DEFAULT_LOCAL_PROVIDER;
        this.settings.localUrl = document.getElementById('admin-local-url').value.trim()
            || LLMService.getLocalProviderConfig(this.settings.localProvider).defaultUrl;
        // Не затираем сохранённую модель пустым select (если "Загрузить список" не нажат).
        const adminLocalModelVal = document.getElementById('admin-local-model-select').value;
        if (adminLocalModelVal) {
            this.settings.localModel = adminLocalModelVal;
        }
        const tempRaw = parseFloat(document.getElementById('admin-temperature').value);
        this.settings.temperature = isNaN(tempRaw) ? 0.2 : tempRaw;
        const tokensRaw = parseInt(document.getElementById('admin-max-tokens').value);
        this.settings.maxTokens = isNaN(tokensRaw) ? 768 : tokensRaw;
        const ctxRaw = parseInt(document.getElementById('admin-context-window').value);
        this.settings.contextWindow = isNaN(ctxRaw) ? 4096 : ctxRaw;
        this.settings.systemPrompt = document.getElementById('admin-system-prompt').value.trim() || DEFAULT_SUPPORT_SYSTEM_PROMPT;
        this.settings.welcomeMessage = document.getElementById('admin-welcome-message').value.trim() || DEFAULT_SUPPORT_WELCOME;
        const adminSessionOnlyEl = document.getElementById('admin-key-session-only');
        if (adminSessionOnlyEl) this.settings.apiKeySessionOnly = !!adminSessionOnlyEl.checked;
        this.saveSettings();
    }

    _bindAdminPage() {
        // Env toggle
        document.getElementById('admin-env-toggle').addEventListener('click', (e) => {
            const btn = e.target.closest('.toggle-btn');
            if (!btn) return;
            const mode = btn.dataset.mode;
            document.querySelectorAll('#admin-env-toggle .toggle-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            this.settings.mode = mode;
            this._applyModeUI(mode);
        });

        // Model cards
        document.querySelectorAll('input[name="admin-deepseek-model"]').forEach(radio => {
            radio.addEventListener('change', () => {
                document.querySelectorAll('.model-card').forEach(c => {
                    if (c.querySelector('input[name="admin-deepseek-model"]')) c.classList.remove('active');
                });
                if (radio.checked) radio.closest('.model-card').classList.add('active');
            });
        });

        // Range sliders
        document.getElementById('admin-temperature').addEventListener('input', (e) => {
            document.getElementById('admin-temperature-value').textContent = e.target.value;
        });
        document.getElementById('admin-max-tokens').addEventListener('input', (e) => {
            document.getElementById('admin-max-tokens-value').textContent = e.target.value;
        });
        document.getElementById('admin-context-window').addEventListener('change', (e) => {
            const val = parseInt(e.target.value);
            document.getElementById('admin-context-window-value').textContent = val >= 1024 ? (val / 1024) + 'K' : val;
        });

        // Save
        document.getElementById('admin-btn-save').addEventListener('click', () => {
            this._saveFromForm();
            Toast.show('Настройки администратора сохранены');
        });

        // Reset prompt
        document.getElementById('admin-btn-reset-prompt').addEventListener('click', () => {
            if (!confirm('Сбросить системный промпт к значению по умолчанию?')) return;
            document.getElementById('admin-system-prompt').value = DEFAULT_SUPPORT_SYSTEM_PROMPT;
            document.getElementById('admin-welcome-message').value = DEFAULT_SUPPORT_WELCOME;
            Toast.show('Промпт сброшен к значению по умолчанию');
        });

        // Admin password change.
        const pwResultEl = document.getElementById('admin-pwd-result');
        const showPwResult = (text, isError = false) => {
            if (!pwResultEl) return;
            pwResultEl.textContent = text;
            pwResultEl.className = 'connection-result ' + (isError ? 'error' : 'success');
        };
        const pwChangeBtn = document.getElementById('admin-pwd-change');
        if (pwChangeBtn) {
            pwChangeBtn.addEventListener('click', async () => {
                const cur = document.getElementById('admin-pwd-current').value;
                const fresh = document.getElementById('admin-pwd-new').value;
                const conf = document.getElementById('admin-pwd-confirm').value;
                if (fresh.length < 4) {
                    showPwResult('Новый пароль должен быть не короче 4 символов', true);
                    return;
                }
                if (fresh !== conf) {
                    showPwResult('Подтверждение не совпадает с новым паролем', true);
                    return;
                }
                pwChangeBtn.disabled = true;
                try {
                    const ok = await _verifyAdminPassword(cur);
                    if (!ok) {
                        showPwResult('Неверный текущий пароль', true);
                        return;
                    }
                    const hash = await _hashAdminPassword(fresh);
                    localStorage.setItem(ADMIN_PASSWORD_HASH_KEY, hash);
                    document.getElementById('admin-pwd-current').value = '';
                    document.getElementById('admin-pwd-new').value = '';
                    document.getElementById('admin-pwd-confirm').value = '';
                    showPwResult('Пароль изменён', false);
                    Toast.show('Пароль администратора изменён');
                } finally {
                    pwChangeBtn.disabled = false;
                }
            });
        }
        const pwResetBtn = document.getElementById('admin-pwd-reset');
        if (pwResetBtn) {
            pwResetBtn.addEventListener('click', () => {
                if (!confirm('Сбросить пароль администратора к заводскому значению?')) return;
                localStorage.removeItem(ADMIN_PASSWORD_HASH_KEY);
                showPwResult('Пароль сброшен. Обратитесь к ответственному за установку для получения заводского пароля.', false);
                Toast.show('Пароль сброшен к заводскому');
            });
        }

        // Fetch local models
        document.getElementById('admin-btn-fetch-models').addEventListener('click', () => {
            this._fetchLocalModels();
        });

        document.getElementById('admin-local-provider').addEventListener('change', () => {
            this.app._setLocalProviderControlState({
                providerSelectId: 'admin-local-provider',
                urlInputId: 'admin-local-url',
                modelSelectId: 'admin-local-model-select',
                hintId: 'admin-local-model-hint',
                settings: this.settings,
                replaceDefaultUrl: true
            });
        });

        // Test connection
        document.getElementById('admin-btn-test-connection').addEventListener('click', () => {
            this._testConnection();
        });
    }

    _bindTogglePasswordBtns() {
        // Toggle password for admin-password-input (in modal) is already handled globally
        // Admin API key toggle is handled in the main app's toggle-password binding
        // but only covers elements in the DOM at init time — we need to also handle admin-api-key
        const btn = document.querySelector('.toggle-password[data-target="admin-api-key"]');
        if (btn) {
            btn.addEventListener('click', () => {
                const input = document.getElementById('admin-api-key');
                const icon = btn.querySelector('use');
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.setAttribute('href', '#i-eye');
                } else {
                    input.type = 'password';
                    icon.setAttribute('href', '#i-eye-off');
                }
            });
        }
        // admin-password-input toggle
        const authToggle = document.querySelector('.toggle-password[data-target="admin-password-input"]');
        if (authToggle) {
            authToggle.addEventListener('click', () => {
                const input = document.getElementById('admin-password-input');
                const icon = authToggle.querySelector('use');
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.setAttribute('href', '#i-eye');
                } else {
                    input.type = 'password';
                    icon.setAttribute('href', '#i-eye-off');
                }
            });
        }
    }

    async _testConnection() {
        this._saveFromForm();
        const btn = document.getElementById('admin-btn-test-connection');
        const result = document.getElementById('admin-test-connection-result');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Проверка...';
        btn.disabled = true;
        result.textContent = '';
        result.className = 'connection-result';

        try {
            const config = this.llm.getEndpointConfig();
            const headers = { 'Content-Type': 'application/json' };
            if (config.apiKey) headers['Authorization'] = `Bearer ${config.apiKey}`;

            const response = await fetch(config.url, {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    model: config.model,
                    messages: [{ role: 'user', content: 'Hello' }],
                    max_tokens: 5,
                    stream: false
                }),
                signal: LLMService._createTimeoutSignal(10000)
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            const json = await response.json();
            const modelName = json.model || config.model;

            result.className = 'connection-result success';
            result.textContent = `Подключено! Модель: ${modelName}`;
            Toast.show(`Подключение успешно! Модель: ${modelName}`);

            // Update status badge
            const statusBadge = document.getElementById('admin-api-status');
            if (statusBadge) {
                statusBadge.className = 'status-badge online';
                statusBadge.querySelector('span:last-child').textContent = 'Подключено';
            }
        } catch (err) {
            result.className = 'connection-result error';
            result.textContent = `Ошибка: ${err.message}`;
            Toast.show(`Ошибка подключения: ${err.message}`, 'error', 6000);
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }
    }

    async _fetchLocalModels() {
        this.settings.localProvider = document.getElementById('admin-local-provider').value || DEFAULT_LOCAL_PROVIDER;
        this.settings.localUrl = document.getElementById('admin-local-url').value.trim()
            || LLMService.getLocalProviderConfig(this.settings.localProvider).defaultUrl;
        const btn = document.getElementById('admin-btn-fetch-models');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span>';
        btn.disabled = true;
        const select = document.getElementById('admin-local-model-select');
        const hint = document.getElementById('admin-local-model-hint');

        try {
            const models = await this._fetchLocalModelsFromConfiguredProvider();

            select.innerHTML = `<option value="">-- Выберите модель (${models.length}) --</option>`;
            models.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m.id;
                opt.textContent = m.name;
                select.appendChild(opt);
            });
            hint.textContent = `(найдено: ${models.length})`;
            if (this.settings.localModel) select.value = this.settings.localModel;
            Toast.show(`Найдено моделей: ${models.length}`);
        } catch (err) {
            select.innerHTML = '<option value="">Ошибка загрузки</option>';
            hint.textContent = '';
            Toast.show(`Не удалось загрузить модели: ${err.message}`, 'error', 5000);
        } finally {
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }
    }

    async _fetchLocalModelsFromConfiguredProvider() {
        const provider = this.settings.localProvider || LLMService.inferLocalProviderFromUrl(this.settings.localUrl);
        const config = LLMService.getLocalProviderConfig(provider);
        let lastError = null;

        for (const url of LLMService.buildLocalModelListUrls(this.settings)) {
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    signal: LLMService._createTimeoutSignal(10000)
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const json = await response.json();
                return LLMService.parseLocalModels(json, provider);
            } catch (err) {
                lastError = err;
            }
        }

        throw new Error(`${config.label}: ${lastError?.message || 'не удалось получить список моделей'}`);
    }

    // callSupportLLM удалён — SupportChat теперь использует this.admin.llm.callLLM напрямую
    // (тот же путь, что и основной анализ: TTFB+idle таймауты, DoS-лимиты, парсинг overflow-ошибок).
}

/* ============================================================
   SUPPORT CHAT
   ============================================================ */
class SupportChat {
    constructor(adminManager) {
        this.admin = adminManager;
        this.messages = []; // { role, content }
        this.isOpen = false;
        this.isGenerating = false;
        this.abortController = null;
        this._welcomeShown = false;
        this.init();
    }

    init() {
        const toggleBtn = document.getElementById('support-chat-toggle');
        const closeBtn = document.getElementById('support-chat-close');
        const sendBtn = document.getElementById('support-chat-send');
        const input = document.getElementById('support-chat-input');

        toggleBtn.addEventListener('click', () => this.toggle());
        closeBtn.addEventListener('click', () => this.close());
        sendBtn.addEventListener('click', () => {
            if (this.isGenerating) {
                this.abortController?.abort();
            } else {
                this.send();
            }
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (!this.isGenerating) this.send();
            }
        });
    }

    toggle() {
        if (this.isOpen) {
            this.close();
        } else {
            this.open();
        }
    }

    open() {
        this.isOpen = true;
        document.getElementById('support-chat-popup').style.display = 'flex';
        document.getElementById('support-chat-unread').style.display = 'none';

        if (!this._welcomeShown) {
            this._welcomeShown = true;
            this._showWelcome();
        }

        setTimeout(() => document.getElementById('support-chat-input').focus(), 100);
    }

    close() {
        this.isOpen = false;
        document.getElementById('support-chat-popup').style.display = 'none';
    }

    _showWelcome() {
        const welcomeMsg = this.admin.settings.welcomeMessage || DEFAULT_SUPPORT_WELCOME;
        this._appendMessage('assistant', welcomeMsg);
        this.messages.push({ role: 'assistant', content: welcomeMsg });
    }

    _isConfigured() {
        const s = this.admin.settings;
        if (s.mode === 'cloud') return !!s.cloudApiKey;
        return !!(s.localUrl && s.localModel);
    }

    _appendMessage(role, content) {
        const container = document.getElementById('support-chat-messages');
        const div = document.createElement('div');
        div.className = `support-msg ${role}`;

        const avatarText = role === 'user' ? 'Вы' : 'УП';
        const bubble = document.createElement('div');
        bubble.className = 'support-msg-bubble';

        if (role === 'assistant') {
            bubble.innerHTML = this._renderSimpleMarkdown(content);
        } else {
            bubble.textContent = content;
        }

        const avatar = document.createElement('div');
        avatar.className = 'support-msg-avatar';
        avatar.textContent = avatarText;

        div.appendChild(avatar);
        div.appendChild(bubble);
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return { div, bubble };
    }

    _renderSimpleMarkdown(text) {
        if (!text) return '';
        let html = MarkdownRenderer.escapeHtml(text);
        // Bold
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        // Italic
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        // Unordered list items
        html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>[\s\S]+?<\/li>\n?)+/g, '<ul>$&</ul>');
        // Paragraphs (double newline = paragraph)
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');
        return '<p>' + html + '</p>';
    }

    async send() {
        if (this.isGenerating) return;

        const input = document.getElementById('support-chat-input');
        const text = input.value.trim();
        if (!text) return;
        input.value = '';

        if (!this._isConfigured()) {
            this._appendMessage('assistant', '⚠️ Чат поддержки не настроен. Обратитесь к администратору (Мартьянов Николай, УПФЭ) для настройки AI-подключения.');
            return;
        }

        // Add user message to UI and history
        this._appendMessage('user', text);
        this.messages.push({ role: 'user', content: text });

        // Trim history: не более 20 сообщений (10 пар) чтобы не переполнить context window
        const MAX_CHAT_HISTORY = 20;
        if (this.messages.length > MAX_CHAT_HISTORY) {
            // Сохраняем первый assistant-msg (приветствие) + последние N-1 сообщений
            this.messages = this.messages.slice(-MAX_CHAT_HISTORY);
        }

        // Prepare messages for API
        const apiMessages = [
            { role: 'system', content: this.admin.settings.systemPrompt || DEFAULT_SUPPORT_SYSTEM_PROMPT },
            ...this.messages
        ];

        // UI: typing indicator, кнопка → стоп
        document.getElementById('support-chat-typing').style.display = 'flex';
        const sendBtn = document.getElementById('support-chat-send');
        sendBtn.innerHTML = '<svg class="icon"><use href="#i-stop"/></svg>';
        sendBtn.title = 'Остановить';
        this.isGenerating = true;

        this.abortController = new AbortController();
        // Таймауты TTFB/idle живут внутри admin.llm.callLLM (requestTimeoutSec=90 в AdminManager).
        // Никаких ручных setTimeout-обёрток не нужно.

        try {
            const container = document.getElementById('support-chat-messages');
            const streamDiv = document.createElement('div');
            streamDiv.className = 'support-msg assistant';
            const streamAvatar = document.createElement('div');
            streamAvatar.className = 'support-msg-avatar';
            streamAvatar.textContent = 'УП';
            const streamBubble = document.createElement('div');
            streamBubble.className = 'support-msg-bubble';
            streamDiv.appendChild(streamAvatar);
            streamDiv.appendChild(streamBubble);

            let firstChunk = false;

            const result = await this.admin.llm.callLLM(
                apiMessages,
                ({ fullContent }) => {
                    if (!firstChunk) {
                        firstChunk = true;
                        document.getElementById('support-chat-typing').style.display = 'none';
                        container.appendChild(streamDiv);
                    }
                    streamBubble.innerHTML = this._renderSimpleMarkdown(fullContent);
                    container.scrollTop = container.scrollHeight;
                },
                this.abortController.signal
            );

            if (!firstChunk) {
                document.getElementById('support-chat-typing').style.display = 'none';
            }

            this.messages.push({ role: 'assistant', content: result.content });

            // Показать бейдж если попап закрыт
            if (!this.isOpen) {
                document.getElementById('support-chat-unread').style.display = 'flex';
            }

        } catch (err) {
            document.getElementById('support-chat-typing').style.display = 'none';
            if (err.name === 'AbortError') {
                // Убираем user-сообщение из истории — оно не получило ответа
                if (this.messages.length && this.messages[this.messages.length - 1].role === 'user') {
                    this.messages.pop();
                }
            } else {
                this._appendMessage('assistant', `Ошибка: ${err.message}. Проверьте настройки в разделе Администратор.`);
            }
        } finally {
            this.isGenerating = false;
            this.abortController = null;
            sendBtn.innerHTML = '<svg class="icon"><use href="#i-send"/></svg>';
            sendBtn.title = 'Отправить';
        }
    }
}

/* ============================================================
   INITIALIZE
   ============================================================ */
let App;
document.addEventListener('DOMContentLoaded', () => {
    App = new Application();

    // Init Admin Manager
    const adminManager = new AdminManager(App);
    adminManager.init();
    App.adminManager = adminManager;

    // Intercept admin nav click to require password
    const adminNavItem = document.querySelector('.nav-item[data-page="admin"]');
    if (adminNavItem) {
        // Remove the generic navigation listener for admin
        const origNavigateTo = App.navigateTo.bind(App);
        App.navigateTo = function(page) {
            if (page === 'admin') {
                if (adminManager.isAuthenticated) {
                    origNavigateTo('admin');
                    adminManager._renderForm();
                } else {
                    adminManager.showPasswordModal();
                }
                return;
            }
            origNavigateTo(page);
        };
    }

    // Init Support Chat
    const supportChat = new SupportChat(adminManager);
    App.supportChat = supportChat;

    // Expose globally
    window.App = App;
});
