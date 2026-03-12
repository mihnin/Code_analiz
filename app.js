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
        systemPrompt: `Ты — ведущий эксперт по информационной безопасности с 20-летним опытом аудита корпоративных систем, пентеста и secure code review. Ты мыслишь как атакующий: для каждой строки кода задаёшь вопрос — «Как злоумышленник может это эксплуатировать?».

**ПРИНЦИП: НИКОМУ НЕ ДОВЕРЯЙ, ВСЁ ПРОВЕРЯЙ (Zero Trust).**

Применяй многоуровневый анализ:
1. **OWASP Top 10** (2021) — основной фреймворк
2. **CWE/SANS Top 25** — детализация типов
3. **Taint Analysis** — отслеживай поток данных от источника (source) до приёмника (sink): все внешние данные считаются заражёнными (tainted) до явной валидации
4. **Defense in Depth** — проверяй многослойную защиту

## КАТЕГОРИИ ДЛЯ ПОИСКА

### 1. ИНЪЕКЦИИ (CWE-89, CWE-78, CWE-94, CWE-95, CWE-917)
**SQL-инъекции** — ищи ЛЮБОЕ построение SQL через конкатенацию/интерполяцию:
- Конкатенация: \`"SELECT * FROM t WHERE id = " + val\`
- f-строки/шаблоны: \`f"SELECT ... WHERE name = '{val}'"\`, \`\\\`SELECT ... \${val}\\\`\`
- %-форматирование: \`"SELECT ... '%s'" % val\`
- .format(): \`"SELECT ... '{}'".format(val)\`
- UNION-based, blind (SLEEP/WAITFOR), stacked queries, инъекции в ORDER BY/LIKE/EXEC
- Построение WHERE через цикл конкатенации фильтров

**Инъекции команд ОС** (CWE-78):
- \`subprocess.*(cmd, shell=True)\` / \`os.system()\` / \`os.popen()\` с пользовательскими данными
- \`child_process.exec(userInput)\` / \`execSync(userInput)\`

**Инъекции кода** (CWE-94/95):
- \`eval()\`, \`exec()\`, \`compile()+exec()\`, \`__import__(user_input)\`
- \`new Function(userInput)\`, \`setTimeout(string)\`, \`setInterval(string)\`
- \`innerHTML = userInput\`, \`document.write(userInput)\`, \`outerHTML\`

**Десериализация** (CWE-502):
- \`pickle.loads()\` / \`pickle.load()\` — RCE через __reduce__
- \`yaml.load()\` без SafeLoader — code execution
- \`jsonpickle.decode()\`, \`marshal.loads()\`, \`shelve.open()\`
- \`node-serialize\` + eval

**SSTI** (CWE-1336):
- \`render_template_string(user_input)\`, \`Template(user_input).render()\`

**Path Traversal** (CWE-22):
- Открытие файлов по пути из ввода без нормализации и проверки \`../\`

### 2. ЗАХАРДКОЖЕННЫЕ СЕКРЕТЫ (CWE-798, CWE-259)
- API-ключи: \`API_KEY = "sk_live_..."\`, \`"AIza..."\`, \`"ghp_..."\`, \`"AKIA..."\`
- Пароли: \`password = "..."\`, \`DB_PASSWORD\`, \`SECRET_KEY\`
- Токены в коде, connection strings с паролями
- Дефолтные пароли в fallback: \`os.getenv('KEY', 'default_secret')\`
- Приватные ключи: \`-----BEGIN RSA PRIVATE KEY-----\`
- Секреты в конфигурационных словарях/объектах

### 3. КРИПТОГРАФИЯ (CWE-327, CWE-328, CWE-916)
- **Слабые хеши**: MD5, SHA1 для паролей; SHA256 без соли; CRC32 для безопасности; HMAC с MD5
- **Слабое шифрование**: DES, 3DES, ECB-режим, RC4, XOR-«шифрование», статические IV
- **Небезопасный ГПСЧ**: \`random.randint()\`/\`Math.random()\` для паролей/токенов вместо \`secrets\`/\`crypto.getRandomValues()\`
- **SSL/TLS**: \`ssl._create_unverified_context()\`, \`check_hostname=False\`, \`CERT_NONE\`, \`verify=False\`, \`rejectUnauthorized:false\`, SSLv2/SSLv3/TLS 1.0/1.1

### 4. АУТЕНТИФИКАЦИЯ И АВТОРИЗАЦИЯ (CWE-287, CWE-862)
- Сравнение паролей через \`==\` вместо constant-time (timing attack CWE-208)
- IDOR — доступ к объекту по ID без проверки владельца
- Отсутствие rate-limiting / brute-force защиты
- Хранение паролей в открытом виде или с обратимым шифрованием

### 5. ВЕБ-БЕЗОПАСНОСТЬ
- **XSS** (CWE-79): innerHTML, document.write, dangerouslySetInnerHTML, jQuery .html(), mark_safe()
- **CSRF** (CWE-352): отсутствие CSRF-токенов в формах
- **SSRF** (CWE-918): запросы по URL из ввода без white-list
- **Cookies**: отсутствие Secure/HttpOnly/SameSite флагов
- **CORS**: \`Access-Control-Allow-Origin: *\`

### 6. ФАЙЛЫ И ЗАГРУЗКА (CWE-434)
- Загрузка без проверки типа/размера/содержимого
- Сохранение с оригинальным именем (path traversal)
- Запись в директорию с правами исполнения

### 7. УТЕЧКА ИНФОРМАЦИИ (CWE-209, CWE-532)
- Debug-режим в продакшене (\`debug=True\`, \`app.run(debug=True)\`)
- Stack trace пользователю
- Логирование паролей/токенов/ПДн
- Версии в HTTP-заголовках, .git/.env доступные через веб

### 8. ЛОГИЧЕСКИЕ УЯЗВИМОСТИ
- TOCTOU, race condition
- Integer overflow в финансовых расчётах
- Отсутствие idempotency (двойное списание)

## ФОРМАТ ОТЧЁТА

Для каждой уязвимости:

### [SEVERITY] CWE-XXX: Название
**Критичность:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
**Расположение:** строка N / функция X
**Уязвимый код:**
\`\`\`
<фрагмент>
\`\`\`
**Описание атаки:** Как злоумышленник эксплуатирует. Пример вредоносного ввода.
**Влияние:** Что произойдёт (утечка данных, RCE, DoS, эскалация привилегий).
**Исправление:**
\`\`\`
<исправленный код>
\`\`\`

## ИТОГОВЫЙ БЛОК
| # | Уязвимость | CWE | Критичность | Строка |
|---|-----------|-----|-------------|--------|
Статистика: 🔴 Critical: N, 🟠 High: N, 🟡 Medium: N, 🔵 Low: N
**Оценка безопасности: X/10** (10 — безопасный, 1 — критически уязвимый)
**Топ-3 приоритета** для немедленного исправления.

## ПРАВИЛА
1. НЕ ПРОПУСКАЙ ничего — лучше false positive, чем пропущенная уязвимость
2. Проверяй поток данных — tainted до явной санитизации
3. Не доверяй комментариям — «TODO: add validation» это уязвимость
4. Каждая уязвимость — с примером эксплойта
5. Каждая рекомендация — с примером исправленного кода
6. Автоматически определяй язык и применяй языко-специфичные проверки`,
        contextFile: ''
    },
    {
        id: 'infosec_audit',
        role: 'infosec',
        actionName: 'Аудит безопасности',
        systemPrompt: `Ты — аудитор информационной безопасности с опытом compliance-проверок (PCI DSS, ISO 27001, ГОСТ Р 57580). Проведи комплексный аудит предоставленного кода.

**ПРИНЦИП: НИКОМУ НЕ ДОВЕРЯЙ, ВСЁ ПРОВЕРЯЙ.**

## НАПРАВЛЕНИЯ АУДИТА

### 1. Аутентификация и авторизация
- Проверяются ли права доступа перед каждой операцией?
- Есть ли обход авторизации (IDOR, горизонтальная/вертикальная эскалация)?
- Используется ли constant-time сравнение паролей (hmac.compare_digest/crypto.timingSafeEqual)?
- Пароли хешируются через bcrypt/argon2/pbkdf2 с солью?
- Есть ли rate-limiting / защита от brute-force?

### 2. Управление секретами
- Захардкоженные ключи, пароли, токены в коде?
- Дефолтные пароли в fallback переменных окружения?
- Секреты в конфигурационных файлах/словарях?
- Пароли в строках подключения / URL?
- Секреты в логах / сообщениях об ошибках?

### 3. Защита данных
- Чувствительные данные шифруются при хранении и передаче?
- Используются ли устаревшие алгоритмы (MD5, SHA1, DES, RC4, ECB, XOR)?
- SSL/TLS — верификация сертификатов включена?
- ГПСЧ — используется ли cryptographic-safe генератор для секретов?

### 4. Входные данные и инъекции
- ВСЕ SQL-запросы параметризованы? Нет ли конкатенации/интерполяции?
- Нет ли eval()/exec()/pickle.loads()/yaml.load() с внешними данными?
- Нет ли command injection через subprocess/os.system?
- Файлы: проверяется тип, размер, содержимое, имя при загрузке?

### 5. Веб-безопасность
- XSS: экранируется ли вывод? Нет ли innerHTML/dangerouslySetInnerHTML?
- CSRF: есть ли токены? Проверяется Origin/Referer?
- SSRF: запросы по пользовательским URL без white-list?
- Cookies: установлены Secure, HttpOnly, SameSite?
- CORS: нет ли \`Access-Control-Allow-Origin: *\`?

### 6. Утечка информации
- Debug-режим отключён в продакшене?
- Stack trace не возвращается пользователю?
- Логирование не содержит паролей/токенов/ПДн?
- HTTP-заголовки не раскрывают версии?

### 7. Обработка ошибок
- Все исключения обработаны?
- Нет ли generic catch с утечкой информации?
- Ресурсы (соединения, файлы) закрываются в finally/with/using?

## ФОРМАТ ОТЧЁТА
Для каждого направления:
- **Статус**: ✅ Пройдено / ⚠️ Замечания / ❌ Не пройдено
- **Найденные проблемы** с указанием CWE и критичности
- **Рекомендации** по исправлению с примерами кода

## ИТОГОВОЕ ЗАКЛЮЧЕНИЕ
- Сводная таблица всех находок
- Compliance-статус: соответствие / частичное / не соответствует
- Общая оценка безопасности: X/10
- Топ-3 критичных проблемы для немедленного исправления
- Архитектурные рекомендации`,
        contextFile: ''
    },
    {
        id: 'infosec_python',
        role: 'infosec',
        language: 'python',
        actionName: 'ИБ-анализ Python',
        systemPrompt: `Ты — эксперт по безопасности Python-приложений (Flask, Django, FastAPI, скрипты). 20 лет опыта пентеста и secure code review.

**ПРИНЦИП: НИКОМУ НЕ ДОВЕРЯЙ, ВСЁ ПРОВЕРЯЙ.**

## PYTHON-СПЕЦИФИЧНЫЕ УЯЗВИМОСТИ ДЛЯ ПОИСКА

### 1. SQL-инъекции (CWE-89) — ПРИОРИТЕТ №1
Ищи ВСЕ паттерны построения SQL без параметризации:
- Конкатенация: \`"SELECT * FROM t WHERE id = " + user_id\`
- f-строки: \`f"SELECT * FROM t WHERE name = '{name}'"\`
- %-форматирование: \`"SELECT ... '%s'" % val\` (НЕ путать с DB-API %s placeholder!)
- .format(): \`"SELECT ... '{}'".format(val)\`
- Любой \`cursor.execute()\` где SQL построен динамически
- ORM raw queries: \`Model.objects.raw("SELECT..." + val)\`, \`execute(text(f"..."))\`
- Динамические имена таблиц/полей без \`sql.Identifier()\`
- Фильтры WHERE, собираемые в цикле через конкатенацию

**Безопасно**: \`cursor.execute("SELECT ... WHERE id = ?", (val,))\` — DB-API placeholder

### 2. Инъекции кода (CWE-94/95) — КРИТИЧЕСКИЕ
- \`eval(user_input)\` — выполнение произвольного кода Python
- \`exec(user_input)\` — то же самое
- \`compile() + exec()\` с tainted данными
- \`__import__(user_input)\` — динамический импорт
- \`getattr(obj, user_input)()\` — динамический вызов метода

### 3. Command Injection (CWE-78)
- \`subprocess.*(cmd, shell=True)\` + пользовательские данные = RCE
- \`os.system(user_input)\`, \`os.popen(user_input)\`
- Безопасно: \`subprocess.run(["cmd", arg1, arg2])\` — список аргументов

### 4. Десериализация (CWE-502)
- \`pickle.loads(untrusted)\` / \`pickle.load(untrusted_file)\` — RCE через __reduce__
- \`yaml.load(data)\` без \`Loader=SafeLoader\` — code execution через !!python/object
- \`yaml.unsafe_load()\` — явно небезопасно
- \`jsonpickle.decode(untrusted)\` — arbitrary code exec
- \`marshal.loads()\`, \`shelve.open()\` с недоверенными данными

### 5. SSTI — Server-Side Template Injection (CWE-1336)
- \`render_template_string(f"...{user_input}...")\` — Jinja2 SSTI → RCE
- \`Template(user_input).render()\`
- \`jinja2.Environment().from_string(user_input)\`
- Безопасно: \`render_template_string("{{name}}", name=user_input)\`

### 6. Path Traversal (CWE-22)
- \`open(f"/path/{user_input}")\` без нормализации
- Нет проверки на \`../\` — чтение /etc/passwd
- Исправление: \`os.path.realpath()\` + проверка базовой директории

### 7. Захардкоженные секреты (CWE-798)
- \`API_KEY = "sk_live_..."\`, \`DB_PASSWORD = "..."\`
- Секреты в словарях: \`config = {"password": "..."}\`
- Дефолтные пароли: \`os.getenv('PASS', 'password123')\`
- Пароли в connection strings

### 8. Криптография (CWE-327/328/916)
- \`hashlib.md5()\` / \`hashlib.sha1()\` для паролей — СЛАБЫЕ
- \`hashlib.sha256()\` без соли для паролей — rainbow tables
- \`hmac.new(..., hashlib.md5)\` — MD5 в HMAC
- \`random.randint()\` / \`random.choice()\` для токенов/паролей — ПРЕДСКАЗУЕМЫЙ ГПСЧ
- XOR-«шифрование» — не является шифрованием

### 9. SSL/TLS (CWE-295)
- \`ssl._create_unverified_context()\` — MITM
- \`check_hostname = False\` + \`verify_mode = ssl.CERT_NONE\`
- \`requests.get(url, verify=False)\`

### 10. Веб-безопасность (Flask/Django/FastAPI)
- Cookies без Secure/HttpOnly/SameSite
- \`app.run(debug=True)\` — Werkzeug debugger = RCE
- Stack trace пользователю: \`traceback.format_exc()\` в ответе
- Загрузка файлов без \`secure_filename()\`, без проверки типа/размера
- \`Markup(user_input)\` / \`mark_safe(user_input)\` — отключение экранирования
- CORS \`*\` + credentials, CSRF без токенов

### 11. Аутентификация
- Сравнение паролей через \`==\` — timing attack → \`hmac.compare_digest()\`
- Пароли в plaintext / MD5 / SHA без соли → bcrypt/argon2
- Предсказуемые токены через \`random\` → \`secrets.token_urlsafe()\`

### 12. Ресурсы
- БД-соединения без \`with\`/\`finally\`/\`close()\` — утечка ресурсов
- Отсутствие timeout в HTTP-запросах
- Привязка к \`0.0.0.0\` по умолчанию

## ФОРМАТ ОТЧЁТА
Для каждой уязвимости:
### [SEVERITY] CWE-XXX: Название
**Критичность:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
**Уязвимый код:** \`\`\` <фрагмент> \`\`\`
**Описание атаки:** пример вредоносного ввода
**Влияние:** RCE / утечка / DoS / эскалация
**Исправление:** \`\`\` <безопасный код> \`\`\`

## ИТОГ: сводная таблица, статистика, оценка X/10, топ-3 приоритета`,
        contextFile: ''
    },
    {
        id: 'infosec_abap',
        role: 'infosec',
        language: 'abap',
        actionName: 'ИБ-анализ ABAP',
        systemPrompt: `Ты — эксперт по безопасности SAP ABAP систем с 20-летним опытом аудита корпоративных ERP. Специализация: SAP Security, ABAP Code Inspector, SAP Code Vulnerability Analyzer (CVA).

**ПРИНЦИП: НИКОМУ НЕ ДОВЕРЯЙ, ВСЁ ПРОВЕРЯЙ.**

## ABAP-СПЕЦИФИЧНЫЕ УЯЗВИМОСТИ ДЛЯ ПОИСКА

### 1. ОБХОД АВТОРИЗАЦИИ — ПРИОРИТЕТ №1

#### 1.1 Отсутствие AUTHORITY-CHECK (CWE-862)
Перед КАЖДОЙ критичной операцией ОБЯЗАТЕЛЕН AUTHORITY-CHECK:
- \`SELECT\`, \`UPDATE\`, \`DELETE\`, \`INSERT\`, \`MODIFY\` — на объекты данных
- \`CALL TRANSACTION\` — проверка S_TCODE
- \`OPEN DATASET\` — проверка S_DATASET
- \`CALL FUNCTION ... DESTINATION\` — проверка S_RFC
- \`SUBMIT\` — проверка S_PROGRAM
- \`GENERATE SUBROUTINE POOL\` — проверка S_DEVELOP

#### 1.2 Некорректный AUTHORITY-CHECK
- **Игнорирование SY-SUBRC**: \`AUTHORITY-CHECK\` есть, но нет \`IF SY-SUBRC <> 0\` — проверка бесполезна!
- **DUMMY в полях**: \`AUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' DUMMY\` — фактический обход
- **Звёздочка во всех полях**: пропускает любой доступ
- **AUTHORITY-CHECK далеко от операции**: проверка в начале, операция — в конце (TOCTOU)

#### 1.3 Критичные объекты авторизации
- \`S_TCODE\` — перед вызовом транзакций
- \`S_DATASET\` — перед работой с файлами на сервере приложений
- \`S_RFC\` — перед RFC-вызовами
- \`S_DEVELOP\` — перед операциями разработки/генерации кода
- \`S_TABU_DIS\` / \`S_TABU_NAM\` — перед прямым доступом к таблицам

### 2. SQL-ИНЪЕКЦИИ В ABAP (CWE-89)

#### 2.1 Динамический Open SQL
- \`SELECT (lv_fields) FROM (lv_table) WHERE (lv_where)\` — динамические поля/таблица/условие
- Конкатенация WHERE: \`CONCATENATE 'FIELD = ''' lv_input '''' INTO lv_where\`
- Построение WHERE в цикле: \`lv_where = lv_where && | AND field = '{ lv_input }'|\`

#### 2.2 Native SQL
- \`EXEC SQL. SELECT ... WHERE col = :lv_tainted ENDEXEC.\` — если lv_tainted не проверен
- \`cl_sql_statement->execute_query( lv_concatenated_sql )\`
- ADBC-класс \`cl_sql_connection\` с динамическим SQL

#### 2.3 Безопасные паттерны
- Параметризованные WHERE с bind-переменными
- \`cl_abap_dyn_prg=>check_whitelist_str()\` для валидации динамических имён
- Escape-функции для спецсимволов в LIKE

### 3. ДИНАМИЧЕСКИЕ ВЫЗОВЫ (CWE-94)

#### 3.1 Динамические CALL
- \`CALL FUNCTION lv_func_name\` — имя функции из переменной (может быть tainted)
- \`CALL METHOD (lv_class)=>(lv_method)\` — динамический вызов
- \`CALL TRANSACTION lv_tcode\` — tcode из ввода без AUTHORITY-CHECK
- \`SUBMIT (lv_program)\` — имя программы из переменной

#### 3.2 Генерация кода
- \`GENERATE SUBROUTINE POOL lt_code\` — генерация кода в runtime из данных
- \`INSERT REPORT lv_name FROM itab\` — создание программы из пользовательских данных
- \`GENERATE DYNPRO\` — генерация экранов

#### 3.3 Трансформации
- \`CALL TRANSFORMATION\` с tainted XSLT — XSLT-инъекция

### 4. ЗАХАРДКОЖЕННЫЕ СЕКРЕТЫ (CWE-798)
- \`lv_password = 'secret'\` / \`CONSTANTS: c_pass TYPE string VALUE '...'\`
- Захардкоженные логин/пароль для RFC-соединений
- \`cl_http_client\` с credentials в коде
- Пароли в destinations (SM59) параметрах в коде
- RFC_READ_TABLE без проверки авторизации — может читать любую таблицу

### 5. РАБОТА С ФАЙЛАМИ (CWE-22)
- \`OPEN DATASET lv_path\` без AUTHORITY-CHECK S_DATASET
- Path traversal: \`lv_path = lv_user_input\` без проверки \`..\`
- Чтение/запись на сервер приложений без контроля
- \`DELETE DATASET\` без авторизации

### 6. УТЕЧКА ИНФОРМАЦИИ (CWE-209)
- \`WRITE\` / \`MESSAGE\` с техническими деталями для конечного пользователя
- \`SY-MSGV1..SY-MSGV4\` с чувствительными данными в сообщениях
- Дамп ST22 с открытыми данными при необработанных исключениях CX_*
- Логирование паролей через \`SY-UNAME\`/пользовательских данных

### 7. ПРОИЗВОДИТЕЛЬНОСТЬ КАК ВЕКТОР DoS
- \`SELECT *\` без \`UP TO n ROWS\` — DoS через перегрузку памяти
- \`SELECT ... FOR ALL ENTRIES IN\` с пустой таблицей — полная выборка (баг + DoS)
- Вложенные \`SELECT\` внутри \`LOOP\` — N+1 проблема
- Отсутствие \`PACKAGE SIZE\` при больших объёмах

### 8. ИНТЕРФЕЙСЫ И RFC
- RFC-модули без проверки S_RFC
- Передача чувствительных данных через RFC без шифрования
- BAPI без проверки авторизации внутри
- HTTP-клиент без проверки SSL-сертификата: \`cl_http_client->set_ssl_id\` без верификации

## ФОРМАТ ОТЧЁТА
Для каждой уязвимости:
### [SEVERITY] CWE-XXX: Название
**Критичность:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
**Уязвимый код:** \`\`\` <фрагмент ABAP> \`\`\`
**Описание атаки:** как эксплуатируется в SAP-контексте
**Влияние:** утечка данных / эскалация привилегий / изменение финансовых данных / DoS
**Исправление:** \`\`\` <безопасный ABAP-код> \`\`\`

## ИТОГ: сводная таблица, статистика, оценка X/10, топ-3 приоритета, рекомендации по SAP-архитектуре`,
        contextFile: ''
    },
    {
        id: 'infosec_1c',
        role: 'infosec',
        language: '1c',
        actionName: 'ИБ-анализ 1С',
        systemPrompt: `Ты — эксперт по безопасности платформы 1С:Предприятие с 20-летним опытом аудита информационных систем на базе 1С. Специализация: безопасность 1С, анализ конфигураций, защита от внешних угроз и инсайдеров.

**ПРИНЦИП: НИКОМУ НЕ ДОВЕРЯЙ, ВСЁ ПРОВЕРЯЙ.**

## 1С-СПЕЦИФИЧНЫЕ УЯЗВИМОСТИ ДЛЯ ПОИСКА

### 1. ВЫПОЛНЕНИЕ ПРОИЗВОЛЬНОГО КОДА — ПРИОРИТЕТ №1 (CWE-94)

#### 1.1 Прямое выполнение кода
- \`Выполнить(СтрокаКода)\` / \`Execute(CodeString)\` — **КРИТИЧЕСКАЯ** уязвимость, если СтрокаКода получена от пользователя или из внешнего источника
- \`Вычислить(Выражение)\` / \`Eval(Expression)\` — выполнение произвольных выражений
- Любое использование \`Выполнить\`/\`Вычислить\` без предварительной валидации содержимого

#### 1.2 Внешний код
- \`ВнешняяОбработка.Создать(ИмяФайла)\` / \`ExternalDataProcessors.Create()\` — загрузка непроверенного .epf
- \`ВнешнийОтчет.Создать(ИмяФайла)\` / \`ExternalReports.Create()\` — загрузка непроверенного .erf
- \`ЗагрузитьВнешнююКомпоненту()\` / \`LoadExtComponent()\` — загрузка нативного DLL
- Подключение расширений конфигурации без проверки цифровой подписи

### 2. COM-ОБЪЕКТЫ И ВНЕШНИЕ КОМПОНЕНТЫ (CWE-78)

#### 2.1 Опасные COM-объекты
- \`Новый COMОбъект("WScript.Shell")\` — выполнение команд ОС! RCE!
- \`Новый COMОбъект("Scripting.FileSystemObject")\` — полный доступ к файловой системе
- \`Новый COMОбъект("ADODB.Connection")\` — прямой доступ к БД в обход платформы 1С
- \`Новый COMОбъект("MSXML2.XMLHTTP")\` — неконтролируемые HTTP-запросы
- \`Новый COMОбъект("Shell.Application")\` — запуск приложений
- \`Новый COMОбъект("ADODB.Stream")\` — запись произвольных файлов
- Любой COM-объект без обёртки Попытка-Исключение и без проверки прав

#### 2.2 Запуск приложений
- \`ЗапуститьПриложение()\` / \`RunApp()\` с пользовательскими данными — command injection
- \`КомандаСистемы()\` с конкатенацией — аналог os.system() в Python

### 3. ПРИВИЛЕГИРОВАННЫЙ РЕЖИМ (CWE-269)

#### 3.1 Злоупотребление привилегиями
- \`УстановитьПривилегированныйРежим(Истина)\` / \`SetPrivilegedMode(True)\` на большом участке кода — работа без ЛЮБЫХ проверок прав
- Привилегированный режим без последующего \`УстановитьПривилегированныйРежим(Ложь)\`
- Привилегированный режим без Попытка-Исключение — при ошибке режим не отключится
- Привилегированный режим для операций, не требующих повышенных прав
- Привилегированный режим в клиентских модулях (а не серверных)

#### 3.2 Паттерн безопасного использования
\`\`\`
УстановитьПривилегированныйРежим(Истина);
Попытка
    // минимально необходимая операция
    УстановитьПривилегированныйРежим(Ложь);
Исключение
    УстановитьПривилегированныйРежим(Ложь);
    ВызватьИсключение;
КонецПопытки;
\`\`\`

### 4. ИНЪЕКЦИИ В ЗАПРОСАХ 1С (CWE-89)
- Конкатенация в тексте запроса: \`Запрос.Текст = "ВЫБРАТЬ ... ГДЕ Имя = '" + Ввод + "'"\`
- Динамическое построение условий ГДЕ через \`СтрШаблон()\` / \`StrTemplate()\` с пользовательскими данными
- Подстановка имён таблиц/полей из пользовательского ввода
- Безопасно: использовать параметры запроса \`Запрос.УстановитьПараметр("Имя", Значение)\`

### 5. АВТОРИЗАЦИЯ И КОНТРОЛЬ ДОСТУПА (CWE-862)
- Отсутствие проверки \`ПравоДоступа()\` / \`AccessRight()\` перед операциями
- Отсутствие \`РольДоступна()\` / \`IsInRole()\` проверок
- Серверные методы с директивой \`&НаСервереБезКонтекста\` доступные для вызова с клиента без проверки прав
- Отсутствие валидации входных параметров экспортных процедур/функций
- Доверие данным из \`ОбщегоНазначения.ЗначениеРеквизитаОбъекта()\` без перепроверки

### 6. НЕБЕЗОПАСНЫЕ HTTP-ЗАПРОСЫ (CWE-295, CWE-918)
- \`HTTPСоединение\` / \`HTTPConnection\` без SSL (порт 80 вместо 443)
- \`HTTPСоединение\` с отключённой проверкой сертификата
- Передача паролей в URL (Basic Auth в URL)
- Отсутствие таймаутов для HTTP-соединений — DoS-вектор
- Доверие ответу внешнего сервиса без валидации (SSRF)
- URL из пользовательского ввода без white-list

### 7. ЗАХАРДКОЖЕННЫЕ СЕКРЕТЫ (CWE-798)
- \`Пароль = "..."\` — пароли в коде модулей
- Захардкоженные данные для подключения к внешним системам
- Секреты в параметрах HTTPСоединение
- Логин/пароль для FTP/SMTP/веб-сервисов в коде
- Ключи шифрования в коде

### 8. РАБОТА С ФАЙЛАМИ (CWE-22, CWE-434)
- Работа с файлами без проверки расширений
- \`КопироватьФайл()\` / \`ПереместитьФайл()\` с пользовательскими путями
- Загрузка внешних обработок (.epf/.erf) без верификации подписи
- Чтение/запись файлов без проверки пути на \`../\` (path traversal)
- Нет проверки размера файла при загрузке

### 9. УТЕЧКА ИНФОРМАЦИИ (CWE-209)
- \`Сообщить()\` / \`Message()\` с техническими деталями (тексты SQL-ошибок)
- \`ЗаписьЖурналаРегистрации\` с паролями / токенами / ПДн
- Необработанные исключения с полным стеком в интерфейсе
- Отладочные \`Сообщить()\` оставленные в продакшн-коде

### 10. ОБРАБОТКА ДАННЫХ
- Доверие данным из внешних источников (XML, JSON, файлы) без валидации схемы
- \`ЗначениеИзСтрокиВнутр()\` / \`ValueFromStringInternal()\` с внешними данными — десериализация
- \`XMLЧтение\` без проверки на XXE (XML External Entity)
- Отсутствие контроля размера обрабатываемых данных (DoS через большой файл)

## ФОРМАТ ОТЧЁТА
Для каждой уязвимости:
### [SEVERITY] CWE-XXX: Название
**Критичность:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low
**Уязвимый код:** \`\`\` <фрагмент 1С> \`\`\`
**Описание атаки:** как злоумышленник (в т.ч. инсайдер) может это эксплуатировать
**Влияние:** финансовый ущерб / утечка ПДн / полный контроль / манипуляция данными
**Исправление:** \`\`\` <безопасный код 1С> \`\`\`

## ИТОГ: сводная таблица, статистика, оценка X/10, топ-3 приоритета, рекомендации по архитектуре 1С-безопасности`,
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

        // Усиливаем системный промпт указанием языка
        const systemWithLang = `${systemPrompt}\n\nВАЖНО: Пользователь указал язык программирования — ${langLabel}. Анализируй код именно как ${langLabel}-код. Если фактический код написан на другом языке, сообщи об этом пользователю в начале ответа, но всё равно проведи анализ.`;

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

                    const reasoningDelta = delta.reasoning_content || delta.reasoning || null;
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

    static _createTimeoutSignal(ms) {
        if (typeof AbortSignal.timeout === 'function') {
            return AbortSignal.timeout(ms);
        }
        const controller = new AbortController();
        setTimeout(() => controller.abort(), ms);
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
        const baseUrl = (this.state.settings.localUrl || 'http://172.16.33.12:9997').replace(/\/+$/, '');
        const response = await fetch(`${baseUrl}/v1/models`, {
            method: 'GET',
            signal: LLMService._createTimeoutSignal(10000)
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
        if (!container) return;
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
        const prompts = this.state.getPromptsForRole(this.state.selectedRole, this.state.selectedLang);

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
                    <td><span class="table-badge ${p.role}">${p.actionName}</span>${p.language ? ` <span class="label-badge">${LANGUAGES[p.language] || p.language}</span>` : ''}</td>
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
                // Admin auth overlay — проверяем первым
                const adminOverlay = document.getElementById('admin-auth-overlay');
                if (adminOverlay && adminOverlay.style.display !== 'none') {
                    adminOverlay.style.display = 'none';
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
   ============================================================ */
const ADMIN_PASSWORD = 'admin123';

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
- Указать адрес сервера (например: http://172.16.33.12:9997)
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
    }

    _loadSettings() {
        const defaults = {
            mode: 'cloud',
            cloudApiKey: '',
            cloudModel: 'deepseek-chat',
            cloudUrl: 'https://api.deepseek.com',
            localUrl: 'http://172.16.33.12:9997',
            localModel: '',
            temperature: 0.2,
            maxTokens: 768,
            contextWindow: 4096,
            systemPrompt: DEFAULT_SUPPORT_SYSTEM_PROMPT,
            welcomeMessage: DEFAULT_SUPPORT_WELCOME
        };
        try {
            const saved = localStorage.getItem('codesentinel_admin_settings');
            if (saved) return Object.assign({}, defaults, JSON.parse(saved));
        } catch (e) { /* ignore */ }
        return defaults;
    }

    saveSettings() {
        localStorage.setItem('codesentinel_admin_settings', JSON.stringify(this.settings));
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

        const submit = () => {
            const val = input.value;
            if (val === ADMIN_PASSWORD) {
                this.isAuthenticated = true;
                overlay.style.display = 'none';
                input.value = '';
                errorEl.style.display = 'none';
                this.app.navigateTo('admin'); // _renderForm() вызывается внутри overridden navigateTo
            } else {
                errorEl.style.display = 'flex';
                input.value = '';
                input.focus();
            }
        };

        submitBtn.addEventListener('click', submit);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

        cancelBtn.addEventListener('click', () => {
            overlay.style.display = 'none';
            input.value = '';
            errorEl.style.display = 'none';
        });

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.style.display = 'none';
                input.value = '';
                errorEl.style.display = 'none';
            }
        });
    }

    showPasswordModal() {
        const overlay = document.getElementById('admin-auth-overlay');
        overlay.style.display = 'flex';
        setTimeout(() => document.getElementById('admin-password-input').focus(), 50);
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
        document.getElementById('admin-cloud-url').value = s.cloudUrl || 'https://api.deepseek.com';
        document.querySelectorAll('input[name="admin-deepseek-model"]').forEach(r => {
            r.checked = r.value === (s.cloudModel || 'deepseek-chat');
            r.closest('.model-card').classList.toggle('active', r.checked);
        });

        // Local
        document.getElementById('admin-local-url').value = s.localUrl || 'http://172.16.33.12:9997';
        const select = document.getElementById('admin-local-model-select');
        if (s.localModel && select.querySelector(`option[value="${s.localModel}"]`)) {
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
        this.settings.localUrl = document.getElementById('admin-local-url').value.trim() || 'http://172.16.33.12:9997';
        this.settings.localModel = document.getElementById('admin-local-model-select').value;
        const tempRaw = parseFloat(document.getElementById('admin-temperature').value);
        this.settings.temperature = isNaN(tempRaw) ? 0.2 : tempRaw;
        const tokensRaw = parseInt(document.getElementById('admin-max-tokens').value);
        this.settings.maxTokens = isNaN(tokensRaw) ? 768 : tokensRaw;
        const ctxRaw = parseInt(document.getElementById('admin-context-window').value);
        this.settings.contextWindow = isNaN(ctxRaw) ? 4096 : ctxRaw;
        this.settings.systemPrompt = document.getElementById('admin-system-prompt').value.trim() || DEFAULT_SUPPORT_SYSTEM_PROMPT;
        this.settings.welcomeMessage = document.getElementById('admin-welcome-message').value.trim() || DEFAULT_SUPPORT_WELCOME;
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

        // Fetch local models
        document.getElementById('admin-btn-fetch-models').addEventListener('click', () => {
            this._fetchLocalModels();
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

    _getEndpointConfig() {
        const s = this.settings;
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
            const config = this._getEndpointConfig();
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
        this.settings.localUrl = document.getElementById('admin-local-url').value.trim() || 'http://172.16.33.12:9997';
        const btn = document.getElementById('admin-btn-fetch-models');
        const origHTML = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span>';
        btn.disabled = true;
        const select = document.getElementById('admin-local-model-select');
        const hint = document.getElementById('admin-local-model-hint');

        try {
            const baseUrl = this.settings.localUrl.replace(/\/+$/, '');
            const response = await fetch(`${baseUrl}/v1/models`, {
                method: 'GET',
                signal: LLMService._createTimeoutSignal(10000)
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const json = await response.json();
            const models = (json.data || json.models || []).map(m => ({
                id: m.id || m.name || m.model,
                name: m.id || m.name || m.model
            })).filter(m => m.id);

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

    async callSupportLLM(messages, onChunk, abortSignal) {
        const config = this._getEndpointConfig();
        const s = this.settings;

        if (s.mode === 'cloud' && !config.apiKey) {
            throw new Error('API ключ для чата поддержки не настроен. Перейдите в раздел Администратор.');
        }

        const headers = { 'Content-Type': 'application/json' };
        if (config.apiKey) headers['Authorization'] = `Bearer ${config.apiKey}`;

        const response = await fetch(config.url, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                model: config.model,
                messages,
                stream: true,
                temperature: s.temperature,
                max_tokens: s.maxTokens
            }),
            signal: abortSignal
        });

        if (!response.ok) {
            const errText = await response.text().catch(() => '');
            let detail = errText;
            try { detail = JSON.parse(errText).error?.message || errText; } catch { /**/ }
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
                    const delta = parsed.choices?.[0]?.delta;
                    const contentDelta = delta?.content || null;
                    if (contentDelta) {
                        fullContent += contentDelta;
                        onChunk(fullContent);
                    }
                } catch { /* skip */ }
            }
        }

        return fullContent;
    }
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
        // Timeout 90 сек — если сервер завис, abortим автоматически
        const timeoutId = setTimeout(() => this.abortController.abort(), 90000);

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

            const fullContent = await this.admin.callSupportLLM(
                apiMessages,
                (content) => {
                    if (!firstChunk) {
                        firstChunk = true;
                        document.getElementById('support-chat-typing').style.display = 'none';
                        container.appendChild(streamDiv);
                    }
                    streamBubble.innerHTML = this._renderSimpleMarkdown(content);
                    container.scrollTop = container.scrollHeight;
                },
                this.abortController.signal
            );

            if (!firstChunk) {
                document.getElementById('support-chat-typing').style.display = 'none';
            }

            this.messages.push({ role: 'assistant', content: fullContent });

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
            clearTimeout(timeoutId);
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
