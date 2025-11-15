# Network Scanner - Техническая документация для ИИ-агента

## Обзор проекта

Network Scanner — инструмент для автоматизированного сетевого сканирования и анализа уязвимостей. Проект использует комбинацию Masscan (быстрое TCP сканирование), Nmap (подтверждение и обогащение сервисов), Nuclei (веб-сканирование уязвимостей) и AI (генерация аналитических отчетов).

### Архитектура

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Masscan   │ --> │    Nmap     │ --> │   Nuclei    │ --> │     AI      │
│  (TCP scan) │     │ (Service    │     │  (Web vuln) │     │  (Reports)  │
│             │     │  detection) │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┘
                                    │
                           ┌────────▼────────┐
                           │   SQLite DB     │
                           │  (Results)      │
                           └─────────────────┘
```

## Структура кодовой базы

```
network_scanner/
├── __init__.py
├── cli/
│   ├── __init__.py
│   └── main.py              # CLI команды (Click framework)
├── config/
│   ├── __init__.py
│   ├── settings.py          # Конфигурация (Settings dataclass)
│   └── logging_utils.py     # Настройка логирования
├── db/
│   ├── __init__.py
│   ├── models.py            # SQLAlchemy модели данных
│   └── dao.py               # Data Access Object - функции работы с БД
├── parsers/
│   ├── __init__.py
│   ├── nmap_xml.py          # Парсинг Nmap XML результатов
│   └── nuclei_json.py       # Парсинг Nuclei JSON результатов
├── scan/
│   ├── __init__.py
│   ├── runner.py            # Основной runner для Masscan+Nmap
│   └── nuclei_runner.py     # Runner для Nuclei сканирования + AI
└── vuln/
    ├── __init__.py
    └── epss.py              # Работа с EPSS API
```

## Модели данных (SQLAlchemy)

### Иерархия моделей

```
Tenant (1) ──< (N) Network
Tenant (1) ──< (1) TenantPorts
Tenant (1) ──< (N) TenantExclude
Tenant (1) ──< (N) Scan
Tenant (1) ──< (N) NucleiScan

Scan (1) ──< (N) Host
Host (1) ──< (N) Service
Host (1) ──< (N) Vulnerability
Host (1) ──< (N) NucleiFinding (через host_id)

NucleiScan (1) ──< (N) NucleiFinding
Scan (1) ──< (0..1) NucleiScan (через scan_id)
```

### Детальное описание моделей

#### Tenant
- **Таблица**: `tenant`
- **Поля**:
  - `id` (int, PK): Уникальный идентификатор
  - `name` (str, unique, indexed): Имя тенанта
  - `description` (str, optional): Описание
- **Связи**:
  - `networks`: список Network (CASCADE DELETE)
  - `scans`: список Scan
  - `nuclei_scans`: список NucleiScan

#### Network
- **Таблица**: `network`
- **Поля**:
  - `id` (int, PK)
  - `cidr` (str): CIDR сеть (например, "10.0.0.0/24")
  - `tenant_id` (int, FK → tenant.id, CASCADE DELETE)
- **Уникальность**: (tenant_id, cidr)

#### TenantPorts
- **Таблица**: `tenant_ports`
- **Поля**:
  - `id` (int, PK)
  - `tenant_id` (int, FK → tenant.id, unique, CASCADE DELETE)
  - `tcp_ports` (str, optional): Список TCP портов через запятую (например, "22,80,443")

#### TenantExclude
- **Таблица**: `tenant_exclude`
- **Поля**:
  - `id` (int, PK)
  - `tenant_id` (int, FK → tenant.id, CASCADE DELETE)
  - `target` (str): IP/CIDR/hostname для исключения
- **Уникальность**: (tenant_id, target)

#### Scan
- **Таблица**: `scan`
- **Поля**:
  - `id` (int, PK)
  - `tenant_id` (int, FK → tenant.id, CASCADE DELETE)
  - `started_at` (datetime, UTC): Время начала сканирования
  - `finished_at` (datetime, optional, UTC): Время завершения
  - `mode` (str): "tcp" или "all"
  - `status` (str): "running", "done", "failed"
- **Связи**:
  - `hosts`: список Host
  - `nuclei_scans`: список NucleiScan (через scan_id)

#### Host
- **Таблица**: `host`
- **Поля**:
  - `id` (int, PK)
  - `scan_id` (int, FK → scan.id, CASCADE DELETE)
  - `ip` (str, indexed): IP адрес
  - `hostname` (str, optional): Имя хоста
- **Уникальность**: (scan_id, ip)
- **Связи**:
  - `services`: список Service
  - `vulnerabilities`: список Vulnerability
  - `nuclei_findings`: список NucleiFinding

#### Service
- **Таблица**: `service`
- **Поля**:
  - `id` (int, PK)
  - `host_id` (int, FK → host.id, CASCADE DELETE)
  - `port` (int): Номер порта
  - `protocol` (str): "tcp" или "udp"
  - `name` (str, optional): Имя сервиса
  - `product` (str, optional): Продукт
  - `version` (str, optional): Версия
  - `extrainfo` (str, optional): Дополнительная информация
  - `good` (bool): Флаг успешного обнаружения (0/1)
  - `time_discovery` (datetime, optional): Время обнаружения
- **Уникальность**: (host_id, port, protocol)

#### Vulnerability
- **Таблица**: `vulnerability`
- **Поля**:
  - `id` (int, PK)
  - `host_id` (int, FK → host.id, CASCADE DELETE)
  - `cve_id` (str): CVE идентификатор (например, "CVE-2021-12345")
  - `epss` (float, optional): EPSS score (0.0-1.0)
  - `percentile` (float, optional): EPSS percentile
  - `cvss_score` (float, optional): CVSS base score
  - `cvss_vector` (str, optional): CVSS vector string
  - `exploit_probability` (float, optional): Рассчитанная вероятность эксплуатации
  - `time_discovery` (datetime, optional): Время обнаружения
- **Уникальность**: (host_id, cve_id)

#### NucleiScan
- **Таблица**: `nuclei_scan`
- **Поля**:
  - `id` (int, PK)
  - `tenant_id` (int, FK → tenant.id, CASCADE DELETE)
  - `scan_id` (int, FK → scan.id, SET NULL, optional): Связь с базовым сканом
  - `started_at` (datetime, UTC): Время начала
  - `finished_at` (datetime, optional, UTC): Время завершения
  - `status` (str): "running", "done", "failed"
  - `templates` (str, optional): Использованные шаблоны (через запятую)
  - `target_count` (int): Количество целей
  - `report_path` (str, optional): Путь к JSON отчету
  - `nuclei_version` (str, optional): Версия Nuclei
  - `ai_summary` (text, optional): AI-сгенерированный отчет
- **Связи**:
  - `findings`: список NucleiFinding
  - `scan`: связь с Scan (optional)

#### NucleiFinding
- **Таблица**: `nuclei_finding`
- **Поля**:
  - `id` (int, PK)
  - `nuclei_scan_id` (int, FK → nuclei_scan.id, CASCADE DELETE)
  - `host_id` (int, FK → host.id, SET NULL, optional): Связь с Host
  - `target` (str): Целевой URL/IP
  - `template_id` (str, optional): ID шаблона Nuclei
  - `template_name` (str, optional): Имя шаблона
  - `severity` (str, optional): Серьезность (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - `description` (text, optional): Описание уязвимости
  - `evidence` (text, optional): Доказательства
  - `references` (text, optional): Ссылки (многострочный текст)
  - `tags` (str, optional): Теги (через запятую)
  - `matched_at` (datetime, UTC): Время обнаружения
  - `matched_url` (str, optional): URL где найдена уязвимость
- **Уникальность**: (nuclei_scan_id, template_id, target, matched_url)

## Конфигурация (Settings)

### Класс Settings

Расположение: `network_scanner/config/settings.py`

**Приоритет загрузки конфигурации:**
1. Файл, указанный через `--config`
2. Файл `.env` в корне проекта
3. Переменные окружения

### Поля Settings

#### Основные настройки
- `sqlite_path` (Path): Путь к SQLite БД (по умолчанию `./scanner.sqlite`)
- `data_dir` (Path): Директория для данных (по умолчанию `./data`)
- `rate` (int): Скорость Masscan (по умолчанию `2048`)
- `nmap_path` (str): Путь к nmap (по умолчанию `"nmap"`)
- `tcp_ports_default` (str, optional): TCP порты по умолчанию (через запятую)
- `exclude_ports` (str, optional): Порты для исключения из nmap (через запятую)

#### EPSS/NVD настройки
- `epss_api_url` (str): URL EPSS API (по умолчанию `https://api.first.org/data/v1/epss`)
- `epss_significant_threshold` (float): Порог значимости EPSS (по умолчанию `0.1`)
- `nvd_api_url` (str): URL NVD API (по умолчанию `https://services.nvd.nist.gov/rest/json/cves/2.0`)

#### Nuclei настройки
- `nuclei_path` (str): Путь к nuclei (по умолчанию `"nuclei"`)
- `nuclei_templates` (str): Шаблоны Nuclei (по умолчанию `"http/cves,ssl"`)
- `nuclei_timeout_sec` (int): Таймаут Nuclei в секундах (по умолчанию `1800`)
- `nuclei_socks5_proxy` (str, optional): SOCKS5 прокси для Nuclei

#### AI настройки
- `ai_api_url` (str, optional): URL AI API (например, OpenAI)
- `ai_api_key` (str, optional): API ключ для AI
- `ai_model` (str): Модель AI (по умолчанию `"gpt-4o-mini"`)
- `ai_enabled` (bool): Включить AI (по умолчанию `False`)
- `ai_temperature` (float): Температура AI (по умолчанию `0.4`)
- `ai_max_tokens` (int): Максимум токенов (по умолчанию `1200`)

### Методы Settings

- `Settings.load(config_path: Optional[str] = None) -> Settings`: Статический метод для загрузки конфигурации

## Data Access Object (DAO)

Расположение: `network_scanner/db/dao.py`

### Основные функции

#### Инициализация БД
- `create_sqlite_engine(db_path: Path) -> Engine`: Создает SQLAlchemy engine с включенными foreign keys
- `init_db(engine: Engine) -> None`: Инициализирует схему БД и выполняет миграции
- `get_session(engine: Engine) -> Iterator[Session]`: Context manager для работы с сессией БД

#### Tenant операции
- `add_tenant(session, name, description) -> Tenant`
- `get_tenant_by_name(session, name) -> Tenant | None`
- `list_tenants(session) -> list[Tenant]`
- `update_tenant(session, tenant, new_name, description) -> Tenant`
- `delete_tenant(session, tenant) -> None`

#### Network операции
- `add_network(session, tenant, cidr) -> Network`
- `list_networks(session, tenant) -> list[Network]`
- `get_network_by_id(session, network_id) -> Network | None`
- `update_network(session, network, cidr) -> Network`
- `delete_network(session, network) -> None`

#### Ports операции
- `get_tenant_ports(session, tenant) -> TenantPorts | None`
- `set_tenant_ports(session, tenant, tcp_ports) -> TenantPorts`

#### Exclude операции
- `list_tenant_excludes(session, tenant) -> list[TenantExclude]`
- `add_tenant_exclude(session, tenant, target) -> TenantExclude`
- `get_tenant_exclude_by_id(session, exclude_id) -> TenantExclude | None`
- `update_tenant_exclude(session, exclude, target) -> TenantExclude`
- `delete_tenant_exclude(session, exclude) -> None`

#### Scan операции
- `list_scans(session, tenant) -> list[Scan]`
- `get_scan_by_id(session, scan_id) -> Scan | None`
- `delete_scan(session, scan) -> None`

#### Nuclei операции
- `create_nuclei_scan(session, tenant, scan, templates, target_count, nuclei_version) -> NucleiScan`
- `get_nuclei_scan_by_id(session, nuclei_scan_id) -> NucleiScan | None`
- `list_nuclei_scans(session, tenant, scan) -> list[NucleiScan]` (сортировка по started_at DESC)
- `update_nuclei_scan(session, nuclei_scan, status, finished_at, target_count, report_path, ai_summary, nuclei_version) -> NucleiScan`
- `delete_nuclei_scan(session, nuclei_scan) -> None`

#### Nuclei Finding операции
- `add_nuclei_finding(session, nuclei_scan, host, target, template_id, template_name, severity, description, evidence, references, tags, matched_url, matched_at) -> NucleiFinding`
- `list_nuclei_findings(session, nuclei_scan, severity) -> list[NucleiFinding]` (сортировка по matched_at DESC)
- `delete_nuclei_findings_for_scan(session, nuclei_scan) -> None`

## Парсеры

### Nmap XML Parser

Расположение: `network_scanner/parsers/nmap_xml.py`

**Функция**: `parse_nmap_xml_into_db(session: Session, scan: Scan, xml_path: Path) -> None`

Парсит XML файл Nmap и сохраняет результаты в БД:
- Извлекает хосты (hosts) с IP и hostname
- Извлекает сервисы (services) с портами, протоколами, именами, продуктами, версиями
- Связывает хосты и сервисы со сканом

**Формат XML**: Стандартный формат Nmap (`-oX`)

### Nuclei JSON Parser

Расположение: `network_scanner/parsers/nuclei_json.py`

**Класс**: `NucleiFindingRecord` (dataclass)
- Содержит все поля из Nuclei JSON результата
- Используется для промежуточной обработки перед сохранением в БД

**Функция**: `load_nuclei_results(report_path: Path | str) -> list[NucleiFindingRecord]`

Парсит JSON файл Nuclei (поддерживает JSONL и JSON array форматы):
- Обрабатывает newline-delimited JSON (JSONL)
- Обрабатывает JSON array как fallback
- Извлекает информацию из структуры `info` и корневых полей
- Преобразует в `NucleiFindingRecord`

**Формат JSON**: Nuclei JSON формат с полями:
- `info.template_id`, `info.name`, `info.severity`, `info.description`
- `info.reference` или `info.references` (список)
- `info.tags` (список)
- `matched-at`, `matched-line`, `extracted-results`, `matcher-name`
- `host`, `ip`

## Сканирование

### Основной Runner (Masscan + Nmap)

Расположение: `network_scanner/scan/runner.py`

**Функция**: `run_scan_for_tenant(...)`

**Параметры**:
- `settings: Settings`
- `tenant_name: str`
- `mode: str = "tcp"` - "tcp" или "all"
- `service_info: bool = False` - использовать `-sV` в nmap
- `input_list: Optional[Path] = None` - файл с целями для masscan `-iL`
- `rate_override: Optional[int] = None` - переопределение скорости masscan
- `vulners: bool = False` - запустить nmap `--script vulners`
- `nuclei: bool = False` - запустить Nuclei после nmap

**Процесс**:
1. Создает запись Scan в БД со статусом "running"
2. Собирает цели из Network тенанта или из `input_list`
3. Применяет исключения из TenantExclude
4. Запускает Masscan с указанными параметрами
5. Сохраняет результаты Masscan в JSON
6. Передает результаты в Nmap для подтверждения
7. Сохраняет XML Nmap
8. Парсит XML через `parse_nmap_xml_into_db`
9. Опционально запускает `--script vulners` для обнаружения CVE
10. Опционально запускает Nuclei сканирование
11. Обновляет статус Scan на "done" или "failed"

**Артефакты**:
- `data/<tenant>/<YYYYMMDD>/masscan.json`
- `data/<tenant>/<YYYYMMDD>/nmap.xml`
- `data/<tenant>/<YYYYMMDD>/vulners_<ip>.xml` (если `--vulners`)

### Nuclei Runner

Расположение: `network_scanner/scan/nuclei_runner.py`

**Функция**: `run_nuclei_scan_for_scan(...)`

**Параметры**:
- `engine: Engine`
- `settings: Settings`
- `tenant_name: str`
- `scan_id: int`
- `output_dir: Path`
- `logger`

**Процесс**:
1. Получает Host и Service из БД для указанного scan_id
2. Определяет HTTP/HTTPS сервисы через `_infer_scheme()` и `_build_target()`
3. Собирает уникальные цели в список
4. Создает запись NucleiScan в БД
5. Для каждой цели запускает Nuclei с таймаутом:
   - Команда: `nuclei -silent -t <template> -target <target> -json-export <file>`
   - Использует прокси если настроен `nuclei_socks5_proxy`
6. Собирает результаты из JSON файлов
7. Сохраняет объединенный JSON отчет и лог
8. Если `ai_enabled=true` и есть находки:
   - Вызывает `_generate_ai_summary()` для генерации AI отчета
   - Сохраняет AI summary в БД
9. Сохраняет находки в БД через `add_nuclei_finding()`
10. Обновляет статус NucleiScan на "done" или "failed"

**Вспомогательные функции**:
- `_infer_scheme(service: Service) -> str | None`: Определяет схему (http/https) по имени/продукту сервиса
- `_build_target(host: Host, service: Service) -> str`: Строит целевой URL/IP:port
- `_collect_targets(pairs: Sequence[tuple[Host, Service]]) -> list[str]`: Собирает уникальные цели

**AI Summary генерация**:
- `_generate_ai_summary(settings, tenant_name, findings, logger) -> str | None`
- Берет до 100 первых находок
- Формирует prompt с JSON данными находок
- Отправляет запрос к AI API
- Логирует запрос и ответ (включая размер prompt)
- Возвращает сгенерированный текст или None при ошибке

**Артефакты**:
- `data/<tenant>/<YYYYMMDD>/nuclei_<timestamp>.json` (JSONL формат)
- `data/<tenant>/<YYYYMMDD>/nuclei_<timestamp>.log`

## CLI Команды

Расположение: `network_scanner/cli/main.py`

CLI построен на Click framework. Все команды доступны через `python cli.py <command>`.

### Основные команды управления

#### Управление тенантами
- `init-db` - Инициализация БД
- `add-tenant --name <name> [--desc <desc>]` - Добавить тенанта
- `edit-tenant --name <name> [--new-name <name>] [--desc <desc>]` - Редактировать тенанта
- `delete-tenant --name <name> [--yes]` - Удалить тенанта
- `list-tenants` - Список тенантов

#### Управление сетями
- `add-network --tenant <name> --cidr <cidr>` - Добавить сеть
- `edit-network --network-id <id> --cidr <cidr>` - Редактировать сеть
- `delete-network --network-id <id> [--yes]` - Удалить сеть
- `list-networks [--tenant <name>]` - Список сетей

#### Управление портами
- `set-ports --tenant <name> [--tcp <ports>]` - Установить TCP порты для тенанта
- `show-ports --tenant <name>` - Показать порты тенанта

#### Управление исключениями
- `add-exclude --tenant <name> --target <ip/cidr/hostname>` - Добавить исключение
- `list-excludes --tenant <name>` - Список исключений
- `edit-exclude --id <id> --target <target>` - Редактировать исключение
- `delete-exclude --id <id> [--yes]` - Удалить исключение

#### Управление сканами
- `list-scans [--tenant <name>]` - Список сканов
- `delete-scan --scan-id <id> [--yes]` - Удалить скан

### Команды сканирования

#### Основное сканирование
- `scan --tenant <name> [--mode tcp|all] [--service-info] [--vulners] [--nuclei] [--iL <file>] [--rate <rate>]` - Запустить сканирование
- `scan --all-tenants [--mode tcp|all] [--service-info] [--vulners] [--nuclei]` - Сканировать все тенанты

#### Nuclei сканирование
- `scan-nuclei --tenant <name> [--scan-id <id>]` - Запустить Nuclei для существующего скана
- `show-nuclei --tenant <name> [--nuclei-scan-id <id>] [--scan-id <id>] [--pdf]` - Показать результаты Nuclei
- `delete-nuclei --tenant <name> --nuclei-scan-id <id> [--yes]` - Удалить Nuclei скан

#### AI генерация
- `ai-nuclei --tenant <name> [--pdf]` - Сгенерировать AI summary для последнего Nuclei скана

### Команды просмотра и отчетов

- `show-last-scan --tenant <name> [--pdf]` - Показать последний скан
- `diff-scans --tenant <name> [--pdf]` - Сравнить два последних скана
- `search-vulners --tenant <name>` - Поиск уязвимостей (EPSS обновление или nmap vulners)

## Форматы данных

### Masscan JSON

Формат: JSON массив объектов, каждый объект представляет открытый порт:
```json
[
  {
    "ip": "192.168.1.1",
    "timestamp": "1234567890",
    "ports": [{"port": 80, "proto": "tcp"}]
  }
]
```

### Nmap XML

Стандартный формат Nmap XML (`-oX`). Содержит:
- `<host>` элементы с IP и hostname
- `<port>` элементы с портами, протоколами, состояниями
- `<service>` элементы с именами, продуктами, версиями

### Nuclei JSON (JSONL)

Формат: Newline-delimited JSON (JSONL), каждая строка - JSON объект:
```json
{
  "template-id": "weak-cipher-suites",
  "info": {
    "name": "Weak Cipher Suites",
    "severity": "low",
    "description": "...",
    "reference": ["https://..."],
    "tags": ["ssl", "tls"]
  },
  "matched-at": "https://example.com:443",
  "host": "example.com",
  "ip": "192.168.1.1",
  "extracted-results": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]
}
```

### PDF отчеты

PDF генерируются через fpdf2 библиотеку:
- Поддержка кириллицы через системные Unicode шрифты (Arial Unicode на macOS, DejaVu Sans на Linux)
- Автоматический парсинг markdown таблиц из AI отчетов
- Структурированные таблицы с метаданными, статистикой и деталями

**Типы PDF отчетов**:
- `{tenant}_last-scan_{timestamp}.pdf` - отчет по последнему скану
- `{tenant}_diff-scans_{timestamp}.pdf` - сравнение сканов
- `{tenant}_nuclei_{timestamp}.pdf` - отчет по Nuclei сканированию
- `{tenant}_nuclei_ai_{timestamp}.pdf` - AI отчет по Nuclei сканированию

## Логирование

Расположение: `network_scanner/config/logging_utils.py`

**Функция**: `get_app_logger(settings: Settings) -> logging.Logger`

- Логгер: `network_scanner`
- Уровень: `INFO`
- Файл: `{data_dir}/activity.log`
- Формат: `%(asctime)s [%(levelname)s] %(message)s`
- Ротация: 5 MB, 3 backup файла
- Кодировка: UTF-8

**Логирование AI запросов**:
- `AI Summary Request`: tenant, url, headers (без ключа), model, findings_count, prompt_size_chars, prompt_size_bytes, total_message_size_chars, body_size_bytes
- `AI Summary Response`: tenant, status_code, response_size
- `AI Summary Generated`: tenant, summary_length
- `AI Summary Generation Failed`: tenant, error (с exc_info)

## Важные детали реализации

### Обработка кириллицы в PDF

1. Автоматический поиск Unicode шрифтов в системных директориях
2. Использование Arial Unicode на macOS, DejaVu Sans на Linux
3. Fallback на Helvetica если Unicode шрифт не найден (будет ошибка с кириллицей)

### Парсинг markdown таблиц из AI отчетов

Функции в `network_scanner/cli/main.py`:
- `_parse_markdown_table(table_lines: list[str]) -> dict | None`: Парсит markdown таблицу
- `_split_ai_summary_into_blocks(ai_summary: str) -> list[dict]`: Разделяет AI summary на текстовые блоки и таблицы

Таблицы из markdown автоматически преобразуются в PDF таблицы.

### Обработка пустых страниц в PDF

- Пропуск пустых блоков перед добавлением в PDF
- Проверка на наличие содержимого в строках
- Правильный расчет высоты строк и переносов страниц

### Определение HTTP/HTTPS целей для Nuclei

- Анализ имени и продукта сервиса для определения схемы
- Построение целевого URL в формате `scheme://hostname:port` или `hostname:port`
- Очистка данных хоста (удаление лишних символов)

### Обработка ошибок

- Все операции с БД используют context manager `get_session()` с автоматическим rollback при ошибках
- Nuclei сканирование продолжается при ошибках отдельных целей
- AI генерация возвращает None при ошибках, но не прерывает процесс
- Все ошибки логируются с полной информацией

## Примеры использования API

### Программное использование (без CLI)

```python
from network_scanner.config.settings import Settings
from network_scanner.db.dao import create_sqlite_engine, init_db, get_session
from network_scanner.scan.runner import run_scan_for_tenant

# Загрузка конфигурации
settings = Settings.load()

# Инициализация БД
engine = create_sqlite_engine(settings.sqlite_path)
init_db(engine)

# Запуск сканирования
run_scan_for_tenant(
    settings=settings,
    tenant_name="ACME",
    mode="tcp",
    service_info=True,
    nuclei=True
)
```

### Работа с БД напрямую

```python
from network_scanner.db.dao import get_session, get_tenant_by_name, list_nuclei_scans, list_nuclei_findings

with get_session(engine) as session:
    tenant = get_tenant_by_name(session, "ACME")
    nuclei_scans = list_nuclei_scans(session, tenant=tenant)
    if nuclei_scans:
        latest_scan = nuclei_scans[0]
        findings = list_nuclei_findings(session, latest_scan)
        print(f"Found {len(findings)} findings")
```

## Зависимости

Основные зависимости (см. `requirements.txt`):
- `click` - CLI framework
- `sqlalchemy` - ORM для работы с БД
- `rich` - Форматирование вывода в консоль
- `fpdf2` - Генерация PDF
- `requests` - HTTP запросы (AI API, EPSS API)
- `lxml` - Парсинг XML (Nmap)
- `python-masscan` - Обертка для Masscan
- `python-dateutil` - Работа с датами

## Структура директорий данных

```
data/
├── activity.log                    # Общий лог всех операций
└── <tenant>/
    ├── <YYYYMMDD>/
    │   ├── masscan.json           # Результаты Masscan
    │   ├── nmap.xml                # Результаты Nmap
    │   ├── nuclei_<timestamp>.json # Результаты Nuclei (JSONL)
    │   ├── nuclei_<timestamp>.log # Лог Nuclei
    │   └── vulners_<ip>.xml        # Результаты nmap vulners
    └── reports/
        ├── <tenant>_last-scan_<timestamp>.pdf
        ├── <tenant>_diff-scans_<timestamp>.pdf
        ├── <tenant>_nuclei_<timestamp>.pdf
        └── <tenant>_nuclei_ai_<timestamp>.pdf
```

## Важные замечания для ИИ-агента

1. **Все даты в UTC**: Все datetime поля в БД используют UTC timezone
2. **CASCADE DELETE**: При удалении Tenant автоматически удаляются связанные Network, Scan, NucleiScan
3. **Уникальность**: Многие таблицы имеют составные уникальные ключи - проверяйте перед вставкой
4. **Логирование**: Все важные операции логируются, включая AI запросы
5. **Обработка ошибок**: Используйте try/except при работе с внешними командами (masscan, nmap, nuclei)
6. **Таймауты**: Nuclei сканирование имеет таймаут на цель (по умолчанию 1800 сек, настраивается)
7. **AI ограничения**: AI summary генерируется только для первых 100 находок
8. **PDF шрифты**: PDF использует системные шрифты, убедитесь что они доступны для поддержки кириллицы
9. **JSONL формат**: Nuclei результаты сохраняются в JSONL (newline-delimited JSON), не в JSON array
10. **Парсинг таблиц**: AI отчеты могут содержать markdown таблицы, которые нужно парсить отдельно

