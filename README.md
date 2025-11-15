## Network Scanner

Инструмент для быстрого TCP‑сканирования: быстрый проход Masscan (через библиотеку python-masscan) с последующим уточнением результатов в Nmap и сохранением в SQLite.

### Возможности
- **Быстрое обнаружение хостов и TCP‑портов** с помощью Masscan (через `python-masscan`).
- **Подтверждение и обогащение TCP‑сервисов** с помощью Nmap (XML → парсинг в БД; опционально `-sV`).
- **Веб-сканирование уязвимостей** с помощью Nuclei для обнаружения известных уязвимостей в веб-сервисах.
- **AI-генерация отчетов** — автоматическая генерация аналитических отчетов на основе результатов Nuclei сканирования (опционально).
- **Хранение результатов** в SQLite, удобные команды CLI для управления арендаторами, сетями и результатами.
- **Исключения хостов/подсетей на тенанта** — исключаются из сканирования Masscan и Nmap (`--exclude`).
- **Экспорт отчетов в PDF** с поддержкой кириллицы и автоматическим парсингом markdown таблиц.

### Требования
- Python 3.10+
- Установленные бинарники `nmap`, `masscan` и `nuclei` в PATH (например, на macOS: `brew install nmap masscan nuclei`).
- Python-зависимости из `requirements.txt` (включая `fpdf2` для экспорта PDF).
- Для AI-генерации отчетов: настройка AI API (см. раздел Конфигурация).

### Установка
```bash
git clone /Users/dmitry/git/network-scanner
cd /Users/dmitry/git/network-scanner
pip install -r requirements.txt
```

### Конфигурация
Параметры читаются из (в порядке приоритета):
1) Файл, указанный `--config` (формат key=value, одна пара на строку)
2) Файл `.env` в корне проекта (если `--config` не указан)
3) Переменные окружения

Поддерживаемые ключи/переменные:
- Путь к SQLite: `sqlite_path` | `NETWORK_SCANNER_DB` | `SQLITE_PATH` (по умолчанию `./scanner.sqlite`)
- Директория данных: `data_dir` | `NETWORK_SCANNER_DATA` | `DATA_DIR` (по умолчанию `./data`)
- Скорость masscan: `rate` | `NETWORK_SCANNER_RATE` | `RATE` (по умолчанию `2048`)
- Путь к `nmap`: `nmap_path` | `NETWORK_SCANNER_NMAP` | `NMAP_PATH` (по умолчанию `nmap`)
- TCP‑порты по умолчанию: `tcp_ports_default` | `NETWORK_SCANNER_TCP_PORTS_DEFAULT` | `TCP_PORTS_DEFAULT`
- Исключаемые TCP‑порты из nmap: `exclude_ports` | `NETWORK_SCANNER_EXCLUDE_PORTS` | `EXCLUDE_PORTS`
- EPSS API URL: `epss_api_url` | `NETWORK_SCANNER_EPSS_API_URL` | `EPSS_API_URL` (по умолчанию `https://api.first.org/data/v1/epss`)
- EPSS значимый порог: `epss_significant_threshold` | `NETWORK_SCANNER_EPSS_SIGNIFICANT_THRESHOLD` | `EPSS_SIGNIFICANT_THRESHOLD` (по умолчанию `0.1`)
- **Nuclei настройки:**
  - Путь к `nuclei`: `nuclei_path` | `NUCLEI_PATH` (по умолчанию `nuclei`)
  - Шаблоны Nuclei: `nuclei_templates` | `NUCLEI_TEMPLATES` (по умолчанию `http/cves,ssl`)
  - Таймаут Nuclei (сек): `nuclei_timeout_sec` | `NUCLEI_TIMEOUT_SEC` (по умолчанию `1800`)
  - SOCKS5 прокси для Nuclei: `nuclei_socks5_proxy` | `NUCLEI_SOCKS5_PROXY` (опционально)
- **AI настройки (опционально):**
  - AI API URL: `ai_api_url` | `AI_API_URL` (например, `https://api.openai.com/v1/chat/completions`)
  - AI API ключ: `ai_api_key` | `AI_API_KEY`
  - AI модель: `ai_model` | `AI_MODEL` (по умолчанию `gpt-4o-mini`)
  - Включить AI: `ai_enabled` | `AI_ENABLED` (по умолчанию `false`, установите `true` для включения)
  - Температура AI: `ai_temperature` | `AI_TEMPERATURE` (по умолчанию `0.4`)
  - Максимум токенов: `ai_max_tokens` | `AI_MAX_TOKENS` (по умолчанию `1200`)

Исключения адресов/подсетей на уровне арендатора настраиваются через CLI (см. ниже). Они применяются к обоим сканерам: Masscan (`--exclude`) и Nmap (`--exclude`).

Пример `.env`:
```ini
sqlite_path=./scanner.sqlite
data_dir=./data
rate=4096
nmap_path=nmap
tcp_ports_default=22,80,443
exclude_ports=5900,12345
epss_api_url=https://api.first.org/data/v1/epss
epss_significant_threshold=0.1

# Nuclei настройки
nuclei_path=nuclei
nuclei_templates=http/cves,ssl
nuclei_timeout_sec=1800

# AI настройки (опционально)
ai_enabled=true
ai_api_url=https://api.openai.com/v1/chat/completions
ai_api_key=sk-...
ai_model=gpt-4o-mini
ai_temperature=0.4
ai_max_tokens=1200
```

### CLI
Запуск CLI:
```bash
python cli.py --help
python cli.py -h
```

Основные команды:
- Инициализация БД:
```bash
python cli.py init-db
```

- Добавить арендатора:
```bash
python cli.py add-tenant --name ACME --desc "Internal networks"
```

- Добавить сеть для арендатора:
```bash
python cli.py add-network --tenant ACME --cidr 10.0.0.0/24
```

- Список арендаторов:
```bash
python cli.py list-tenants
```

- Список сетей (опционально фильтр по арендатору):
```bash
python cli.py list-networks --tenant ACME
```

- Сканирование:
```bash
python cli.py scan --tenant ACME --mode tcp
# или полный диапазон TCP
python cli.py scan --tenant ACME --mode all

# Определение названий и версий сервисов (-сV)
python cli.py scan --tenant ACME --mode tcp --service-info

# Сканирование с обнаружением уязвимостей (--script vulners)
python cli.py scan --tenant ACME --mode tcp --service-info --vulners

# Сканирование с автоматическим запуском Nuclei веб-сканирования
python cli.py scan --tenant ACME --mode tcp --service-info --nuclei

# Сканирование по списку целей из файла (masscan -iL)
# В этом режиме цели берутся из файла, а не из БД тенанта
python cli.py scan --tenant ACME --mode tcp --iL ./targets.txt

# Сканирование всех тенантов по очереди с учётом их настроек
python cli.py scan --all-tenants --mode tcp

# Переопределить скорость masscan на один запуск
python cli.py scan --tenant ACME --mode tcp --rate 5000
```

- Управление исключениями (адреса/подсети/хостнеймы), применяются к Masscan и Nmap через `--exclude`:
```bash
# Показать исключения для арендатора
python cli.py list-excludes --tenant ACME

# Добавить исключение (IP/CIDR/hostname/range)
python cli.py add-exclude --tenant ACME --target 10.0.0.5
python cli.py add-exclude --tenant ACME --target 10.0.1.0/24
python cli.py add-exclude --tenant ACME --target example.org

# Изменить исключение по ID
python cli.py edit-exclude --id 3 --target 10.0.2.0/24

# Удалить исключение по ID
python cli.py delete-exclude --id 3 --yes
```

- Просмотр последнего скана и экспорт в PDF:
```bash
python cli.py show-last-scan --tenant ACME
python cli.py show-last-scan --tenant ACME --pdf  # PDF отчёт в data/<tenant>/reports
```

- Сравнение двух последних сканов и экспорт в PDF:
```bash
python cli.py diff-scans --tenant ACME
python cli.py diff-scans --tenant ACME --pdf  # PDF отчёт в data/<tenant>/reports
```

- Поиск уязвимостей для последнего скана:
```bash
# Если уязвимости уже есть - обновит EPSS и пересчитает вероятность взлома
# Если уязвимостей нет - запустит nmap --script vulners
python cli.py search-vulners --tenant ACME
```

- Nuclei веб-сканирование:
```bash
# Запустить Nuclei сканирование для последнего скана тенанта
python cli.py scan-nuclei --tenant ACME

# Запустить Nuclei сканирование для конкретного scan_id
python cli.py scan-nuclei --tenant ACME --scan-id 123

# Просмотр результатов Nuclei сканирования
python cli.py show-nuclei --tenant ACME

# Просмотр конкретного Nuclei сканирования
python cli.py show-nuclei --tenant ACME --nuclei-scan-id 5

# Просмотр с экспортом в PDF
python cli.py show-nuclei --tenant ACME --pdf

# Удаление Nuclei сканирования
python cli.py delete-nuclei --tenant ACME --nuclei-scan-id 5 --yes
```

- AI-генерация отчетов:
```bash
# Генерация AI summary для последнего Nuclei сканирования
python cli.py ai-nuclei --tenant ACME

# Генерация AI summary с экспортом в PDF
python cli.py ai-nuclei --tenant ACME --pdf
```

Пример с конфигом:
```bash
python cli.py --config ./settings.yaml scan --tenant ACME
```

Примечания по опциям:
- `--mode tcp` — сканирует TCP‑порты (по умолчанию). Список берётся из настроек арендатора или `tcp_ports_default`.
- `--mode all` — сканирует полный TCP‑диапазон `1-65535`.
- `--service-info` — добавляет `-sV` к `nmap` для определения названий и версий сервисов.
- Исключения на уровне арендатора применяются автоматически: к Masscan (`--exclude`) и к Nmap (`--exclude`).
- `exclude_ports` — глобальный параметр (конфиг/ENV) для Nmap `--exclude-ports` (исключение TCP‑портов).
- `--iL <file>` — передаёт список целей в Masscan через `-iL <file>`. В этом режиме цели не берутся из сетей в БД.
- `--all-tenants` — последовательно запускает сканирование для всех арендаторов с их индивидуальными настройками (сети, исключения и т. п.). Несовместимо с `--iL`.
- `--rate <value>` — переопределяет скорость masscan для текущего запуска (по умолчанию берётся `rate` из настроек).
- `--vulners` — включает nmap скрипт `vulners` для обнаружения CVE (требует `--service-info`). Результаты сохраняются в БД с EPSS оценками и расчетом вероятности взлома.
- `--nuclei` — запускает Nuclei веб-сканирование после завершения nmap. Автоматически определяет HTTP/HTTPS сервисы и сканирует их на известные уязвимости.
- `--pdf` (в командах `show-last-scan`, `diff-scans`, `show-nuclei`, `ai-nuclei`) — сохраняет PDF-отчёт в директорию `data/<tenant>/reports/`, имя файла содержит название тенанта, тип отчёта и время сканирования. PDF поддерживает кириллицу и автоматически парсит markdown таблицы из AI отчетов.
- `search-vulners` — команда для поиска уязвимостей в последнем скане. Если уязвимости уже есть — обновляет EPSS и пересчитывает вероятность взлома. Если нет — запускает nmap --script vulners.
- `scan-nuclei` — запускает Nuclei сканирование для существующего скана без повторного запуска masscan/nmap. Использует результаты последнего скана или указанного `--scan-id`.
- `show-nuclei` — отображает результаты Nuclei сканирования. Показывает метаданные сканирования, статистику по серьезности находок и детальный список уязвимостей. Если доступен AI summary — отображает его.
- `ai-nuclei` — генерирует AI summary для последнего Nuclei сканирования. Требует настройки AI API (см. Конфигурация). Все запросы и ответы к AI API логируются в `data/activity.log`.

### Как это работает
1. Быстрый проход выполняется через `python-masscan` (TCP), где задаются цели (CIDR/адреса), порты и ограничение скорости (`--rate`). При наличии исключений арендатора — используются `--exclude`.
2. Результаты `masscan` (хосты и открытые TCP‑порты) передаются в `nmap` для подтверждения и обогащения (опционально `-sV`). При наличии исключений арендатора — используются `--exclude`. Если задан `exclude_ports` — добавляется `--exclude-ports`.
3. Nmap сохраняет XML в директорию данных, XML парсится и записывается в SQLite.
4. При использовании `--nuclei` или команды `scan-nuclei`: автоматически определяются HTTP/HTTPS сервисы из результатов nmap, и для каждого запускается Nuclei сканирование на известные уязвимости. Результаты сохраняются в БД и JSON файлы.
5. Если `ai_enabled=true`: после завершения Nuclei сканирования автоматически генерируется AI summary с анализом находок. Все запросы к AI API логируются в `data/activity.log`.

Артефакты и отчеты складываются в `data/<tenant>/<YYYYMMDD>/`:
- `masscan.json` — полный JSON‑ответ Masscan
- `nmap.xml` — результат Nmap (для парсинга в БД)
- `nuclei_<timestamp>.json` — результаты Nuclei сканирования (JSONL формат)
- `nuclei_<timestamp>.log` — лог выполнения Nuclei сканирования
- PDF-отчёты (если экспортированы через `--pdf`) сохраняются в `data/<tenant>/reports/`:
  - `{tenant}_last-scan_{timestamp}.pdf` — отчет по последнему скану
  - `{tenant}_diff-scans_{timestamp}.pdf` — сравнение двух последних сканов
  - `{tenant}_nuclei_{timestamp}.pdf` — отчет по Nuclei сканированию
  - `{tenant}_nuclei_ai_{timestamp}.pdf` — AI отчет по Nuclei сканированию
- `data/activity.log` — общий лог всех операций, включая запросы к AI API

### Тонкости и ограничения
- `python-masscan` требует установленный системный бинарник `masscan`.
- Для высоких значений `--rate` необходимы соответствующие права и конфигурация сети.
- На некоторых ОС может потребоваться запуск с повышенными привилегиями для сырого трафика.
- `exclude_ports` — (список через запятую) эти порты будут исключены nmap, аргумент `--exclude-ports`. Можно задать через переменные окружения или конфиг-файл. Если не задан — не применяется.
- **Nuclei:** Требует установленный бинарник `nuclei` в PATH. Nuclei автоматически определяет HTTP/HTTPS сервисы на основе результатов nmap и сканирует их. Для больших сетей сканирование может занять значительное время (настраивается через `nuclei_timeout_sec`).
- **AI генерация:** Требует настройки AI API (URL и ключ). Все запросы к AI API логируются в `data/activity.log` с деталями запросов и ответов. AI summary генерируется автоматически после завершения Nuclei сканирования (если `ai_enabled=true`), или может быть запрошен вручную через команду `ai-nuclei`.
- **PDF экспорт:** PDF отчеты поддерживают кириллицу через автоматическое использование системных Unicode шрифтов (Arial Unicode на macOS, DejaVu Sans на Linux). Markdown таблицы из AI отчетов автоматически парсятся и отображаются как нормальные PDF таблицы.

### Разработка
Запуск линтера/форматирования зависит от ваших инструментов. В проекте используется `ruff` (см. `pyproject.toml`).

### Ссылки
- Репозиторий библиотеки Masscan для Python: [python-masscan](https://github.com/MyKings/python-masscan.git)

### Лицензия
См. лицензию соответствующих зависимостей. Использование `masscan`/`nmap` подчиняется их лицензиям.


