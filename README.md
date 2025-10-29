## Network Scanner

Инструмент для быстрого TCP‑сканирования: быстрый проход Masscan (через библиотеку python-masscan) с последующим уточнением результатов в Nmap и сохранением в SQLite.

### Возможности
- **Быстрое обнаружение хостов и TCP‑портов** с помощью Masscan (через `python-masscan`).
- **Подтверждение и обогащение TCP‑сервисов** с помощью Nmap (XML → парсинг в БД; опционально `-sV`).
- **Хранение результатов** в SQLite, удобные команды CLI для управления арендаторами, сетями и результатами.

### Требования
- Python 3.10+
- Установленный бинарник `nmap` в PATH (например, на macOS: `brew install nmap`).

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

Пример `.env`:
```ini
sqlite_path=./scanner.sqlite
data_dir=./data
rate=4096
nmap_path=nmap
tcp_ports_default=22,80,443
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

# Определение названий и версий сервисов (-sV)
python cli.py scan --tenant ACME --mode tcp --service-info
```

Пример с конфигом:
```bash
python cli.py --config ./settings.yaml scan --tenant ACME
```

Примечания по опциям:
- `--mode tcp` — сканирует TCP‑порты (по умолчанию). Список берётся из настроек арендатора или `tcp_ports_default`.
- `--mode all` — сканирует полный TCP‑диапазон `1-65535`.
- `--service-info` — добавляет `-sV` к `nmap` для определения названий и версий сервисов.

### Как это работает
1. Быстрый проход выполняется через `python-masscan` (TCP), где задаются цели (CIDR/адреса), порты и ограничение скорости (`--rate`).
2. Результаты `masscan` (хосты и открытые TCP‑порты) передаются в `nmap` для подтверждения и обогащения (опционально `-sV`).
3. Nmap сохраняет XML в директорию данных, XML парсится и записывается в SQLite.

Артефакты и отчеты складываются в `data/<tenant>/<YYYYMMDD>/`:
- `masscan.json` — полный JSON‑ответ Masscan
- `nmap.xml` — результат Nmap (для парсинга в БД)

### Тонкости и ограничения
- `python-masscan` требует установленный системный бинарник `masscan`.
- Для высоких значений `--rate` необходимы соответствующие права и конфигурация сети.
- На некоторых ОС может потребоваться запуск с повышенными привилегиями для сырого трафика.

### Разработка
Запуск линтера/форматирования зависит от ваших инструментов. В проекте используется `ruff` (см. `pyproject.toml`).

### Ссылки
- Репозиторий библиотеки Masscan для Python: [python-masscan](https://github.com/MyKings/python-masscan.git)

### Лицензия
См. лицензию соответствующих зависимостей. Использование `masscan`/`nmap` подчиняется их лицензиям.


