## Network Scanner

Инструмент для быстрого сканирования сетей: быстрый проход Masscan (через библиотеку python-masscan) с последующим уточнением результатов в Nmap и сохранением в SQLite.

### Возможности
- **Быстрое обнаружение хостов и портов** с помощью Masscan (через `python-masscan`).
- **Подтверждение и обогащение сервисов** с помощью Nmap (XML → парсинг в БД).
- **Хранение результатов** в SQLite, удобные команды CLI для управления арендаторами и сетями.

### Требования
- Python 3.10+
- Системные бинарники:
  - `masscan` (должен быть установлен и доступен в PATH)
  - `nmap` (должен быть установлен и доступен в PATH)

Установка `masscan`/`nmap` зависит от вашей ОС (например, на macOS через Homebrew: `brew install masscan nmap`).

### Установка
```bash
git clone /Users/dmitry/git/network-scanner
cd /Users/dmitry/git/network-scanner
pip install -r requirements.txt
```

### Конфигурация
Параметры читаются из переменных окружения или YAML-файла.

- Переменные окружения:
  - `NETWORK_SCANNER_DB` — путь к SQLite (по умолчанию `./scanner.sqlite`)
  - `NETWORK_SCANNER_DATA` — директория данных/артефактов (по умолчанию `./data`)
  - `NETWORK_SCANNER_RATE` — скорость сканирования masscan (по умолчанию `2048`)
  - `NETWORK_SCANNER_MASSCAN` — путь к бинарнику masscan (по умолчанию `masscan`)
  - `NETWORK_SCANNER_NMAP` — путь к бинарнику nmap (по умолчанию `nmap`)

- YAML-файл (ключи опциональны):
```yaml
sqlite_path: ./scanner.sqlite
data_dir: ./data
rate: 4096
masscan_path: masscan
nmap_path: nmap
```

Передать путь к YAML можно опцией `--config` (см. ниже).

### CLI
Запуск CLI:
```bash
python cli.py --help
python cli.py -h
```

Основные команды:
- Инициализация БД:
```bash
python cli.py init-db-cmd
```

- Добавить арендатора:
```bash
python cli.py add-tenant-cmd --name ACME --desc "Internal networks"
```

- Добавить сеть для арендатора:
```bash
python cli.py add-network-cmd --tenant ACME --cidr 10.0.0.0/24
```

- Список арендаторов:
```bash
python cli.py list-tenants-cmd
```

- Список сетей (опционально фильтр по арендатору):
```bash
python cli.py list-networks-cmd --tenant ACME
```

- Сканирование:
```bash
python cli.py scan-cmd --tenant ACME --mode tcp
# или
python cli.py scan-cmd --tenant ACME --mode all
```

Пример с конфигом:
```bash
python cli.py --config ./settings.yaml scan-cmd --tenant ACME
```

Примечания по опциям:
- `--mode tcp` — сканирует TCP-порты (по умолчанию).
- `--mode all` — включает TCP-диапазон и подмножество UDP-портов (53, 69, 123, 161).

### Как это работает
1. Быстрый проход выполняется через `python-masscan`, где задаются цели (CIDR/адреса), порты и ограничение скорости (`--rate`).
2. Результаты `masscan` (хосты и открытые TCP/UDP порты) передаются в `nmap` для подтверждения и обогащения.
3. Nmap сохраняет XML в директорию данных, XML парсится и записывается в SQLite.

Артефакты и отчеты складываются в `NETWORK_SCANNER_DATA/<tenant>/<YYYYMMDD>/`.

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


