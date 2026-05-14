# antiscan

Утилита для блокировки сканеров портов через iptables и ipset с поддержкой логирования и агрегации статистики. Поддерживает только IPv4.

Форк проекта [dotX12/traffic-guard](https://github.com/dotX12/traffic-guard).

## Содержание

- [О проекте](#о-проекте)
- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
  - [Автоматическая установка](#автоматическая-установка)
  - [Ручная установка](#ручная-установка)
- [Использование](#использование)
  - [Публичные списки](#публичные-списки)
  - [Примеры использования](#примеры-использования)
  - [Опции](#опции)
- [Удаление (uninstall)](#удаление-uninstall)
- [Логирование](#логирование)
  - [Конфигурация](#конфигурация)
  - [Файлы логов](#файлы-логов)
  - [Формат агрегированного CSV](#формат-агрегированного-csv)
  - [Лимиты логирования](#лимиты-логирования)
  - [Просмотр логов](#просмотр-логов)
- [Что создается в системе](#что-создается-в-системе)
- [Отличия от оригинала](#отличия-от-оригинала)
- [Лицензия](#лицензия)

---

## О проекте

**antiscan** блокирует весь трафик с известных IP-адресов сканеров на уровне сетевого фильтра (iptables/ipset), до того как пакеты достигнут ваших сервисов. Правила применяются при запуске и восстанавливаются после перезагрузки через `netfilter-persistent`.

При включённом логировании каждое заблокированное соединение записывается в CSV-файл с временем, IP, портом назначения и информацией об ASN (через whois).

## Требования

- Linux (проверялось на Debian 12/13)
- root-права
- `systemd`
- `iptables`, `ipset`, `netfilter-persistent`
- `rsyslog` — для логирования
- **UFW должен быть неактивен** — утилита использует `netfilter-persistent` напрямую и несовместима с UFW

---

## Быстрый старт

```bash
# 1. Установка
curl -fsSL https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash

# 2. Запуск с базовой защитой
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list

# 3. (Опционально) Проверка логов через несколько минут
tail -f /var/log/iptables-scanners-aggregate.csv
```

---

## Установка

### Автоматическая установка

```bash
curl -fsSL https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash
```

или

```bash
wget -qO- https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash
```

Скрипт автоматически определит архитектуру (amd64, 386, arm, arm64), скачает подходящий бинарник и установит его в `/usr/local/bin/antiscan-simple`.

### Ручная установка

1. Скачайте нужный бинарник из [последнего релиза](https://github.com/serj1974-maker/antiscan/releases/latest):
   - `antiscan-simple-linux-amd64` — для 64-битных систем
   - `antiscan-simple-linux-386` — для 32-битных систем
   - `antiscan-simple-linux-arm` — для ARM
   - `antiscan-simple-linux-arm64` — для ARM64

2. Установите:

```bash
sudo mv antiscan-simple-linux-* /usr/local/bin/antiscan-simple
sudo chmod +x /usr/local/bin/antiscan-simple
```

---

## Использование

Параметр `-u` обязателен — он задаёт URL со списком подсетей для блокировки. Можно указать несколько раз.

### Публичные списки

Готовые списки доступны в репозитории **[shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists/tree/main)**:

- `public/antiscanner.list` — список от [zakachkin/AntiScanner](https://github.com/zakachkin/AntiScanner)
- `public/government_networks.list` — подсети государственных организаций, проводящих массовое сканирование

### Примеры использования

Базовая блокировка:

```bash
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
```

С включённым логированием:

```bash
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

Собственный список:

```bash
# Файл со списком подсетей (по одной на строку)
cat > /tmp/my-blocklist.txt <<EOF
192.168.1.0/24
10.0.0.0/8
EOF

sudo antiscan-simple full -u file:///tmp/my-blocklist.txt
```

### Опции

| Флаг | Описание |
|------|----------|
| `-u, --urls` | URL для скачивания подсетей (обязательно, можно указать несколько раз) |
| `-l, --enable-logging` | Включить логирование заблокированных подключений |
| `--auto-update` | Включить автоматическое обновление списков по расписанию |
| `--update-interval` | Интервал обновления, например `24h`, `30m`, `7d` (по умолчанию: `24h`) |
| `--log-level` | Уровень логирования: debug, info, warn, error (по умолчанию: info) |

---

## Удаление (uninstall)

Команда `uninstall` пошагово удаляет все изменения, внесённые antiscan-simple:

- правила и цепочку `SCANNERS-BLOCK` из iptables
- набор `ipset` (`SCANNERS-BLOCK-V4`) и `/etc/ipset.conf`
- systemd-сервисы `antiscan-*` и их unit-файлы
- конфиги rsyslog/logrotate и скрипт агрегации

Что **не** делает uninstall по умолчанию:

- не удаляет системные пакеты (`iptables`, `ipset`, `netfilter-persistent`)
- не удаляет логи в `/var/log` (для этого используйте `--remove-logs`)

```bash
# Интерактивное удаление
sudo antiscan-simple uninstall

# Удаление без подтверждения
sudo antiscan-simple uninstall --yes

# Удаление с очисткой логов
sudo antiscan-simple uninstall --yes --remove-logs
```

---

## Логирование

### Конфигурация

При указании `--enable-logging` создаются:

1. **`/etc/rsyslog.d/10-iptables-scanners.conf`** — конфигурация rsyslog с кастомным шаблоном (RFC3339 timestamp)
2. **`/etc/logrotate.d/iptables-scanners`** — ротация логов (ежедневно, хранится 7 дней)
3. **`/usr/local/bin/antiscan-aggregate-logs.sh`** — скрипт агрегации
4. **`/etc/systemd/system/antiscan-aggregate.service`** — systemd service
5. **`/etc/systemd/system/antiscan-aggregate.timer`** — systemd timer (каждые 30 секунд)

### Файлы логов

- **`/var/log/iptables-scanners-ipv4.log`** — сырые логи IPv4 (обрабатываются таймером каждые 30 сек и очищаются)
- **`/var/log/iptables-scanners-aggregate.csv`** — CSV с историей заблокированных подключений

### Формат агрегированного CSV

Каждое заблокированное соединение пишется отдельной строкой. Дедупликация не производится.

```csv
DATETIME|IP_ADDRESS|ASN|NETNAME|PORT
2026-04-30 22:21:21|85.142.100.138|AS49505|JSCCYBEROK-NET|22
2026-04-30 22:21:45|1.2.3.4|AS12345|EXAMPLE-NET|443
```

**Поля:**

| Поле | Описание |
|------|----------|
| `DATETIME` | Время блокировки в локальной таймзоне (`YYYY-MM-DD HH:MM:SS`) |
| `IP_ADDRESS` | IP-адрес источника |
| `ASN` | Номер автономной системы (из whois RIPE) |
| `NETNAME` | Имя сети (из whois RIPE) |
| `PORT` | Порт назначения |

**Особенности:**

- whois-кэш сбрасывается раз в сутки; таймаут одного запроса — 3 секунды
- при первом запуске после обновления старый CSV (формат с `COUNT|LAST_SEEN`) пересоздаётся автоматически

### Лимиты логирования

- Максимум **10 записей в минуту** на каждый IP (rate-limit в iptables)

### Просмотр логов

```bash
# Последние события
tail -f /var/log/iptables-scanners-aggregate.csv

# Статус таймера агрегации
systemctl status antiscan-aggregate.timer

# Логи скрипта агрегации
journalctl -u antiscan-aggregate.service -f
```

---

## Что создается в системе

### iptables

- **Цепочка**: `SCANNERS-BLOCK`
- **Правила**:
  - `INPUT -j SCANNERS-BLOCK`
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V4 src -j DROP`
  - При включённом логировании — дополнительные правила с rate-limit перед DROP

### ipset

- **Набор**: `SCANNERS-BLOCK-V4` (hash:net, IPv4)
- **Конфигурация**: `/etc/ipset.conf`

### Автозагрузка

Правила сохраняются через `netfilter-persistent` в `/etc/iptables/rules.v4`.

### Docker

Если на хосте обнаружен Docker (docker CLI или `/var/run/docker.sock`), дополнительно создаётся:

- **`antiscan-docker-rules.service`** — инъектирует правило в цепочку `DOCKER-USER`
- **`antiscan-docker-rules.timer`** — повторяет инъекцию каждые 5 минут (цепочка сбрасывается при рестарте Docker)

---

## Отличия от оригинала

По сравнению с [dotX12/traffic-guard](https://github.com/dotX12/traffic-guard):

- **Только IPv4** — поддержка IPv6 и `ip6tables` удалена
- **Без UFW** — интеграция с UFW удалена; при обнаружении активного UFW установка прерывается с ошибкой; правила сохраняются только через `netfilter-persistent`
- **Docker** — цепочка `DOCKER-USER` настраивается только при обнаружении Docker; добавлен таймер для переинъекции правила каждые 5 минут
- **Формат CSV** — вместо дедуплицированных счётчиков (`COUNT|LAST_SEEN`) — полный дамп: одна строка на каждое заблокированное соединение с временем и портом
- **Timestamp** — rsyslog пишет RFC3339 timestamp; в CSV хранится как `YYYY-MM-DD HH:MM:SS` в локальной таймзоне
- **Тесты** — добавлено unit-покрытие для `state`, парсеров `status` и интервалов `updater`

---

## Лицензия

MIT

---
---

# antiscan (English)

Utility for blocking port scanners via iptables and ipset, with optional
connection logging and statistics aggregation. IPv4 only.

Fork of [dotX12/traffic-guard](https://github.com/dotX12/traffic-guard).

## Contents

- [About](#about)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Installation](#installation)
  - [Automatic install](#automatic-install)
  - [Manual install](#manual-install)
- [Usage](#usage)
  - [Public lists](#public-lists)
  - [Examples](#examples)
  - [Options](#options)
- [Uninstall](#uninstall)
- [Logging](#logging)
  - [Configuration](#configuration)
  - [Log files](#log-files)
  - [Aggregate CSV format](#aggregate-csv-format)
  - [Logging limits](#logging-limits)
  - [Viewing logs](#viewing-logs)
- [What gets installed](#what-gets-installed)
- [Differences from upstream](#differences-from-upstream)
- [License](#license)

---

## About

**antiscan** blocks traffic from known scanner IP ranges at the network filter
level (iptables/ipset), before packets reach your services. Rules are applied
at startup and restored across reboots via `netfilter-persistent`.

When logging is enabled, every blocked connection is appended to a CSV file
with timestamp, source IP, destination port, and ASN/network info (looked up
via whois).

## Requirements

- Linux (tested on Debian 12/13)
- root privileges
- `systemd`
- `iptables`, `ipset`, `netfilter-persistent`
- `rsyslog` — required when logging is enabled
- **UFW must be inactive** — this tool drives `netfilter-persistent` directly
  and is incompatible with UFW

---

## Quick start

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash

# 2. Run with a baseline blocklist
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list

# 3. (Optional) Check logs after a few minutes
tail -f /var/log/iptables-scanners-aggregate.csv
```

---

## Installation

### Automatic install

```bash
curl -fsSL https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash
```

or

```bash
wget -qO- https://raw.githubusercontent.com/serj1974-maker/antiscan/master/install.sh | sudo bash
```

The script detects the architecture (amd64, 386, arm, arm64), downloads the
matching binary, and installs it to `/usr/local/bin/antiscan-simple`.

### Manual install

1. Download the appropriate binary from the [latest release](https://github.com/serj1974-maker/antiscan/releases/latest):
   - `antiscan-simple-linux-amd64` — 64-bit systems
   - `antiscan-simple-linux-386` — 32-bit systems
   - `antiscan-simple-linux-arm` — ARM
   - `antiscan-simple-linux-arm64` — ARM64

2. Install:

```bash
sudo mv antiscan-simple-linux-* /usr/local/bin/antiscan-simple
sudo chmod +x /usr/local/bin/antiscan-simple
```

---

## Usage

`-u` is required and points to a URL containing one subnet per line. The flag
can be repeated to combine multiple lists.

### Public lists

Ready-to-use lists are published in
**[shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists/tree/main)**:

- `public/antiscanner.list` — sourced from [zakachkin/AntiScanner](https://github.com/zakachkin/AntiScanner)
- `public/government_networks.list` — subnets of government agencies known for mass scanning

### Examples

Basic blocking:

```bash
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
```

With logging enabled:

```bash
sudo antiscan-simple full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

Custom blocklist:

```bash
# One subnet per line
cat > /tmp/my-blocklist.txt <<EOF
192.168.1.0/24
10.0.0.0/8
EOF

sudo antiscan-simple full -u file:///tmp/my-blocklist.txt
```

### Options

| Flag | Description |
|------|-------------|
| `-u, --urls` | URL to download subnets from (required, repeatable) |
| `-l, --enable-logging` | Enable logging of blocked connections |
| `--auto-update` | Enable scheduled blocklist updates |
| `--update-interval` | Auto-update interval (e.g. `24h`, `30m`, `7d`); default `24h` |
| `--log-level` | Log level: `debug`, `info`, `warn`, `error` (default `info`) |

---

## Uninstall

`uninstall` reverses every change made by `antiscan-simple`:

- removes rules and the `SCANNERS-BLOCK` chain from iptables
- destroys the `SCANNERS-BLOCK-V4` ipset and `/etc/ipset.conf`
- stops, disables, and removes all `antiscan-*` systemd units
- removes rsyslog/logrotate configs and the aggregation script

What `uninstall` does **not** do by default:

- it does **not** remove system packages (`iptables`, `ipset`, `netfilter-persistent`)
- it does **not** remove `/var/log` log files (use `--remove-logs` for that)

```bash
# Interactive
sudo antiscan-simple uninstall

# Skip confirmation
sudo antiscan-simple uninstall --yes

# Also remove log files
sudo antiscan-simple uninstall --yes --remove-logs
```

---

## Logging

### Configuration

`--enable-logging` installs:

1. **`/etc/rsyslog.d/10-iptables-scanners.conf`** — rsyslog template (RFC3339 timestamp)
2. **`/etc/logrotate.d/iptables-scanners`** — log rotation (daily, 7 days retention)
3. **`/usr/local/bin/antiscan-aggregate-logs.sh`** — aggregation script
4. **`/etc/systemd/system/antiscan-aggregate.service`** — systemd service
5. **`/etc/systemd/system/antiscan-aggregate.timer`** — systemd timer (fires every 30 seconds)

### Log files

- **`/var/log/iptables-scanners-ipv4.log`** — raw IPv4 logs (drained every 30s by the timer)
- **`/var/log/iptables-scanners-aggregate.csv`** — historical record of blocked connections

### Aggregate CSV format

One row per blocked connection. No deduplication.

```csv
DATETIME|IP_ADDRESS|ASN|NETNAME|PORT
2026-04-30 22:21:21|85.142.100.138|AS49505|JSCCYBEROK-NET|22
2026-04-30 22:21:45|1.2.3.4|AS12345|EXAMPLE-NET|443
```

**Fields:**

| Field | Description |
|-------|-------------|
| `DATETIME` | Block time in local timezone (`YYYY-MM-DD HH:MM:SS`) |
| `IP_ADDRESS` | Source IP |
| `ASN` | Autonomous system number (whois RIPE) |
| `NETNAME` | Network name (whois RIPE) |
| `PORT` | Destination port |

**Notes:**

- the whois cache is invalidated daily; each lookup has a 3-second timeout
- if an older CSV (with `COUNT|LAST_SEEN` columns) is detected at startup,
  it is replaced automatically

### Logging limits

- At most **10 entries per minute** per source IP (iptables rate limit)

### Viewing logs

```bash
# Most recent events
tail -f /var/log/iptables-scanners-aggregate.csv

# Aggregation timer status
systemctl status antiscan-aggregate.timer

# Aggregation script logs
journalctl -u antiscan-aggregate.service -f
```

---

## What gets installed

### iptables

- **Chain**: `SCANNERS-BLOCK`
- **Rules**:
  - `INPUT -j SCANNERS-BLOCK`
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V4 src -j DROP`
  - Extra rate-limited LOG rule before DROP when logging is enabled

### ipset

- **Set**: `SCANNERS-BLOCK-V4` (hash:net, IPv4)
- **Persistence**: `/etc/ipset.conf`

### Boot persistence

Rules are saved via `netfilter-persistent` into `/etc/iptables/rules.v4`.

### Docker

When Docker is detected on the host (the `docker` CLI is in PATH or
`/var/run/docker.sock` exists), antiscan additionally creates:

- **`antiscan-docker-rules.service`** — injects the rule into the `DOCKER-USER` chain
- **`antiscan-docker-rules.timer`** — re-injects every 5 minutes (Docker resets this chain on restart)

---

## Differences from upstream

Versus [dotX12/traffic-guard](https://github.com/dotX12/traffic-guard):

- **IPv4 only** — IPv6 and `ip6tables` support has been removed
- **No UFW integration** — UFW support has been removed; if active UFW is
  detected, installation aborts with an error; rules are persisted only via
  `netfilter-persistent`
- **Docker** — the `DOCKER-USER` chain is configured only when Docker is
  detected; a periodic timer re-injects the rule every 5 minutes
- **CSV format** — instead of deduplicated counters (`COUNT|LAST_SEEN`),
  every blocked connection is appended with its timestamp and destination port
- **Timestamp** — rsyslog emits RFC3339; the aggregator stores `YYYY-MM-DD HH:MM:SS`
  in local time
- **Tests** — unit tests added for `state`, `status` parsers, and `updater` intervals

---

## License

MIT
