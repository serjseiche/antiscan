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
sudo traffic-guard full \
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

Скрипт автоматически определит архитектуру (amd64, 386, arm, arm64), скачает подходящий бинарник и установит его в `/usr/local/bin/traffic-guard`.

### Ручная установка

1. Скачайте нужный бинарник из [последнего релиза](https://github.com/serj1974-maker/antiscan/releases/latest):
   - `traffic-guard-linux-amd64` — для 64-битных систем
   - `traffic-guard-linux-386` — для 32-битных систем
   - `traffic-guard-linux-arm` — для ARM
   - `traffic-guard-linux-arm64` — для ARM64

2. Установите:

```bash
sudo mv traffic-guard-linux-* /usr/local/bin/traffic-guard
sudo chmod +x /usr/local/bin/traffic-guard
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
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
```

С включённым логированием:

```bash
sudo traffic-guard full \
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

sudo traffic-guard full -u file:///tmp/my-blocklist.txt
```

### Опции

| Флаг | Описание |
|------|----------|
| `-u, --urls` | URL для скачивания подсетей (обязательно, можно указать несколько раз) |
| `-l, --enable-logging` | Включить логирование заблокированных подключений |
| `--log-level` | Уровень логирования: debug, info, warn, error (по умолчанию: info) |

---

## Удаление (uninstall)

Команда `uninstall` пошагово удаляет все изменения, внесённые TrafficGuard:

- правила и цепочку `SCANNERS-BLOCK` из iptables
- набор `ipset` (`SCANNERS-BLOCK-V4`) и `/etc/ipset.conf`
- systemd-сервисы `antiscan-*` и их unit-файлы
- конфиги rsyslog/logrotate и скрипт агрегации

Что **не** делает uninstall по умолчанию:

- не удаляет системные пакеты (`iptables`, `ipset`, `netfilter-persistent`)
- не удаляет логи в `/var/log` (для этого используйте `--remove-logs`)

```bash
# Интерактивное удаление
sudo traffic-guard uninstall

# Удаление без подтверждения
sudo traffic-guard uninstall --yes

# Удаление с очисткой логов
sudo traffic-guard uninstall --yes --remove-logs
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
