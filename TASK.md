# antiscan — Task Specification

## 1. Project Overview

**antiscan** — утилита для блокировки сканеров портов через iptables + ipset.
Форк [dotX12/traffic-guard](https://github.com/dotX12/traffic-guard).

- Язык: Go 1.25
- Модуль: `github.com/serjseiche/antiscan`
- Бинарник: `antiscan-simple`, устанавливается в `/usr/local/bin`
- ОС: Linux (Debian 12/13)
- Зависимости: `spf13/cobra`, `rs/zerolog` (минимальные внешние зависимости)

### Принцип работы

1. Скачивание списков подсетей с URL
2. Создание ipset-набора `SCANNERS-BLOCK-V4`
3. Создание iptables-цепочки `SCANNERS-BLOCK` с правилами DROP
4. Линковка цепочки к `INPUT`
5. Сохранение правил через `netfilter-persistent` для восстановления после перезагрузки

---

## 2. Команды CLI

### `full` — полная установка

```
antiscan-simple full -u <url> [-u <url>...] [--enable-logging] [--auto-update] [--update-interval=<duration>]
```

Последовательность:

1. Проверка root-прав
2. Проверка отсутствия UFW
3. Проверка зависимостей: `iptables`, `ipset`, `netfilter-persistent`
4. Если `--enable-logging` — проверка `whois`, `rsyslog`
5. Скачивание списков подсетей (до 50 MB на URL, таймаут 30 с, IPv6 пропускаются, дубликаты исключаются)
6. Создание/сброс ipset `SCANNERS-BLOCK-V4` (hash:net, hashsize 1024, maxelem 65536)
7. Заполнение ipset подсетями
8. Создание/сброс iptables-цепочки `SCANNERS-BLOCK`
9. Добавление правил: ESTABLISHED/RELATED → RETURN (поз. 1), опционально LOG (поз. 2), DROP (в конец)
10. Линковка `SCANNERS-BLOCK` к `INPUT` (поз. 1)
11. Если Docker обнаружен — инъекция DROP-правила в `DOCKER-USER`
12. Если `--enable-logging` — настройка rsyslog, logrotate, скрипта агрегации, systemd-таймера
13. Сохранение ipset в `/etc/ipset.conf`
14. Создание `antiscan-ipset-restore.service`
15. Сохранение iptables через `netfilter-persistent` → `/etc/iptables/rules.v4`
16. Сохранение state-файла `/etc/antiscan-simple/config.json`
17. Если `--auto-update` — настройка `antiscan-simple-update.service` + timer

### `update` — обновление списков

```
antiscan-simple update
```

1. Проверка root-прав
2. Загрузка сохранённого state-файла
3. Скачивание списков заново
4. Если результат пуст — отказ (сохранение предыдущего состояния)
5. Сброс и заполнение ipset
6. Сохранение `/etc/ipset.conf`
7. Проверка, активна ли цепочка (warning если нет)
8. Обновление `last_update` в state-файле

### `status` — проверка состояния

```
antiscan-simple status
```

Выводит:

- Статус защиты (active/inactive)
- Прикреплённые цепочки (INPUT, DOCKER-USER)
- Размер ipset-наборов
- Источники (URL из state-файла)
- Время последнего обновления
- Количество заблокированных пакетов

### `uninstall` — полное удаление

```
antiscan-simple uninstall [--yes] [--remove-logs]
```

1. Подтверждение (интерактивное или `--yes`)
2. Остановка и отключение всех `antiscan-*` systemd-юнитов
3. Удаление jump-правила из `INPUT`
4. Удаление DROP-правила из `DOCKER-USER`
5. Сброс и удаление цепочки `SCANNERS-BLOCK`
6. Сброс и удаление ipset `SCANNERS-BLOCK-V4`
7. Удаление `/etc/ipset.conf`
8. Удаление всех systemd unit-файлов, rsyslog-конфига, logrotate-конфига, скрипта агрегации
9. Удаление state-файла и пустой директории `/etc/antiscan-simple`
10. `daemon-reload`, рестарт rsyslog (если активен)
11. Сохранение пустого состояния через `netfilter-persistent`

---

## 3. State-файл

- Путь: `/etc/antiscan-simple/config.json`
- Сохраняется атомарно (запись в `.tmp`, затем `rename`)

```json
{
  "urls": ["https://..."],
  "enable_logging": true,
  "auto_update": true,
  "update_interval": "24h",
  "last_update": "2026-05-27T12:00:00Z"
}
```

- Пакет: `internal/state`
- `configDir` — переменная, переопределяется в тестах

---

## 4. Ipset

### Набор

| Имя | Тип | Family | HashSize | MaxElem |
|-----|-----|--------|----------|---------|
| `SCANNERS-BLOCK-V4` | hash:net | inet | 1024 | 65536 |

### Файлы

- `/etc/ipset.conf` — сохранённый дамп (`ipset save`)

### Systemd

- `antiscan-ipset-restore.service` — восстанавливает ipset при загрузке (`Before=netfilter-persistent.service`)

---

## 5. Iptables

### Цепочка

- Имя: `SCANNERS-BLOCK`
- Таблица: filter

### Порядок правил

1. ESTABLISHED/RELATED → RETURN (conntrack)
2. (если logging) LOG с rate-limit 10/min, burst 5
3. DROP — `-m set --match-set SCANNERS-BLOCK-V4 src -j DROP`

### Привязка

- `INPUT -j SCANNERS-BLOCK` (позиция 1)

### Сохранение

- `netfilter-persistent save` → `/etc/iptables/rules.v4`

---

## 6. Docker Integration

- Docker детектится по наличию бинарника `docker` или файла `/var/run/docker.sock`
- Правило `-m set --match-set SCANNERS-BLOCK-V4 src -j DROP` вставляется в цепочку `DOCKER-USER` (поз. 1)
- Если цепочка `DOCKER-USER` отсутствует — создаётся с RETURN-правилом в конце

### Systemd

- `antiscan-docker-rules.service` — oneshot, `After=docker.service`, переинъекция правила при старте Docker
- `antiscan-docker-rules.timer` — каждые 5 минут (Docker может сбросить правила при рестарте)

---

## 7. Logging (`--enable-logging`)

### Rsyslog

- Конфиг: `/etc/rsyslog.d/10-iptables-scanners.conf`
- Шаблон: RFC3339 timestamp
- Фильтр: сообщения с `ANTISCAN-v4:` → пишутся в `/var/log/iptables-scanners-ipv4.log`

### Logrotate

- Конфиг: `/etc/logrotate.d/iptables-scanners`
- `*.log` — daily, rotate 7, сжатие, postrotate rsyslog-rotate
- `aggregate.csv` — weekly, rotate 4, сжатие

### Скрипт агрегации

- Путь: `/usr/local/bin/antiscan-aggregate-logs.sh`
- Частота: каждые 30 секунд (systemd timer)
- Действия:
  1. Атомарное перемещение `iptables-scanners-ipv4.log` во временный файл
  2. Разбор каждой строки: SRC= → IP, DPT= → порт
  3. WHOIS-запрос к whois.ripe.net (таймаут 3 с, кэш на 1 день) → ASN + NETNAME
  4. Добавление строки в `/var/log/iptables-scanners-aggregate.csv`

### Формат CSV

```
DATETIME|IP_ADDRESS|ASN|NETNAME|PORT
2026-04-30 22:21:21|85.142.100.138|AS49505|JSCCYBEROK-NET|22
```

### Rate-limit

- Не более 10 LOG-записей в минуту на одно совпадение в iptables

---

## 8. Auto-Update (`--auto-update`)

### Парсинг интервала

Поддерживаемые форматы:

- `7d` — дни
- `24h` — часы
- `30m` — минуты
- `90s` — секунды
- `1h30m` — комбинированные (через `time.ParseDuration`)

### Systemd

- `antiscan-simple-update.service` — запускает `antiscan-simple update`
- `antiscan-simple-update.timer` — `OnBootSec=15min`, `OnUnitActiveSec=<interval>`, `Persistent=true`

---

## 9. Systemd Units

| Unit | Тип | Назначение |
|------|-----|-----------|
| `antiscan-ipset-restore.service` | oneshot | Восстановление ipset при загрузке |
| `antiscan-aggregate.service` | oneshot | Агрегация логов (run на каждый тик таймера) |
| `antiscan-aggregate.timer` | timer | Каждые 30 секунд |
| `antiscan-simple-update.service` | oneshot | Обновление списков |
| `antiscan-simple-update.timer` | timer | `OnUnitActiveSec=<interval>` |
| `antiscan-docker-rules.service` | oneshot | Инъекция правила в DOCKER-USER после старта Docker |
| `antiscan-docker-rules.timer` | timer | Каждые 5 минут |

---

## 10. File Paths

| Файл | Назначение |
|------|-----------|
| `/etc/antiscan-simple/config.json` | State-файл |
| `/etc/ipset.conf` | Дамп ipset |
| `/etc/iptables/rules.v4` | Сохранённые iptables-правила |
| `/etc/rsyslog.d/10-iptables-scanners.conf` | Rsyslog-конфиг |
| `/etc/logrotate.d/iptables-scanners` | Logrotate-конфиг |
| `/usr/local/bin/antiscan-aggregate-logs.sh` | Скрипт агрегации |
| `/usr/local/bin/antiscan-simple` | Бинарник |
| `/etc/systemd/system/antiscan-ipset-restore.service` | Systemd ipset-restore |
| `/etc/systemd/system/antiscan-aggregate.service` | Systemd агрегация |
| `/etc/systemd/system/antiscan-aggregate.timer` | Timer агрегации |
| `/etc/systemd/system/antiscan-simple-update.service` | Systemd update |
| `/etc/systemd/system/antiscan-simple-update.timer` | Timer update |
| `/etc/systemd/system/antiscan-docker-rules.service` | Systemd Docker rules |
| `/etc/systemd/system/antiscan-docker-rules.timer` | Timer Docker rules |
| `/var/log/iptables-scanners-ipv4.log` | Сырые логи |
| `/var/log/iptables-scanners-aggregate.csv` | Агрегированный CSV |

---

## 11. Build & Release

### Сборка

```bash
go build -ldflags="-X main.version=<tag>" -o antiscan-simple cmd/main.go
```

### Релиз (GitHub Actions)

- Триггер: создание релиза
- Платформы: `linux/amd64`, `linux/arm64`, `linux/arm`, `linux/386`
- Артефакты: бинарники + `checksums.txt`
- Действие: `softprops/action-gh-release@v2`

### Установка (`install.sh`)

- Детект OS/arch
- Скачивание через curl или wget
- Установка в `/usr/local/bin`
- Опция `--dev` для pre-release