# Задание: улучшения traffic-guard

## Контекст проекта

`traffic-guard` — Go-утилита, которая блокирует сканеры портов через `iptables` + `ipset`. Качает списки подсетей по URL, заливает в `ipset`-наборы `SCANNERS-BLOCK-V4/V6`, навешивает правила на `INPUT` (или `ufw-before-input`, если активен UFW). Опционально логирует заблокированные подключения через rsyslog + systemd-таймер с bash-агрегатором (whois → CSV).

Архитектура: `cmd/main.go` (cobra), сервисы в `internal/service/` (CommandService, IptablesService, IpsetService, Downloader, InstallerService, LoggingService, UninstallerService).

## Задачи (в порядке выполнения)

Делай задачи по одной. После каждой — `go build ./...` + `go vet ./...` должны проходить. Не переходи к следующей задаче без подтверждения.

---

### Задача 1. Убрать автоинсталляцию системных пакетов

**Файлы:** `internal/service/installer.go`, возможно `cmd/main.go`.

**Что сделать:**

1. В `EnsureDependencies()` — заменить логику "если нет пакета → `apt-get install`" на "если нет пакета → напечатать инструкцию по ручной установке и вернуть ошибку".

2. То же для `EnsureNetfilterPersistent()` — больше не вызываем `apt-get install`, только проверяем наличие.

3. Удалить вспомогательные методы, которые после этого станут неиспользуемыми (`installPackage`, `runCommand` в installer.go, если они больше нигде не нужны — проверь).

4. Сообщения должны быть конкретными, например:
   ```
   ipset не установлен.
   Установите вручную:
     Debian/Ubuntu: sudo apt-get install ipset
     RHEL/CentOS:   sudo yum install ipset
   ```

5. Не трогать `install.sh` в корне репо — это отдельный установщик самого бинарника, его поведение не меняем.

**Тесты:** ручная проверка не требуется, достаточно `go build`.

---

### Задача 2. State-файл + команда `status`

**Цель:** ввести персистентное хранение конфигурации (URL'ы списков, флаги, время последнего апдейта) и команду `traffic-guard status` для просмотра текущего состояния защиты.

**Файлы:** новый пакет `internal/state/`, новый файл `internal/service/status.go`, изменения в `cmd/main.go`, минимальные правки в `runFull` для записи state, в `uninstaller.go` для удаления state-файла.

**State-файл:**

- Путь: `/etc/traffic-guard/config.json`
- Формат: JSON (используем `encoding/json` из stdlib, никаких внешних зависимостей)
- Права: `0644`, директория `0755`

Структура:

```go
type Config struct {
    URLs           []string  `json:"urls"`
    EnableLogging  bool      `json:"enable_logging"`
    AutoUpdate     bool      `json:"auto_update"`
    UpdateInterval string    `json:"update_interval,omitempty"` // e.g. "24h"
    LastUpdate     time.Time `json:"last_update,omitempty"`
}
```

API пакета `state`:

```go
func Load() (*Config, error)        // читает файл, если нет — возвращает ErrNotFound
func Save(cfg *Config) error        // атомарная запись через .tmp + rename
func Path() string                  // возвращает путь к файлу
func Remove() error                 // удаляет файл
var ErrNotFound = errors.New(...)
```

**Изменения в `runFull`:**

После успешной установки сохранить `Config` со всеми переданными флагами и `LastUpdate = time.Now()`.

**Команда `status`:**

Регистрация в `cmd/main.go`:

```go
statusCmd := &cobra.Command{
    Use:   "status",
    Short: "Показать текущее состояние защиты",
    Run:   runStatus,
}
rootCmd.AddCommand(statusCmd)
```

Что показывает (human-readable, plain text с минимумом цветов через zerolog или fmt):

1. **Защита:** активна / не активна. Активна = существует цепочка `SCANNERS-BLOCK` И есть отсылка к ней из `INPUT` ИЛИ `ufw-before-input` ИЛИ `DOCKER-USER`. Перечислить, к чему именно привязана.

2. **Размер ipset:** число элементов в `SCANNERS-BLOCK-V4` и `SCANNERS-BLOCK-V6`. Получать через `ipset list -t SCANNERS-BLOCK-V4` (parse `Number of entries:`).

3. **Источники списков:** URL'ы из state-файла. Если state-файла нет — "не сконфигурировано, запустите traffic-guard full".

4. **Последнее обновление:** `LastUpdate` из state, в формате "2 hours ago" или ISO — на твой вкус, главное человекочитаемо.

5. **Заблокировано пакетов:** счётчик из `iptables -L SCANNERS-BLOCK -v -n -x` (сумма по DROP-правилам). Только IPv4 для простоты.

**Не показываем** (сознательное решение): версию утилиты, состояние systemd-юнитов, детали логирования.

**Изменения в uninstaller:** при `uninstall` удалять `/etc/traffic-guard/config.json` и пустую директорию `/etc/traffic-guard`.

---

### Задача 3. Auto-update

**Цель:** периодическое автоматическое обновление списков через systemd-таймер + ручная команда `update`.

**Файлы:** новый файл `internal/service/updater.go`, новые шаблоны в `internal/service/systemd_templates.go`, изменения в `cmd/main.go`, `iptables.go` (новые флаги), `uninstaller.go`.

**Поведение по умолчанию:** auto-update **выключен**. Включается флагом `--auto-update` при `full`.

**Новые флаги для `full`:**

```
--auto-update              включить автоматическое обновление списков (default false)
--update-interval string   интервал обновления (default "24h")
```

`--update-interval` принимает любое валидное значение для `time.ParseDuration` (`"6h"`, `"30m"`, `"7d"` — последнее не поддерживается ParseDuration, возможно нужен кастомный парсер; либо ограничить только `h`/`m` и задокументировать).

**Логика в `runFull`:**

Если `--auto-update`:
1. Сохранить `AutoUpdate=true`, `UpdateInterval=...` в state.
2. Создать systemd service + timer:
   - `/etc/systemd/system/traffic-guard-update.service` — `ExecStart=/usr/local/bin/traffic-guard update`
   - `/etc/systemd/system/traffic-guard-update.timer` — `OnUnitActiveSec={interval}`, `OnBootSec=15min`
3. `daemon-reload`, `enable --now traffic-guard-update.timer`.

**Команда `update`:**

```go
updateCmd := &cobra.Command{
    Use:   "update",
    Short: "Обновить списки блокировки из сохранённых URL",
    Run:   runUpdate,
}
```

Логика `runUpdate`:

1. CheckRoot.
2. `state.Load()`. Если ошибка — fatal "Не сконфигурировано, запустите traffic-guard full".
3. `downloader.Download(cfg.URLs)`.
4. **Защита от пустого результата:** если `networks.TotalCount() == 0` — fatal "получен пустой список, обновление отменено", оставляем текущий ipset как есть.
5. `ipsetSvc.Setup()` (flush) + `ipsetSvc.Fill(networks)` + `ipsetSvc.Save("/etc/ipset.conf")`.
6. `cfg.LastUpdate = time.Now()`, `state.Save(cfg)`.

**Атомарность через swap НЕ делаем** — оставляем существующий flush+fill.

**Изменения в uninstaller:** останавливать и удалять `traffic-guard-update.service` и `.timer`.

---

### Задача 4. Поддержка Docker (DOCKER-USER)

**Цель:** блокировать SCANNERS-BLOCK-трафик не только к хосту (`INPUT`), но и к Docker-контейнерам (`FORWARD`/`DOCKER-USER`), независимо от наличия Docker на машине.

**Контекст:**

- Docker DNAT'ит входящие пакеты для опубликованных портов, после чего они идут через `FORWARD`, минуя `INPUT`.
- Docker гарантирует, что цепочка `DOCKER-USER` пользовательская и не очищается при рестартах docker-сервиса (но **может пересоздаваться**, поэтому нужен реинжектор).
- Только IPv4. IPv6-Docker (опт-ин фича) игнорируем.
- Делаем безусловно — даже если Docker не установлен. Пустая цепочка iptables ничего не стоит, защита будет на месте если Docker появится позже.

**Файлы:** изменения в `iptables.go`, `iptables_commands.go`, новый шаблон в `systemd_templates.go`, изменения в `uninstaller.go`.

**Логика setup в `IptablesService.SetupChain()`:**

После существующей настройки `SCANNERS-BLOCK` для IPv4:

1. Проверить, существует ли цепочка `DOCKER-USER` в `iptables filter`. Если нет — создать её (`iptables -N DOCKER-USER`).

   Важно: добавить в цепочку правило `RETURN` в конце, потому что Docker по умолчанию делает так. Если цепочка пустая, Docker всё равно отработает, но лучше явно: `iptables -A DOCKER-USER -j RETURN` (добавляем только если цепочка только что создана, чтобы не плодить дубли).

2. Проверить, есть ли уже наше правило в DOCKER-USER:
   `iptables -C DOCKER-USER -m set --match-set SCANNERS-BLOCK-V4 src -j DROP`

3. Если нет — вставить на позицию 1:
   `iptables -I DOCKER-USER 1 -m set --match-set SCANNERS-BLOCK-V4 src -j DROP`

**Реинжектор после рестарта Docker:**

По аналогии с существующим `antiscan-move-rules.service`:

Создать `antiscan-docker-rules.service`:

```ini
[Unit]
Description=Reinject SCANNERS-BLOCK rule into DOCKER-USER after docker starts
After=docker.service
Wants=docker.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'iptables -C DOCKER-USER -m set --match-set SCANNERS-BLOCK-V4 src -j DROP 2>/dev/null || iptables -I DOCKER-USER 1 -m set --match-set SCANNERS-BLOCK-V4 src -j DROP'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Этот юнит создаётся всегда (как и сама цепочка), независимо от наличия Docker. Если `docker.service` не существует — юнит просто не сработает в `After=`, ошибки не будет.

`enable` юнита.

**Сохранение правил:**

DOCKER-USER правила должны сохраняться в `iptables-save` для автозагрузки. Существующая логика `Save()` через `netfilter-persistent` или UFW `before.rules` это покроет — но проверь, что правило из DOCKER-USER попадает в дамп.

**Важный нюанс с UFW:** при UFW-сценарии правила сейчас пишутся в `before.rules`. DOCKER-USER в `before.rules` писать **не нужно** — это пользовательская цепочка Docker. Правило в DOCKER-USER инжектится только runtime + восстанавливается через `antiscan-docker-rules.service`. 

То есть: `before.rules` остаётся как есть (только SCANNERS-BLOCK с привязкой к ufw-before-input), а DOCKER-USER управляется отдельно через systemd-юнит.

**Изменения в uninstaller:**

1. Удалить наше правило из DOCKER-USER:
   `iptables -D DOCKER-USER -m set --match-set SCANNERS-BLOCK-V4 src -j DROP`
2. **Не удалять саму цепочку DOCKER-USER** — она принадлежит Docker.
3. `disable` + удалить `antiscan-docker-rules.service`.

**Изменения в `status` (задача 2):**

Добавить проверку привязки к `DOCKER-USER` в список мест, где смонтирована защита.

---

## Принципы для всех задач

- **Минимум зависимостей.** Не добавляй новые Go-модули. Хватает stdlib + cobra + zerolog.
- **Идемпотентность.** Все операции должны корректно отрабатывать при повторном запуске. Уже создано — не пересоздавать. Уже привязано — не дублировать.
- **Логирование через zerolog**, как везде в проекте. Стиль сообщений — на русском, как уже принято.
- **Ошибки.** Fatal только когда продолжать невозможно. Warning — когда некритично (что-то не удалось почистить, например).
- **Не трогаем то, что не просили.** Никаких рефакторингов "по дороге", никаких переименований существующих API без причины.
- **Тесты.** Юнит-тестов в проекте нет, добавлять не требуется. Но если делаешь нетривиальный парсер (например, парсинг вывода `ipset list` для подсчёта элементов в status) — желательно покрыть тестом.

## Что отложено и НЕ делаем в этом задании

- Перевод bash-агрегатора логов на Go.
- Whitelist для подсетей.
- Защита от блокировки слишком больших подсетей (`/0`, `/8` и т.п.).
- Любые изменения в IPv6-логике (оставляем как есть, новый код только для IPv4).
- Атомарный swap ipset при обновлении.
