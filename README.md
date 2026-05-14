# antiscan

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
