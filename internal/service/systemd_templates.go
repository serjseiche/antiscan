package service

// SystemdTemplates contains all systemd unit file templates
const (
	// IpsetRestoreServiceTemplate is the systemd service for restoring ipset on boot
	IpsetRestoreServiceTemplate = `[Unit]
Description=Restore AntiscanSimple ipset configuration
Before=netfilter-persistent.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ipset restore -exist -f /etc/ipset.conf
ExecStart=-/usr/sbin/iptables -N SCANNERS-BLOCK

[Install]
WantedBy=multi-user.target
RequiredBy=netfilter-persistent.service
`

	// AggregateLogsServiceTemplate is the systemd service for log aggregation
	AggregateLogsServiceTemplate = `[Unit]
Description=AntiscanSimple Log Aggregator
After=rsyslog.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antiscan-aggregate-logs.sh
StandardOutput=journal
StandardError=journal
`

	// AggregateLogsTimerTemplate is the systemd timer for log aggregation
	AggregateLogsTimerTemplate = `[Unit]
Description=AntiscanSimple Log Aggregator Timer
Requires=antiscan-aggregate.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=30sec
AccuracySec=5sec

[Install]
WantedBy=timers.target
`

	// AggregateLogsScriptTemplate is the bash script for log aggregation
	AggregateLogsScriptTemplate = `#!/bin/bash
# AntiscanSimple Log Aggregation Script
# Output CSV format: DATETIME|IP_ADDRESS|ASN|NETNAME|PORT
# Each blocked connection is appended as a separate row (no deduplication).

set -uo pipefail

IPV4_LOG="/var/log/iptables-scanners-ipv4.log"
OUTPUT_CSV="/var/log/iptables-scanners-aggregate.csv"
WHOIS_CACHE="/tmp/antiscan-whois-cache.txt"
TEMP_IPV4="/tmp/antiscan-ipv4-$$.tmp"

# Invalidate whois cache if older than 1 day
if [ -f "$WHOIS_CACHE" ]; then
    find "$WHOIS_CACHE" -mtime +1 -delete 2>/dev/null || true
fi
touch "$WHOIS_CACHE"

# Atomic grab and clear log file
if [ ! -f "$IPV4_LOG" ]; then exit 0; fi
cat "$IPV4_LOG" > "$TEMP_IPV4"
> "$IPV4_LOG"
chown syslog:adm "$IPV4_LOG" 2>/dev/null || true
chmod 640 "$IPV4_LOG" 2>/dev/null || true

# Return cached or fresh ASN|NETNAME for an IP
get_ip_info() {
    local ip="$1"
    local cached
    cached=$(grep "^${ip}|" "$WHOIS_CACHE" 2>/dev/null | head -1)
    if [ -n "$cached" ]; then
        echo "$cached" | cut -d'|' -f2-
        return
    fi
    local asn="" netname=""
    local whois_output
    whois_output=$(timeout 3 whois -h whois.ripe.net "$ip" 2>/dev/null || echo "")
    if [ -n "$whois_output" ]; then
        asn=$(echo "$whois_output" | grep -iE "^origin:"  | head -1 | awk '{print $2}' | sed 's/AS//gi' | tr -d '\r\n ')
        netname=$(echo "$whois_output" | grep -iE "^netname:" | head -1 | awk '{print $2}' | tr -d '\r\n')
    fi
    if [ -n "$asn" ] && ! echo "$asn" | grep -qE '^[0-9]+$'; then asn=""; fi
    [ -z "$asn" ]     && asn="UNKNOWN"
    [ -z "$netname" ] && netname="UNKNOWN"
    [ "$asn" != "UNKNOWN" ] && ! echo "$asn" | grep -q "^AS" && asn="AS${asn}"
    echo "${ip}|${asn}|${netname}" >> "$WHOIS_CACHE"
    echo "${asn}|${netname}"
}

# Create/recreate header if file is missing or has old format
if [ ! -f "$OUTPUT_CSV" ] || ! head -1 "$OUTPUT_CSV" 2>/dev/null | grep -q "^DATETIME|"; then
    echo "DATETIME|IP_ADDRESS|ASN|NETNAME|PORT" > "$OUTPUT_CSV"
fi

# One CSV row per blocked request.
# $1 from rsyslog template is RFC3339 (e.g. 2026-04-30T22:21:21.599309+03:00);
# substr extracts local YYYY-MM-DD HH:MM:SS without fractional seconds or offset.
# SRC= and DPT= are matched via substr() — no regex interval syntax {N} required.
if [ -f "$TEMP_IPV4" ] && [ -s "$TEMP_IPV4" ]; then
    grep 'ANTISCAN-v4:' "$TEMP_IPV4" | awk '{
        ts = substr($1,1,10) " " substr($1,12,8); ip = ""; port = ""
        for (i = 1; i <= NF; i++) {
            if (substr($i,1,4) == "SRC=") ip   = substr($i,5)
            if (substr($i,1,4) == "DPT=") port = substr($i,5)
        }
        if (ip != "") print ts "|" ip "|" (port != "" ? port : "UNKNOWN")
    }' | while IFS='|' read -r ts ip port; do
        info=$(get_ip_info "$ip")
        printf '%s|%s|%s|%s\n' "$ts" "$ip" "$info" "$port"
    done >> "$OUTPUT_CSV"
fi

rm -f "$TEMP_IPV4"
exit 0
`

	// RsyslogConfigTemplate is the rsyslog configuration for iptables logging
	RsyslogConfigTemplate = `template(name="antiscan_tmpl" type="string" string="%TIMESTAMP:::date-rfc3339% %msg%\n")
:msg, contains, "ANTISCAN-v4: " action(type="omfile" file="/var/log/iptables-scanners-ipv4.log" template="antiscan_tmpl")
& stop
`

	// LogrotateConfigTemplate is the logrotate configuration
	LogrotateConfigTemplate = `/var/log/iptables-scanners-*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/iptables-scanners-aggregate.csv {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
`
)

// SystemdServicePaths contains paths to systemd service files
const (
	IpsetRestoreServicePath  = "/etc/systemd/system/antiscan-ipset-restore.service"
	AggregateLogsServicePath = "/etc/systemd/system/antiscan-aggregate.service"
	AggregateLogsTimerPath   = "/etc/systemd/system/antiscan-aggregate.timer"
	AggregateLogsScriptPath  = "/usr/local/bin/antiscan-aggregate-logs.sh"
	RsyslogConfigPath        = "/etc/rsyslog.d/10-iptables-scanners.conf"
	LogrotateConfigPath      = "/etc/logrotate.d/iptables-scanners"
	UpdateServicePath        = "/etc/systemd/system/antiscan-simple-update.service"
	UpdateTimerPath          = "/etc/systemd/system/antiscan-simple-update.timer"
	DockerRulesServicePath   = "/etc/systemd/system/antiscan-docker-rules.service"
	DockerRulesTimerPath     = "/etc/systemd/system/antiscan-docker-rules.timer"
)

// Update systemd unit templates
const (
	UpdateServiceTemplate = `[Unit]
Description=Update antiscan-simple scanner block lists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antiscan-simple update

[Install]
WantedBy=multi-user.target
`

	// UpdateTimerTemplate is the systemd timer for auto-updates.
	// {interval} will be replaced with the actual interval (e.g. "24h", "30min").
	UpdateTimerTemplate = `[Unit]
Description=Update antiscan-simple scanner block lists timer

[Timer]
OnBootSec=15min
OnUnitActiveSec={interval}
Persistent=true

[Install]
WantedBy=timers.target
`

	DockerRulesServiceTemplate = `[Unit]
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
`

	DockerRulesTimerTemplate = `[Unit]
Description=Reinject SCANNERS-BLOCK rule into DOCKER-USER (periodic)

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=30sec

[Install]
WantedBy=timers.target
`
)

// IpsetConfigPaths contains paths for ipset configuration
const (
	IpsetConfigPath     = "/etc/ipset.conf"
	IpsetConfigPathAlt  = "/etc/iptables/ipsets"
	IptablesRulesV4Path = "/etc/iptables/rules.v4"
)

// LogPaths contains paths for log files
const (
	IPv4LogPath      = "/var/log/iptables-scanners-ipv4.log"
	AggregateLogPath = "/var/log/iptables-scanners-aggregate.csv"
)
