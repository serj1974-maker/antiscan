package service

// SystemdTemplates contains all systemd unit file templates
const (
	// IpsetRestoreServiceTemplate is the systemd service for restoring ipset on boot.
	// NOTE: The set name "SCANNERS-BLOCK-V4" and chain name "SCANNERS-BLOCK" below
	// must match the ipsetV4Name and chainName constants defined in ipset.go / iptables.go.
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
# Reads kernel journal entries via journalctl with cursor tracking — no rsyslog required.

set -euo pipefail

OUTPUT_CSV="/var/log/iptables-scanners-aggregate.csv"
WHOIS_CACHE="/tmp/antiscan-whois-cache.txt"
CURSOR_FILE="/var/lib/antiscan/journal-cursor"
LOCK_FILE="/var/lock/antiscan-aggregate.lock"

# Prevent concurrent execution
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

# Invalidate whois cache if older than 1 day
if [ -f "$WHOIS_CACHE" ]; then
    find "$WHOIS_CACHE" -mtime +1 -delete 2>/dev/null || true
fi
touch "$WHOIS_CACHE"

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
    whois_output=$(timeout 5 whois "$ip" 2>/dev/null || echo "")
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

# Build journalctl cursor argument
CURSOR_ARG=""
if [ -f "$CURSOR_FILE" ] && [ -s "$CURSOR_FILE" ]; then
    CURSOR_ARG="--after-cursor=$(cat "$CURSOR_FILE")"
fi

# Read kernel journal entries with cursor tracking
TEMP_JOURNAL=$(mktemp /tmp/antiscan-journal-XXXXXX.tmp)
trap 'rm -f "$TEMP_JOURNAL"' EXIT

if ! journalctl -k $CURSOR_ARG --output=short-iso --show-cursor 2>/dev/null > "$TEMP_JOURNAL"; then
    # Stale cursor — retry from current boot
    rm -f "$CURSOR_FILE"
    journalctl -k --output=short-iso --show-cursor 2>/dev/null > "$TEMP_JOURNAL" || true
fi

# Save new cursor
NEW_CURSOR=$(grep '^-- cursor: ' "$TEMP_JOURNAL" | tail -1 | sed 's/^-- cursor: //')
if [ -n "$NEW_CURSOR" ]; then
    mkdir -p /var/lib/antiscan
    printf '%s\n' "$NEW_CURSOR" > "$CURSOR_FILE"
fi

# One CSV row per blocked request.
# short-iso format: "2026-06-01T12:34:56+0300 hostname kernel: [optional] ANTISCAN-v4: ..."
# substr($1,1,10) extracts "2026-06-01", substr($1,12,8) extracts "12:34:56".
# SRC= and DPT= are matched via substr() — no regex interval syntax {N} required.
grep 'ANTISCAN-v4:' "$TEMP_JOURNAL" 2>/dev/null | awk '{
    ts = substr($1,1,10) " " substr($1,12,8); ip = ""; port = ""
    for (i = 1; i <= NF; i++) {
        if (substr($i,1,4) == "SRC=") ip   = substr($i,5)
        if (substr($i,1,4) == "DPT=") port = substr($i,5)
    }
    if (ip != "") print ts "|" ip "|" (port != "" ? port : "UNKNOWN")
}' | while IFS='|' read -r ts ip port; do
    info=$(get_ip_info "$ip")
    printf '%s|%s|%s|%s\n' "$ts" "$ip" "$info" "$port"
done >> "$OUTPUT_CSV" || true

exit 0
`

	// LogrotateConfigTemplate is the logrotate configuration
	LogrotateConfigTemplate = `/var/log/iptables-scanners-aggregate.csv {
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
	LogrotateConfigPath      = "/etc/logrotate.d/iptables-scanners"
	JournalCursorPath        = "/var/lib/antiscan/journal-cursor"
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

	// DockerRulesServiceTemplate re-injects the DROP rule into DOCKER-USER.
	// NOTE: "SCANNERS-BLOCK-V4" must match ipsetV4Name in ipset.go.
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
	IptablesRulesV4Path = "/etc/iptables/rules.v4"
)

// LogPaths contains paths for log files
const (
	AggregateLogPath = "/var/log/iptables-scanners-aggregate.csv"
)
