#!/usr/bin/env bash
# fw-server.sh - backup server for Windows Firewall policies
#
# BACKUP:  the server PULLS the policy from the client over SSH (forced command "agent", key id_export).
# RESTORE: the server only PREPARES the restore (validates the chosen backup, optionally makes a
#          pre-restore backup). The CLIENT then downloads the backup over SFTPGo (permissions
#          list + download) and imports it locally. The server no longer pushes data to Windows.
#
# Modes:
#   request <user>     forced command from authorized_keys; client command in SSH_ORIGINAL_COMMAND
#   scheduled [user]   cron: pull a backup from every client in clients.conf (or only one)
set -uo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin
umask 027

CONF=/etc/fwbackup/clients.conf
KEY_EXPORT=/etc/fwbackup/id_export
KNOWN=/etc/fwbackup/known_hosts
BASE=/srv/fwbackups
LOCKDIR=/var/lib/fwbackup/locks
LOG=/var/log/fwbackup/server.log
KEEP_AUTO=30
EXPORT_TRIES=3

CUR_USER="?"; HOST=""; WINUSER=""; STORE=""; MODE_OUT=0
BK_NAME=""; export BK_SHA=""; BK_MSG=""; PROTECT=""

log() { printf '%s [%s] %s\n' "$(date -Is)" "$CUR_USER" "$*" >> "$LOG"; }

emit_result() { # status message [file]
    log "$1: $2 ${3:-}"
    if [ "$MODE_OUT" = 1 ]; then
        echo "STATUS=$1"
        echo "MESSAGE=$2"
        echo "FILE=${3:-}"
    fi
}

# Resolves the client from clients.conf (never from data sent by the client)
setup_user() {
    local line
    [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || return 1
    line=$(awk -v u="$1" '$1==u {print $2" "$3; exit}' "$CONF" 2>/dev/null)
    HOST=${line%% *}
    WINUSER=${line#* }
    [[ "$HOST" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]] || return 1
    [[ "$WINUSER" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || return 1
    STORE="$BASE/$1/backups"
    mkdir -p "$STORE" "$LOCKDIR"
}

# $1 = private key; stdin/stdout go to the forced command on Windows.
# LogLevel=ERROR hides the harmless "server may need to be upgraded" banner.
agent_ssh() {
    ssh -T -i "$1" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$KNOWN" -o ConnectTimeout=10 \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=6 -o LogLevel=ERROR \
        "$WINUSER@$HOST" agent
}

# Keeps the newest KEEP_AUTO auto-* / scheduled backups; never deletes $PROTECT (the backup being restored)
prune_backups() {
    find "$STORE" -maxdepth 1 -type f \( -name "*_auto-*.wfw" -o -name "*_scheduled.wfw" \) -printf '%T@\t%p\n' 2>/dev/null \
        | sort -k1,1rn \
        | cut -f2- \
        | tail -n +$((KEEP_AUTO + 1)) \
        | while read -r f; do
            [ -n "$PROTECT" ] && [ "$(basename "$f")" = "$PROTECT" ] && continue
            rm -f -- "$f" "$f.sha256"
        done
    rm -f -- "$STORE"/*.part 2>/dev/null
}

# Pulls a backup from the client. Sets BK_NAME, BK_SHA, BK_MSG.
do_backup() { # $1 = reason
    local reason out clean tmp computer sha calc dest ok=0 try
    reason=$(printf '%s' "$1" | tr -cd 'a-z-' | cut -c1-20)
    [ -n "$reason" ] || reason=manual
    out=$(mktemp); clean=$(mktemp); tmp=$(mktemp)
    BK_NAME=""; BK_SHA=""; BK_MSG=""
    _bk_clean() { rm -f "$out" "$out.err" "$clean" "$tmp"; }

    for try in $(seq "$EXPORT_TRIES"); do
        if agent_ssh "$KEY_EXPORT" < /dev/null > "$out" 2> "$out.err" \
           && tr -d '\r' < "$out" | grep -q '^FWAGENT-END$'; then
            ok=1; break
        fi
        log "export attempt $try/$EXPORT_TRIES failed: $(tail -n 1 "$out.err" 2>/dev/null | cut -c1-120)"
        sleep 2
    done
    if [ "$ok" != 1 ]; then
        BK_MSG="cannot reach client or agent failed: $(tail -n 1 "$out.err" 2>/dev/null | cut -c1-120)"
        _bk_clean; return 1
    fi

    tr -d '\r' < "$out" > "$clean"
    computer=$(sed -n 's/^COMPUTER=//p' "$clean" | head -n 1)
    sha=$(sed -n 's/^SHA256=//p' "$clean" | head -n 1 | tr 'A-F' 'a-f')
    if [[ ! "$computer" =~ ^[A-Za-z0-9-]{1,15}$ ]] || [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
        BK_MSG="invalid agent response"; _bk_clean; return 1
    fi
    sed -n '/^DATA$/,/^FWAGENT-END$/p' "$clean" | sed '1d;$d' | base64 -d > "$tmp" 2>/dev/null
    calc=$(sha256sum "$tmp" | cut -d' ' -f1)
    if [ ! -s "$tmp" ] || [ "$calc" != "$sha" ]; then
        BK_MSG="hash mismatch or empty data"; _bk_clean; return 1
    fi

    BK_NAME="${computer}_$(date +%Y%m%d_%H%M%S)_${reason}.wfw"
    dest="$STORE/$BK_NAME"
    # cat (not mv): the new file inherits the group of the directory (setgid), so SFTPGo can read it.
    # A .part file plus mv makes the appearance of the backup atomic; the .sha256 is written LAST,
    # and the client lists only backups that have a .sha256.
    if ! cat "$tmp" > "$dest.part" 2>/dev/null; then
        BK_MSG="cannot write to the backup store"; rm -f "$dest.part"; BK_NAME=""; _bk_clean; return 1
    fi
    chmod 640 "$dest.part"; mv -f "$dest.part" "$dest"
    printf '%s  %s\n' "$sha" "$BK_NAME" > "$dest.sha256.part"
    chmod 640 "$dest.sha256.part"; mv -f "$dest.sha256.part" "$dest.sha256"
    BK_SHA=$sha
    _bk_clean
    prune_backups
    return 0
}

# Validates a stored backup before the client downloads it. Sets BK_MSG.
prepare_restore() { # $1 = backup file name
    local file=$1 path sha
    [[ "$file" =~ ^[A-Za-z0-9._-]+\.wfw$ ]] || { BK_MSG="invalid backup name"; return 1; }
    path="$STORE/$file"
    if [ ! -f "$path" ] || [ ! -f "$path.sha256" ]; then BK_MSG="backup not found on server"; return 1; fi
    sha=$(cut -d' ' -f1 "$path.sha256" | tr 'A-F' 'a-f')
    if [ "$(sha256sum "$path" | cut -d' ' -f1)" != "$sha" ]; then
        BK_MSG="stored backup failed integrity check"; return 1
    fi
    return 0
}

# Request mode: forced command, the user comes from authorized_keys, the command from the client
handle_request() { # $1 = sftp user
    local user=$1 cmd=${SSH_ORIGINAL_COMMAND:-} verb a1 a2 extra
    CUR_USER=$user; MODE_OUT=1
    if ! setup_user "$user"; then emit_result FAIL "client not registered on the server"; return 1; fi
    read -r verb a1 a2 extra <<< "$cmd"

    exec 9>"$LOCKDIR/$user.lock"
    if ! flock -w 120 9; then emit_result FAIL "server busy"; return 1; fi

    case "${verb:-}" in
        backup)
            if [[ ! "${a1:-manual}" =~ ^[a-z-]{1,20}$ ]] || [ -n "${a2:-}" ]; then emit_result FAIL "bad arguments"; return 1; fi
            if do_backup "${a1:-manual}"; then emit_result OK "backup stored" "$BK_NAME"
            else emit_result FAIL "$BK_MSG"; fi ;;
        restore)
            if [[ ! "${a1:-}" =~ ^[A-Za-z0-9._-]+\.wfw$ ]] || [[ ! "${a2:-}" =~ ^(yes|no)$ ]] || [ -n "${extra:-}" ]; then
                emit_result FAIL "bad arguments"; return 1
            fi
            PROTECT=$a1
            if ! prepare_restore "$a1"; then emit_result FAIL "$BK_MSG" "$a1"; return 1; fi
            if [ "$a2" = "yes" ] && ! do_backup pre-restore; then
                emit_result FAIL "pre-restore backup failed: $BK_MSG" "$a1"; return 1
            fi
            # the pre-restore backup may have pruned old files: check again
            if ! prepare_restore "$a1"; then emit_result FAIL "$BK_MSG" "$a1"; return 1; fi
            emit_result OK "restore ready: client downloads and imports" "$a1" ;;
        *)
            emit_result FAIL "unknown command"; return 1 ;;
    esac
}

# Scheduled mode (cron): pull a backup from each registered client
run_scheduled() { # optional $1 = only this user
    local only=${1:-} u _
    MODE_OUT=0
    while read -r u _; do
        [[ -z "${u:-}" || "$u" == \#* ]] && continue
        [ -n "$only" ] && [ "$u" != "$only" ] && continue
        CUR_USER=$u
        if ! setup_user "$u"; then log "bad config for $u"; continue; fi
        exec 9>"$LOCKDIR/$u.lock"
        if ! flock -w 120 9; then log "busy, skipped"; continue; fi
        if do_backup scheduled; then emit_result OK "scheduled backup stored" "$BK_NAME"
        else emit_result FAIL "$BK_MSG"; fi
        flock -u 9; exec 9>&-
    done < "$CONF"
}

case "${1:-}" in
    request)   handle_request "${2:-}" ;;
    scheduled) run_scheduled "${2:-}" ;;
    *) echo "usage: $0 request <user> | scheduled [user]" >&2; exit 2 ;;
esac
