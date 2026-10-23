#!/bin/sh
# Shared entrypoint, byte-identical in every image (CONTAINER_UID_GID.md). As root: remap, hooks, chown, gosu.
# As non-root (compose `user:` pin): no remap, hooks or chown; fail unless every $DATA_DIRS entry is writable.
set -eu

: "${APP_USER:?entrypoint: APP_USER must be set by the image}"
: "${DATA_DIRS?entrypoint: DATA_DIRS must be set by the image (empty when it writes nothing)}"

if [ "$#" -eq 0 ]; then
    echo "entrypoint: no command to run; set CMD in the image or pass one to docker run" >&2
    exit 1
fi

CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

if [ "$CURRENT_UID" != "0" ]; then
    echo "entrypoint: started as ${CURRENT_UID}:${CURRENT_GID} (not root), skipping the PUID/PGID remap, hooks and chown" >&2
    if [ -n "${PUID:-}" ] && [ "$PUID" != "$CURRENT_UID" ]; then
        echo "entrypoint: PUID=${PUID} does not match the uid this container was started as (${CURRENT_UID}); drop the \"user:\" pin or unset PUID" >&2
        exit 1
    fi
    if [ -n "${PGID:-}" ] && [ "$PGID" != "$CURRENT_GID" ]; then
        echo "entrypoint: PGID=${PGID} does not match the gid this container was started as (${CURRENT_GID}); drop the \"user:\" pin or unset PGID" >&2
        exit 1
    fi
    for dir in $DATA_DIRS; do
        if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
            owner=$(stat -c '%u:%g' "$dir" 2>/dev/null || echo 'missing')
            echo "entrypoint: ${dir} is not writable by ${CURRENT_UID}:${CURRENT_GID} (owner ${owner}); chown it on the host, or drop the \"user:\" pin so the entrypoint can do it as root" >&2
            exit 1
        fi
    done
    exec "$@"
fi

# PUID/PGID must be numeric and non-zero: the workload never runs as root.
check_id() {
    case "$2" in
        ''|*[!0-9]*) echo "entrypoint: $1=$2 is not numeric, refusing to start" >&2; exit 1 ;;
        0) echo "entrypoint: $1=0 is not allowed, refusing to run the workload as root" >&2; exit 1 ;;
    esac
}

# Unset PUID/PGID adopt the owner of the first data dir; a root owner, or no data dir, falls back to 1001.
FIRST_DIR=""
for dir in $DATA_DIRS; do FIRST_DIR=$dir; break; done
OWNER_UID=0
OWNER_GID=0
if [ -n "$FIRST_DIR" ]; then
    OWNER_UID=$(stat -c '%u' "$FIRST_DIR")
    OWNER_GID=$(stat -c '%g' "$FIRST_DIR")
fi

if [ -n "${PUID:-}" ]; then
    check_id PUID "$PUID"; RESOLVED_UID=$PUID; UID_SOURCE="PUID"
elif [ "$OWNER_UID" != "0" ]; then
    RESOLVED_UID=$OWNER_UID; UID_SOURCE="owner of ${FIRST_DIR}"
else
    RESOLVED_UID=1001; UID_SOURCE="default"
fi
if [ -n "${PGID:-}" ]; then
    check_id PGID "$PGID"; RESOLVED_GID=$PGID; GID_SOURCE="PGID"
elif [ "$OWNER_GID" != "0" ]; then
    RESOLVED_GID=$OWNER_GID; GID_SOURCE="owner of ${FIRST_DIR}"
else
    RESOLVED_GID=1001; GID_SOURCE="default"
fi
echo "entrypoint: resolved ${APP_USER} to ${RESOLVED_UID}:${RESOLVED_GID} (uid from ${UID_SOURCE}, gid from ${GID_SOURCE})" >&2

# -o allows an id already present in the image.
groupmod -o -g "$RESOLVED_GID" "$APP_USER"
usermod -o -u "$RESOLVED_UID" -g "$RESOLVED_GID" "$APP_USER"

# Image-specific root steps (e.g. joining the docker socket's group) live in hooks, never in this file.
export APP_USER RESOLVED_UID RESOLVED_GID
for hook in /etc/entrypoint.d/*.sh; do
    [ -e "$hook" ] || continue
    echo "entrypoint: running root hook ${hook}" >&2
    sh "$hook" || { rc=$?; echo "entrypoint: root hook ${hook} failed with exit ${rc}, refusing to start" >&2; exit "$rc"; }
done

# Chown only what is wrong, so a volume that already matches is untouched.
for dir in $DATA_DIRS; do
    find "$dir" \( ! -user "$RESOLVED_UID" -o ! -group "$RESOLVED_GID" \) -exec chown "$RESOLVED_UID:$RESOLVED_GID" {} +
done

# User form, not uid:gid, so supplementary groups come from /etc/group.
exec gosu "$APP_USER" "$@"
