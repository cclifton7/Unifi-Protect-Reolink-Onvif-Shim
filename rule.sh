#!/bin/sh
# Keep the DNAT rules in place only while the shim is listening.
# Camera n (0-based, in SHIM_CAM_HOSTS order) uses SHIM_LISTEN_PORT+n and
# SHIM_SNAP_LISTEN_PORT+n. Any of our rules not wanted right now (shim down,
# snapshots off, camera removed from the list) are deleted.
# Usage: rule.sh ensure | remove
# ensure exits 1 if a wanted rule could not be added.
D=${SHIM_DIR:-/data/onvif-shim}
[ -f "$D/shim.conf" ] || { echo "missing $D/shim.conf"; exit 1; }
. "$D/shim.conf"
HOSTS=$(echo "${SHIM_CAM_HOSTS:-$SHIM_CAM_HOST}" | tr ',' ' ')
[ -n "$HOSTS" ] || { echo "SHIM_CAM_HOSTS not set in $D/shim.conf"; exit 1; }

MARK=${SHIM_MARK:-0x40000000}
CAM_PORT=${SHIM_CAM_PORT:-8000}
CAM_HTTP_PORT=${SHIM_CAM_HTTP_PORT:-80}
LISTEN=${SHIM_LISTEN_PORT:-18000}
SNAP_LISTEN=${SHIM_SNAP_LISTEN_PORT:-18080}
SNAP=0; [ "${SHIM_SNAPSHOTS:-1}" = "1" ] && SNAP=1

rule() { echo "OUTPUT -p tcp -d $1 --dport $2 -m mark ! --mark $MARK/$MARK -j DNAT --to-destination 127.0.0.1:$3"; }
has_rule() { iptables -t nat -S OUTPUT | grep -qE -- "-d $1/32 .*--dport $2 .*--to-destination 127\.0\.0\.1:$3( |\$)"; }
shim_up() { ss -ltn "sport = :$1" | grep -q LISTEN; }

# Delete our DNAT rules except those listed in $1 ("host:camport:shimport ...").
prune() {
  iptables -t nat -S OUTPUT | grep -- "--mark $MARK/$MARK" | grep -- "--to-destination 127.0.0.1:" |
  while read -r r; do
    key=$(echo "$r" | sed -n 's|.*-d \([0-9.]*\)/32 .*--dport \([0-9]*\) .*127\.0\.0\.1:\([0-9]*\).*|\1:\2:\3|p')
    case " $1 " in
      *" $key "*) ;;
      *) iptables -t nat $(echo "$r" | sed 's/^-A /-D /') && logger -t onvif-shim "DNAT $key removed" ;;
    esac
  done
}

case "$1" in
  ensure)
    keep="" i=0 rc=0
    for host in $HOSTS; do
      for pair in "$CAM_PORT:$((LISTEN + i)):1" "$CAM_HTTP_PORT:$((SNAP_LISTEN + i)):$SNAP"; do
        cam=${pair%%:*}; rest=${pair#*:}; shim=${rest%%:*}; enabled=${rest##*:}
        if [ "$enabled" = 1 ] && shim_up $shim; then
          keep="$keep $host:$cam:$shim"
          has_rule $host $cam $shim || {
            if iptables -t nat -I $(rule $host $cam $shim); then
              logger -t onvif-shim "DNAT $host:$cam -> :$shim (re)added"
            else
              logger -t onvif-shim "DNAT $host:$cam -> :$shim could not be added"; rc=1
            fi
          }
        fi
      done
      i=$((i + 1))
    done
    prune "$keep"
    exit $rc
    ;;
  remove) prune "" ;;
  *) echo "usage: $0 ensure|remove"; exit 2 ;;
esac
exit 0
