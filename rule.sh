#!/bin/sh
# Keep the DNAT rules in place only while the shim is listening.
# Usage: rule.sh ensure | remove
D=${SHIM_DIR:-/data/onvif-shim}
[ -f "$D/shim.conf" ] || { echo "missing $D/shim.conf"; exit 1; }
. "$D/shim.conf"
[ -n "$SHIM_CAM_HOST" ] || { echo "SHIM_CAM_HOST not set in $D/shim.conf"; exit 1; }

CAM_HOST=$SHIM_CAM_HOST
MARK=${SHIM_MARK:-0x40000000}
# camera_port:shim_port:enabled -- ONVIF events, and (optionally) HTTP snapshots.
# A disabled pair is always removed, so turning snapshots off cleans up port 80.
SNAP=0; [ "${SHIM_SNAPSHOTS:-1}" = "1" ] && SNAP=1
PAIRS="${SHIM_CAM_PORT:-8000}:${SHIM_LISTEN_PORT:-18000}:1 ${SHIM_CAM_HTTP_PORT:-80}:${SHIM_SNAP_LISTEN_PORT:-18080}:$SNAP"

rule() { echo "OUTPUT -p tcp -d $CAM_HOST --dport $1 -m mark ! --mark $MARK/$MARK -j DNAT --to-destination 127.0.0.1:$2"; }
has_rule() { iptables -t nat -S OUTPUT | grep -q -- "-d $CAM_HOST/32 .*--dport $1 .*--to-destination 127.0.0.1:$2"; }
shim_up() { ss -ltn "sport = :$1" | grep -q LISTEN; }

for pair in $PAIRS; do
  cam=${pair%%:*}; rest=${pair#*:}; shim=${rest%%:*}; enabled=${rest##*:}
  case "$1" in
    ensure)
      if [ "$enabled" = 1 ] && shim_up $shim; then
        has_rule $cam $shim || { iptables -t nat -I $(rule $cam $shim) && logger -t onvif-shim "DNAT $CAM_HOST:$cam -> :$shim (re)added"; }
      else
        has_rule $cam $shim && { iptables -t nat -D $(rule $cam $shim); logger -t onvif-shim "shim :$shim down, DNAT removed"; }
      fi
      ;;
    remove)
      while has_rule $cam $shim; do iptables -t nat -D $(rule $cam $shim) || break; done
      ;;
    *) echo "usage: $0 ensure|remove"; exit 2 ;;
  esac
done
exit 0
