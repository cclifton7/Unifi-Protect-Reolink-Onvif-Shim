#!/bin/sh
# (Re)install the ONVIF shim. Safe to re-run, e.g. after a UniFi OS update.
#   sh /data/onvif-shim/install.sh            install/enable
#   sh /data/onvif-shim/install.sh uninstall  remove units + rules (keeps /data/onvif-shim)
set -e
D=/data/onvif-shim
U=/etc/systemd/system

if [ "$1" = "uninstall" ]; then
  systemctl disable --now onvif-shim-rule.timer onvif-shim.service 2>/dev/null || true
  [ -f $D/shim.conf ] && sh $D/rule.sh remove
  rm -f $U/onvif-shim.service $U/onvif-shim-rule.service $U/onvif-shim-rule.timer
  systemctl daemon-reload
  echo "onvif-shim uninstalled"
  exit 0
fi

[ -f $D/shim.conf ] || { echo "Create $D/shim.conf first (see shim.conf.example)"; exit 1; }
. $D/shim.conf
[ -n "${SHIM_CAM_HOSTS:-$SHIM_CAM_HOST}" ] || { echo "Set SHIM_CAM_HOSTS in $D/shim.conf"; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found on this console"; exit 1; }
command -v iptables >/dev/null || { echo "iptables not found on this console"; exit 1; }
# The shim only works through an iptables nat OUTPUT rule. Some Protect hosts
# (UNVR, UNVR Pro) have a kernel built without netfilter: stop before
# installing anything rather than leave a shim that nothing is sent to.
if ! nat_err=$(iptables -t nat -S OUTPUT 2>&1); then
  echo "This console can't create iptables NAT rules, so the shim can't run here."
  echo "UNVR and UNVR Pro are not supported: their kernel has no netfilter."
  echo "See README.md > Compatibility. iptables said:"
  echo "$nat_err" | sed 's/^/  /'
  exit 1
fi

cat > $U/onvif-shim.service <<EOF
[Unit]
Description=ONVIF shim (UniFi Protect <-> Reolink)
After=network-online.target

[Service]
EnvironmentFile=$D/shim.conf
ExecStart=/usr/bin/env python3 -u $D/onvif_shim.py
ExecStopPost=/bin/sh $D/rule.sh remove
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > $U/onvif-shim-rule.service <<EOF
[Unit]
Description=Ensure ONVIF shim DNAT rules

[Service]
Type=oneshot
ExecStart=/bin/sh $D/rule.sh ensure
EOF

cat > $U/onvif-shim-rule.timer <<EOF
[Unit]
Description=Re-check ONVIF shim DNAT rules

[Timer]
OnBootSec=30
OnUnitActiveSec=30
AccuracySec=5

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable onvif-shim.service
systemctl restart onvif-shim.service
systemctl enable --now onvif-shim-rule.timer

# rule.sh only adds a camera's ONVIF rule once the shim is listening, so give
# the shim a few seconds, then check that every camera's rule is in place.
CAM_PORT=${SHIM_CAM_PORT:-8000}
missing=""
for try in 1 2 3 4 5; do
  sleep 2
  rule_ok=1; sh $D/rule.sh ensure || rule_ok=0
  missing=""
  for host in $(echo "${SHIM_CAM_HOSTS:-$SHIM_CAM_HOST}" | tr ',' ' '); do
    iptables -t nat -S OUTPUT | grep -qE -- "-d $host/32 .*--dport $CAM_PORT .*--to-destination 127\.0\.0\.1:" || missing="$missing $host"
  done
  # (an if, not an && chain: under set -e a failing last test would exit the script)
  if [ -z "$missing" ] && [ $rule_ok = 1 ]; then break; fi
done
if [ -n "$missing" ] || [ $rule_ok = 0 ]; then
  echo "onvif-shim did NOT install cleanly: ONVIF redirect missing for camera(s):${missing:- (see log)}"
  echo "The shim may not be running. Check: journalctl -u onvif-shim -n 30 --no-pager"
  echo "The rule timer will keep retrying. To remove everything: sh $D/install.sh uninstall"
  exit 1
fi
echo "onvif-shim installed for camera(s) ${SHIM_CAM_HOSTS:-$SHIM_CAM_HOST}"
