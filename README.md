# UniFi Protect ONVIF Shim for Reolink cameras

**Get motion events, detection-based motion and correct thumbnails working for Reolink cameras in UniFi Protect.** It runs directly on your UniFi console. No Scrypted, Home Assistant or extra hardware.

If your Reolink camera is adopted in UniFi Protect as a third-party ONVIF camera and it **records fine but never produces motion events**, even though its spotlight or siren clearly shows it's detecting motion, this is probably your problem.

> ⚠️ **Unofficial and unsupported.** This adds a small service and two firewall (NAT) rules to your UniFi console. It's easy to remove (one command), but use it at your own risk. Not affiliated with Ubiquiti or Reolink.

---

## Contents
- [Symptoms](#symptoms)
- [Confirm you have this problem](#confirm-you-have-this-problem)
- [Root cause](#root-cause)
- [What the shim does](#what-the-shim-does)
- [Compatibility](#compatibility)
- [Installation](#installation)
- [Verify it's working](#verify-its-working)
- [Configuration reference](#configuration-reference)
- [Day-to-day operation](#day-to-day-operation)
- [Troubleshooting](#troubleshooting)
- [How it works (technical)](#how-it-works-technical)
- [Security considerations](#security-considerations)
- [Limitations](#limitations)
- [Related tips](#related-tips)
- [Version history](#version-history)

---

## Symptoms

- The Reolink camera is adopted in Protect (third-party / ONVIF) and live view and recording work.
- **No motion events ever appear** in Protect for that camera, even with motion detection enabled.
- Re-adopting, updating the camera firmware and toggling Protect settings change nothing.
- The camera *is* detecting motion: its spotlight/siren fires, and the Reolink app shows detections.
- (Once motion works) thumbnails show an empty scene, and motion events start late or at odd times.

## Confirm you have this problem

SSH into your UniFi console (see [Step 1](#1-enable-ssh-on-the-console)) and run:

```bash
grep -iE "consecutive errors|circuit-breaker" /srv/unifi-protect/logs/onvif.events.log | tail -5
```

If you see lines like these for your camera, repeating every few minutes, you have this problem:

```
warn: Deactivated ONVIF event subscription for XXXXXXXXXXXX after 3 consecutive errors
warn: REOLINK RLC-XXXX [...] ONVIF event subscription circuit-breaker fired: subscription kept failing after 3 deactivations
info: REOLINK RLC-XXXX [...] motionDetection available -> misconfigured [...]
```

**Optional definitive check.** Capture the camera's ONVIF traffic for about 5 minutes; Protect retries every 5 minutes. Replace `CAMERA_IP` with your camera's address:

```bash
timeout 330 tcpdump -i any -A -s 0 "host CAMERA_IP and tcp port 8000" | grep -aE "PullMessages|HTTP/1.1 (200|400)"
```

`PullMessages` requests answered with `HTTP/1.1 400 Bad Request` confirm it.

## Root cause

Protect subscribes to the camera's ONVIF events correctly. The camera accepts the subscription, and Protect even discovers its motion topics. Protect then polls for events with `PullMessages` requests every few seconds. **Those requests carry no WS-Addressing headers** (`wsa:To` / `wsa:Action`). Reolink's embedded gSOAP web server requires them, so it rejects every poll with **HTTP 400** and an empty SOAP fault.

After three failures Protect deactivates the subscription, trips a circuit breaker and marks motion detection as "misconfigured". It retries every 5 minutes, forever. The camera is fine and Protect is *almost* fine, but neither can be configured to fix it: Protect's ONVIF client behavior is compiled in, and Reolink's server is firmware.

Two more problems show up once events flow:
1. **Reolink's pixel-motion signal is erratic over ONVIF.** In testing it fired 13 s late, or only *after* the person had left (for example when the spotlight turned off). The camera's **AI detections** (`PeopleDetect`, `VehicleDetect`, `DogCatDetect`, …) tracked presence to about a second. Protect ignores those and only reads pixel motion.
2. **Protect takes a third-party camera's event thumbnail when the event *ends*,** by which point the subject has usually left the frame.

## What the shim does

A small Python service runs on the UniFi console, between Protect and the camera:

| Feature | Effect | Optional? |
|---|---|---|
| **Header fix** | Adds the missing `wsa:To` / `wsa:Action` headers to Protect's event requests. The subscription stops failing and motion events reach Protect. | Always on |
| **AI-driven motion** | Protect's motion follows the camera's person/vehicle/animal detections instead of pixel motion. Events start about 1–4 s after someone appears, end about 10–15 s after they leave, and lights, shadows and bugs don't trigger events. | `SHIM_MOTION_MODE=ai` (default) or `passthrough` |
| **Motion-start thumbnails** | Grabs a snapshot the moment motion starts and gives it to Protect when it asks for the event thumbnail at the end, so thumbnails show the subject. | `SHIM_SNAPSHOTS=1` (default) or `0` |

Nothing else changes. Video (RTSP) never passes through the shim, the camera doesn't need re-adopting in Protect, and uninstalling restores the original behavior.

## Compatibility

**Tested on:**
- UniFi Dream Machine Pro, UniFi OS 5.1.33, UniFi Protect 7.3.56 (third-party ONVIF motion requires Protect 7.1.55 or newer)
- Reolink **RLC-1240A**, firmware v3.2.0.5758

**Likely to work:** other UniFi OS consoles that run Protect (UDM SE, UDR, UNVR, CK Gen2+), as long as they have `python3`, `iptables` and `systemd`, which UniFi OS 3.x and later have. It should also work with other Reolink PoE cameras that use the same gSOAP ONVIF stack and `MyRuleDetector/*Detect` AI topics. **If you try another model or console, please open an issue or PR with the result.**

## Installation

Everything below runs **on the UniFi console** over SSH, except copying the files (Step 3), which runs from your computer. Replace these placeholders:
- `CONSOLE_IP`: your UniFi console (often your gateway, e.g. `192.168.1.1`)
- `CAMERA_IP`: your Reolink camera

### 0. Prerequisites
- The camera is already **adopted in Protect** as a third-party ONVIF camera. ONVIF must be enabled on the camera (Reolink default port **8000**), and Protect needs the camera's credentials.
- The camera has a **fixed IP**: create a DHCP reservation in UniFi Network. The shim is configured by IP.
- Protect **7.1.55 or newer** (Protect → Settings → Control Plane / About).

### 1. Enable SSH on the console
UniFi OS → **Console Settings → SSH** → enable it and set a strong password. The SSH user is `root`.

Optional but recommended: set up key-based login from your computer.
```bash
ssh-keygen -t ed25519
```
```bash
ssh-copy-id root@CONSOLE_IP
```

### 2. Confirm the problem
Run the check in [Confirm you have this problem](#confirm-you-have-this-problem).

### 3. Copy the files to the console
From the folder containing this repo, on your computer:
```bash
ssh root@CONSOLE_IP 'mkdir -p /data/onvif-shim'
```
```bash
scp onvif_shim.py rule.sh install.sh shim.conf.example root@CONSOLE_IP:/data/onvif-shim/
```
Files under `/data` survive reboots and firmware updates.

### 4. Create the config
```bash
ssh root@CONSOLE_IP
```
```bash
cp /data/onvif-shim/shim.conf.example /data/onvif-shim/shim.conf
```
```bash
vi /data/onvif-shim/shim.conf
```
Set `SHIM_CAM_HOSTS=` to your cameras' IPs, comma-separated with no spaces (e.g. `SHIM_CAM_HOSTS=192.168.1.20,192.168.1.21`). The defaults are fine for everything else. (In `vi`: press `i` to edit, then **Esc**, then type `:wq` and press Enter.)

**Skipping motion-start thumbnails?** Set `SHIM_SNAPSHOTS=0`, skip Step 5, and go to Step 6.

### 5. (For thumbnails) enable HTTP on the camera and store credentials
1. In the Reolink app: camera **Settings → Network → Advanced → Server/Port Settings** → enable **HTTP (port 80)**. Protect fetches snapshots from `http://CAMERA_IP/cgi-bin/api.cgi?cmd=onvifSnapPic…`, and this is also why thumbnails fail entirely when HTTP is off.
2. Save the camera credentials on the console. This prompts without echoing the password and creates a root-only file:
   ```bash
   ssh -t root@CONSOLE_IP 'bash -c '\''umask 077; read -r -p "Camera username [admin]: " u; u=${u:-admin}; read -r -s -p "Camera password: " p; echo; printf "SHIM_CAM_USER=%s\nSHIM_CAM_PASS=%s\n" "$u" "$p" > /data/onvif-shim/camera.env; echo "saved ($(wc -l < /data/onvif-shim/camera.env) lines)"'\'''
   ```
   It should print `saved (2 lines)`. The shim reads this file literally, so any characters in the password are fine. If your camera supports it, a view-only Reolink user is better than `admin`.

### 6. Install
```bash
ssh root@CONSOLE_IP 'sh /data/onvif-shim/install.sh'
```
Expected output ends with `onvif-shim installed for camera CAMERA_IP`.

### 7. Recommended Protect settings
- **Recording mode → Detections** for this camera, instead of Always. This is usually the big storage win.
- **Notifications:** Protect → **Alarm Manager** → your motion alarm → make sure this camera is **included**. Alarm rules list specific cameras, and a newly adopted or re-adopted camera isn't added automatically.

## Verify it's working

**1. The service and rules are up:**
```bash
ssh root@CONSOLE_IP 'systemctl is-active onvif-shim onvif-shim-rule.timer; iptables -t nat -S OUTPUT | grep 127.0.0.1:180'
```
You should see `active` twice, then one DNAT rule for port 8000 (plus one for port 80 if snapshots are on).

**2. Protect's subscription stopped failing.** Within about 5 minutes, no new `circuit-breaker` lines should appear:
```bash
ssh root@CONSOLE_IP 'grep -iE "consecutive errors|circuit-breaker|Started ONVIF" /srv/unifi-protect/logs/onvif.events.log | tail -3'
```
A healthy subscription logs `Started ONVIF event subscription` and then **nothing**.

**3. Walk-test.** Walk through the camera's view and watch the shim log live:
```bash
ssh root@CONSOLE_IP 'journalctl -u onvif-shim -f -o cat'
```
You should see something like:
```
event arrived=03:13:50.728Z cam=2026-…T03:13:40Z topic=RuleEngine/MyRuleDetector/PeopleDetect State=true
motion ON  (AI: PeopleDetect)
event snapshot captured (420 KB in 0.38s)
…
motion OFF
served motion-start snapshot to Protect (420 KB)
```
The event, with a thumbnail showing you, then appears in Protect.

> Tip: `arrived=` is the console's clock and `cam=` is the camera's. A large, constant gap usually means the camera's clock is off (set its NTP server), not that anything is slow.

## Configuration reference

All settings live in `/data/onvif-shim/shim.conf`. After changing it, restart the shim:
```bash
ssh root@CONSOLE_IP 'systemctl restart onvif-shim && sleep 2 && sh /data/onvif-shim/rule.sh ensure'
```

| Setting | Default | Description |
|---|---|---|
| `SHIM_CAM_HOSTS` | *(required)* | Camera IP addresses, comma-separated. Camera *n* uses ports `SHIM_LISTEN_PORT`+*n* / `SHIM_SNAP_LISTEN_PORT`+*n*, so add new cameras at the end. `SHIM_CAM_HOST` (one IP) still works. |
| `SHIM_CAM_PORT` | `8000` | Camera ONVIF port |
| `SHIM_CAM_HTTP_PORT` | `80` | Camera HTTP port (snapshots) |
| `SHIM_MOTION_MODE` | `ai` | `ai` = motion from AI detections; `passthrough` = header fix only (camera's own pixel motion) |
| `SHIM_OFF_HOLD` | `10` | Seconds to hold "motion off" so brief detection dropouts don't split one visit into several events. Lower = events end sooner |
| `SHIM_SNAPSHOTS` | `1` | `1` = motion-start thumbnails; `0` = off (port 80 not touched) |
| `SHIM_SNAP_SERVE_WINDOW` | `20` | Seconds after motion ends during which Protect gets the motion-start snapshot |
| `SHIM_SNAP_PATH` | Reolink `onvifSnapPic` URL | Snapshot URL path on the camera |
| `SHIM_LOG_EVENTS` | `1` | Log every camera event with camera vs. arrival time |
| `SHIM_LISTEN_PORT` / `SHIM_SNAP_LISTEN_PORT` | `18000` / `18080` | Local ports the shim listens on (127.0.0.1 only) |
| `SHIM_MARK` | `0x40000000` | Firewall mark on the shim's own connections to the camera (UniFi uses the `0x7f0000` range) |

Credentials go in `/data/onvif-shim/camera.env` (created in Step 5), never in `shim.conf`.

## Day-to-day operation

| Task | Command (on the console) |
|---|---|
| Status | `systemctl status onvif-shim` |
| Live log | `journalctl -u onvif-shim -f -o cat` |
| Recent log | `journalctl -u onvif-shim -n 100 --no-pager -o cat` |
| Restart | `systemctl restart onvif-shim && sleep 2 && sh /data/onvif-shim/rule.sh ensure` |
| **After a UniFi OS update** | `sh /data/onvif-shim/install.sh` |
| **Uninstall** | `sh /data/onvif-shim/install.sh uninstall` (then `rm -rf /data/onvif-shim` to delete the files) |

**Firmware updates:** UniFi OS updates can wipe the systemd units in `/etc` and the firewall rules. Your files in `/data` survive. If motion stops after an update, re-run `install.sh`. SSH keys may also need re-adding with `ssh-copy-id`.

**Camera IP change / adding a camera:** update `SHIM_CAM_HOSTS`, restart, and update the camera's address in Protect.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `circuit-breaker fired` still appearing | The shim isn't in the path. Check `systemctl is-active onvif-shim` and that the DNAT rule exists. Run `sh /data/onvif-shim/rule.sh ensure`. |
| Shim log shows no `event arrived` lines during a walk-test | The camera isn't sending AI events. Check that detection is enabled in the Reolink app and the camera is sending ONVIF events. Try `SHIM_MOTION_MODE=passthrough` to use pixel motion. |
| `motion ON` in the shim log but no event in Protect | Check motion detection is enabled for the camera in Protect, then check `/srv/unifi-protect/logs/events.cameras.log`. |
| `event snapshot attempt … failed` | HTTP isn't enabled on the camera, the credentials are wrong (`camera.env`), or the camera's snapshot service briefly stalled (it retries 3×; Protect then falls back to its normal snapshot). |
| Thumbnails still show the empty scene | `SHIM_SNAPSHOTS=0`, no `camera.env`, or HTTP is disabled on the camera. The shim's startup log line says which. |
| `Snapshot not available` in Protect logs | HTTP (port 80) is disabled on the camera. Needed for *any* third-party thumbnail, with or without the shim. |
| Events in Protect but no phone notification | Add the camera to your **Alarm Manager** motion rule. Also check phone Focus modes and the Protect app's notification settings. |
| `non-200 … deviceIO_service: 400` in the log | Harmless. Reolink doesn't implement that ONVIF service; this happens without the shim too. |
| Motion stopped after the camera rebooted or dropped off; `onvif.events.log` shows `motionDetection available -> unsupported [unsupported: no eventServicePath]` | Shim versions before 1.0.1 closed Protect's connection silently while the camera was unreachable, and Protect took that to mean the camera has no event service. Protect doesn't re-check on its own: update the shim, then remove the camera in Protect and adopt it again. Check it's still in your Alarm Manager motion rule afterwards. |
| Service won't start: `SHIM_CAM_HOSTS is not set` | Create or fix `/data/onvif-shim/shim.conf`. |

Protect's own logs are in `/srv/unifi-protect/logs/`. The useful ones are `onvif.events.log` and `events.cameras.log` (search for the camera's MAC or IP), and `notifications.push.log`.

## How it works (technical)

```
Protect ──► CAMERA_IP:8000 ──[iptables nat OUTPUT DNAT]──► 127.0.0.1:18000 ─┐
Protect ──► CAMERA_IP:80   ──[iptables nat OUTPUT DNAT]──► 127.0.0.1:18080 ─┤  onvif_shim.py
                                                                             │  (python3, stdlib only)
            camera ◄──── shim's own connections, tagged SO_MARK 0x40000000 ◄─┘  (DNAT rules skip marked traffic)
```

- **Transparent redirect:** the DNAT rules are in the `nat OUTPUT` chain, so they only affect connections that start on the console itself, i.e. Protect. The UniFi console's iptables has no `owner` match. Instead, the shim tags its own connections to the camera with a firewall mark, and the rules skip marked traffic, which prevents loops. RTSP (554) is never touched.
- **Header fix:** for `PullMessages`, `Renew`, `Unsubscribe` and `SetSynchronizationPoint`, the shim inserts `wsa:MessageID`, `wsa:ReplyTo`, `wsa:To` (the request URL) and `wsa:Action`. The WS-Security digest only covers nonce + timestamp + password, not the headers, so Protect's authentication stays valid.
- **AI motion:** the shim reads each `PullMessagesResponse`. It drops the camera's `Changed` pixel-motion messages (`CellMotionDetector/Motion`, `VideoSource/MotionAlarm`) and, whenever the OR of all `MyRuleDetector/*Detect` states changes, inserts a `CellMotionDetector/Motion` message built from the AI message itself (same source tokens, new topic, `IsMotion`). "Off" is delayed by `SHIM_OFF_HOLD` and delivered in a later poll if needed. Protect polls about every 4.5 s. `Initialized` messages (a new subscription) reset the state.
- **Thumbnails:** at motion ON, the shim fetches the camera's snapshot with digest auth (3 tries × 5 s). Protect requests third-party thumbnails at motion *end*, twice (cropped and full). For `SHIM_SNAP_SERVE_WINDOW` seconds after motion OFF, requests that already carry an `Authorization` header (sent after the camera's 401 challenge) get the cached image. Everything else passes through.
- **Fail-safe:** a systemd timer runs `rule.sh ensure` every 30 s. It re-adds rules that UniFi flushed, and **removes** them if the shim isn't listening, so Protect falls back to talking to the camera directly (motion stops working, but nothing else breaks). Stopping the service also removes the rules.

## Security considerations

- The shim only listens on `127.0.0.1` and only receives traffic redirected from the console itself.
- Cached snapshots are only returned to requests that already carry an `Authorization` header, which only Protect sends after the camera's challenge. The shim does not check that header itself; anything able to connect to the console's loopback already has root on your console.
- `camera.env` holds the camera password in plain text, readable only by root (mode `600`). Protect already stores the same credentials on the same console, so this doesn't add a new place an attacker could get them. Use a view-only camera user if your model allows it.
- Enabling HTTP on the camera adds its web API to the attack surface. ONVIF (8000) and RTSP (554) are unencrypted HTTP already. **The strongest mitigation is a dedicated camera VLAN**: allow only the console to reach the cameras, and block the cameras from the internet and your other devices. Also consider disabling **UPnP** and **P2P/UID** remote access in the Reolink settings.

## Limitations

- **Multiple cameras run in one process.** Each camera gets its own listener pair and DNAT rules. Cameras with their own login can use `SHIM_CAM_USER.<ip>=` / `SHIM_CAM_PASS.<ip>=` in `camera.env`; the plain `SHIM_CAM_USER` / `SHIM_CAM_PASS` apply to the rest.
- **Protect shows plain "Motion", not "Person"/"Vehicle".** Protect doesn't accept third-party smart-detection types. The AI detections decide *when* motion happens, not how it's labeled.
- **Unofficial:** a future Protect or UniFi OS release could change log paths or ONVIF behavior. If Protect ever adds WS-Addressing itself, set `SHIM_MOTION_MODE=passthrough` or uninstall.
- AI-driven motion depends on Reolink's `MyRuleDetector/*Detect` ONVIF topics. Cameras without onboard AI should use `passthrough`.

## Related tips

- **Playback stalls / buffering dots:** Protect records a single stream from third-party cameras, the camera's main stream. At 8–12 MP H.265, that's beyond many phones' hardware decoders and heavy over remote connections. Setting the Reolink main stream to **3840×2160, 4–6 Mbps, 15–20 fps, I-frame interval 1–2× fps** usually fixes it and saves storage too.
- **Camera clock:** Reolink clocks can drift even with NTP on. Point NTP at `pool.ntp.org` or your gateway.

---

*Contributions welcome, especially test results from other Reolink models and UniFi consoles.*

## Version history

Version numbers follow [semantic versioning](https://semver.org/): a bug fix bumps the last number, new features or settings bump the middle number, and a change that needs you to edit your config or reinstall bumps the first.

To see which version you're running, compare the checksum of your copy (`md5sum /data/onvif-shim/onvif_shim.py`) with the table.

| Version | Date | `onvif_shim.py` md5 | Changes |
|---|---|---|---|
| **1.0.1** | 2026-10-19 | `a533a3ec06673ae3c63593004af9a054` | **Fix:** motion could stop permanently after the camera rebooted or briefly dropped off the network. While the camera was unreachable, the shim closed Protect's connection without a response. Protect took that to mean the camera has no event service and marked motion `unsupported: no eventServicePath`, a state it never re-checks. The shim now resets the connection instead, so Protect treats the camera as temporarily unreachable and retries. If you were already affected, update, then remove and re-adopt the camera in Protect (see [Troubleshooting](#troubleshooting)). Also: `.gitignore` now excludes editor swap files, which can contain the camera password. |
| **1.0.0** | 2026-09-24 | `f6a196d52b8dee7ea73522610a8841d3` | First release: WS-Addressing header fix, AI-driven motion, motion-start thumbnails, `shim.conf` configuration, installer and fail-safe firewall rules. |

**Upgrading:** copy the new `onvif_shim.py` to `/data/onvif-shim/`, then run `systemctl restart onvif-shim && sleep 2 && sh /data/onvif-shim/rule.sh ensure`. Your `shim.conf` and `camera.env` are unchanged.

## License

[MIT](LICENSE)
