#!/usr/bin/env python3
"""ONVIF shim for UniFi Protect <-> Reolink cameras.

Runs on the UniFi console (UDM / UDM Pro / UNVR, etc.) and sits between
UniFi Protect and one or more third-party ONVIF cameras via iptables nat
OUTPUT DNAT rules (one listener pair per camera, all in this one process). It:

  1. Adds the WS-Addressing headers (wsa:To / wsa:Action) that Reolink's gSOAP
     event service requires but Protect's PullMessages requests omit (without
     them every PullMessages gets HTTP 400 and Protect never sees motion).
  2. Optionally drives Protect's motion from the camera's AI detections
     (person / vehicle / animal) instead of its erratic pixel-motion signal.
  3. Optionally captures a snapshot at motion start and hands it to Protect
     when Protect fetches the event thumbnail at motion end.

Upstream sockets are tagged with SO_MARK so the DNAT rules skip them.
Python 3 standard library only. See README.md.
"""
import http.client
import os
import re
import socket
import socketserver
import sys
import threading
import time
import urllib.request
import uuid
from xml.sax.saxutils import escape

LISTEN_HOST = os.environ.get("SHIM_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("SHIM_LISTEN_PORT", "18000"))
CAM_HOSTS = [h.strip() for h in (os.environ.get("SHIM_CAM_HOSTS")
                                  or os.environ.get("SHIM_CAM_HOST", "")).split(",") if h.strip()]
CAM_PORT = int(os.environ.get("SHIM_CAM_PORT", "8000"))
MARK = int(os.environ.get("SHIM_MARK", "0x40000000"), 16)
SO_MARK = getattr(socket, "SO_MARK", 36)
CRED_FILE = os.environ.get("SHIM_CRED_FILE", "/data/onvif-shim/camera.env")


def load_creds(host):
    """Read SHIM_CAM_USER / SHIM_CAM_PASS from CRED_FILE, values taken literally.

    SHIM_CAM_USER.<camera ip> / SHIM_CAM_PASS.<camera ip> override them for one camera.
    """
    creds = {}
    try:
        with open(CRED_FILE) as f:
            for line in f:
                key, sep, value = line.rstrip("\r\n").partition("=")
                if sep:
                    creds[key.strip()] = value
    except OSError:
        pass
    return tuple(creds.get("%s.%s" % (k, host), creds.get(k)) for k in ("SHIM_CAM_USER", "SHIM_CAM_PASS"))


SNAP_LISTEN_PORT = int(os.environ.get("SHIM_SNAP_LISTEN_PORT", "18080"))
CAM_HTTP_PORT = int(os.environ.get("SHIM_CAM_HTTP_PORT", "80"))
SNAPSHOTS = os.environ.get("SHIM_SNAPSHOTS", "1") == "1"
SNAP_PATH = os.environ.get("SHIM_SNAP_PATH", "/cgi-bin/api.cgi?cmd=onvifSnapPic&channel=0")
SNAP_SERVE_WINDOW = float(os.environ.get("SHIM_SNAP_SERVE_WINDOW", "20"))


class MarkedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose socket carries SO_MARK, so the DNAT rule skips it."""

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
        self.sock.settimeout(self.timeout if isinstance(self.timeout, (int, float)) else 10)
        self.sock.connect((self.host, self.port))


class MarkedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(MarkedHTTPConnection, req)


class SnapshotCache:
    """Grab a snapshot when motion starts; hand it to Protect at event end.

    Protect fetches a third-party camera's event thumbnail when the motion
    event *stops* -- by then the subject has usually left. We capture at
    motion start and, for SNAP_SERVE_WINDOW seconds after motion stops,
    answer Protect's authenticated snapshot requests with that image.
    """

    def __init__(self, cam):
        self.cam = cam
        self.lock = threading.Lock()
        self.image = None
        self.ended_at = None
        self.gen = 0
        self.opener = None
        self.user, pw = load_creds(cam.host)
        if SNAPSHOTS and self.user and pw:
            pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pm.add_password(None, "http://%s:%d/" % (cam.host, CAM_HTTP_PORT), self.user, pw)
            self.opener = urllib.request.build_opener(
                MarkedHTTPHandler,
                urllib.request.HTTPDigestAuthHandler(pm),
                urllib.request.HTTPBasicAuthHandler(pm))

    def enabled(self):
        return self.opener is not None

    def motion_started(self):
        if not self.enabled():
            return
        with self.lock:
            self.image, self.ended_at = None, None
            self.gen += 1
            gen = self.gen
        threading.Thread(target=self._capture, args=(gen,), daemon=True).start()

    def motion_stopped(self):
        with self.lock:
            self.ended_at = time.monotonic()

    def _capture(self, gen, attempts=3, timeout=5):
        # The camera's snapshot service occasionally stalls; retry briefly.
        t = time.monotonic()
        for attempt in range(1, attempts + 1):
            try:
                r = self.opener.open("http://%s:%d%s" % (self.cam.host, CAM_HTTP_PORT, SNAP_PATH), timeout=timeout)
                data = r.read()
                if data[:2] != b"\xff\xd8":
                    raise ValueError("not a JPEG (%d bytes)" % len(data))
                break
            except Exception as e:  # noqa: BLE001 -- log and fall back to pass-through
                self.cam.log("event snapshot attempt %d/%d failed: %s: %s" % (attempt, attempts, type(e).__name__, e))
                with self.lock:
                    if gen != self.gen or self.ended_at is not None:
                        return  # event over or superseded; Protect fetches its own
        else:
            return
        with self.lock:
            if gen != self.gen:
                return  # a newer event started meanwhile
            self.image = data
        self.cam.log("event snapshot captured (%d KB in %.2fs)" % (len(data) // 1024, time.monotonic() - t))

    def image_for_protect(self):
        """The motion-start image if Protect is fetching its end-of-event thumbnail."""
        with self.lock:
            if (self.image and self.ended_at is not None
                    and time.monotonic() - self.ended_at <= SNAP_SERVE_WINDOW):
                return self.image
        return None


WSA_NS = "http://www.w3.org/2005/08/addressing"
ACTIONS = {
    "PullMessages": "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest",
    "SetSynchronizationPoint": "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/SetSynchronizationPointRequest",
    "Renew": "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest",
    "Unsubscribe": "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
}
BODY_OP_RE = re.compile(rb"<(?:[\w.-]+:)?Body[^>]*>\s*<(?:[\w.-]+:)?(\w+)[\s>/]")
HEADER_RE = re.compile(rb"<((?:[\w.-]+:)?)Header(\s[^>]*)?>")
ENVELOPE_RE = re.compile(rb"<((?:[\w.-]+:)?)Envelope[\s>]")

MSG_RE = re.compile(rb"<(?:[\w.-]+:)?NotificationMessage>.*?</(?:[\w.-]+:)?NotificationMessage>", re.S)
TOPIC_RE = re.compile(rb"<(?:[\w.-]+:)?Topic[^>]*>([^<]+)<")
UTC_RE = re.compile(rb'UtcTime="([^"]+)"')
DATA_RE = re.compile(rb"<(?:[\w.-]+:)?Data>(.*?)</(?:[\w.-]+:)?Data>", re.S)
ITEM_RE = re.compile(rb'<(?:[\w.-]+:)?SimpleItem\s+Name="([^"]+)"\s+Value="([^"]*)"')
LOG_EVENTS = os.environ.get("SHIM_LOG_EVENTS", "1") == "1"



def log(msg):
    print(msg, flush=True)


def inject_wsa(body, host, path):
    """Return body with wsa:To/Action added, or None if not applicable."""
    if WSA_NS.encode() in body:
        return None
    m = BODY_OP_RE.search(body)
    if not m:
        return None
    action = ACTIONS.get(m.group(1).decode())
    if not action:
        return None
    env = ENVELOPE_RE.search(body)
    soap = env.group(1).decode() if env else ""
    to = escape("http://%s%s" % (host, path))
    wsa = (
        '<wsa:MessageID xmlns:wsa="{ns}">urn:uuid:{mid}</wsa:MessageID>'
        '<wsa:ReplyTo xmlns:wsa="{ns}"><wsa:Address>{ns}/anonymous</wsa:Address></wsa:ReplyTo>'
        '<wsa:To xmlns:wsa="{ns}" {s}mustUnderstand="1">{to}</wsa:To>'
        '<wsa:Action xmlns:wsa="{ns}" {s}mustUnderstand="1">{action}</wsa:Action>'
    ).format(ns=WSA_NS, mid=uuid.uuid4(), s=soap, to=to, action=action).encode()
    h = HEADER_RE.search(body)
    if h:
        return body[: h.end()] + wsa + body[h.end():]
    # No Header element at all: create one right after the Envelope open tag.
    if not env:
        return None
    end = body.index(b">", env.start()) + 1
    return body[:end] + b"<" + env.group(1) + b"Header>" + wsa + b"</" + env.group(1) + b"Header>" + body[end:]


def log_events(cam, resp):
    """Log each event notification with the camera's UtcTime vs. our arrival time."""
    arrived = time.strftime("%H:%M:%S", time.gmtime()) + ".%03d" % (time.time() % 1 * 1000)
    for m in MSG_RE.finditer(resp):
        msg = m.group(0)
        topic = TOPIC_RE.search(msg)
        utc = UTC_RE.search(msg)
        data = DATA_RE.search(msg)
        items = ITEM_RE.findall(data.group(1)) if data else []
        cam.log("event arrived=%sZ cam=%s topic=%s %s" % (
            arrived,
            utc.group(1).decode() if utc else "?",
            topic.group(1).decode().strip().split(":")[-1] if topic else "?",
            " ".join("%s=%s" % (k.decode(), v.decode()) for k, v in items)))


MOTION_MODE = os.environ.get("SHIM_MOTION_MODE", "ai")  # "ai" or "passthrough"
OFF_HOLD = float(os.environ.get("SHIM_OFF_HOLD", "10"))
MOTION_TOPIC_SUFFIX = b"RuleEngine/CellMotionDetector/Motion"
RAW_MOTION_TOPICS = (b"CellMotionDetector/Motion", b"VideoSource/MotionAlarm")
AI_TOPIC_RE = re.compile(rb"MyRuleDetector/\w*Detect$")
PROP_OP_RE = re.compile(rb'PropertyOperation="([^"]+)"')
RESP_END_RE = re.compile(rb"</(?:[\w.-]+:)?PullMessagesResponse>")


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class MotionTranslator:
    """Drive Protect's motion from the camera's AI detections.

    Reolink's pixel-motion signal (CellMotionDetector / MotionAlarm) fires
    late and erratically, while its AI detections (PeopleDetect, VehicleDetect,
    DogCatDetect, ...) track presence accurately. Protect only reads the
    former, so: drop raw "Changed" motion messages and emit a synthetic
    CellMotionDetector/Motion message whenever the OR of all AI detections
    changes. "Off" is held for OFF_HOLD seconds to bridge brief detection
    dropouts, and is delivered in a later PullMessages response if needed.
    """

    def __init__(self, cam):
        self.cam = cam
        self.lock = threading.Lock()
        self.active = set()        # AI topics currently true
        self.motion = False        # what Protect was last told
        self.off_due = None        # monotonic time a pending "off" is due
        self.template = None       # last AI message, reused to build "off"
        self.raw_logged = set()

    def _synth(self, msg, value):
        """Turn an AI NotificationMessage into a CellMotionDetector/Motion one."""
        msg = TOPIC_RE.sub(
            lambda m: m.group(0).replace(
                m.group(1), m.group(1).split(b":")[0] + b":" + MOTION_TOPIC_SUFFIX
                if b":" in m.group(1) else MOTION_TOPIC_SUFFIX),
            msg, count=1)
        msg = PROP_OP_RE.sub(b'PropertyOperation="Changed"', msg, count=1)
        msg = UTC_RE.sub(b'UtcTime="' + utc_now().encode() + b'"', msg, count=1)

        def data_sub(m):
            item = ITEM_RE.search(m.group(1))
            if not item:
                return m.group(0)
            new_item = item.group(0).replace(
                b'Name="' + item.group(1) + b'"', b'Name="IsMotion"').replace(
                b'Value="' + item.group(2) + b'"', b'Value="' + value + b'"')
            return m.group(0).replace(item.group(0), new_item, 1)
        return DATA_RE.sub(data_sub, msg, count=1)

    def _log_raw_once(self, topic, msg):
        if topic not in self.raw_logged and len(self.raw_logged) < 20:
            self.raw_logged.add(topic)
            self.cam.log("raw sample %s: %s" % (topic.decode(errors="replace"),
                                       msg.decode(errors="replace")[:1500]))

    def rewrite_response(self, resp):
        head, sep, body = resp.partition(b"\r\n\r\n")
        if not sep or b"chunked" in head.lower() or b" 200 " not in head.split(b"\r\n", 1)[0]:
            return resp
        with self.lock:
            out, pos = [], 0
            for m in MSG_RE.finditer(body):
                msg = m.group(0)
                out.append(body[pos:m.start()])
                pos = m.end()
                t = TOPIC_RE.search(msg)
                topic = t.group(1).strip() if t else b""
                op = PROP_OP_RE.search(msg)
                op = op.group(1) if op else b""
                self._log_raw_once(topic, msg)
                if op == b"Initialized" and self.motion:
                    # New subscription: Protect's motion state starts at false.
                    self.motion, self.off_due = False, None
                if AI_TOPIC_RE.search(topic):
                    out.append(msg)  # keep original AI message too
                    item = ITEM_RE.search((DATA_RE.search(msg) or m).group(0))
                    on = bool(item) and item.group(2).lower() == b"true"
                    (self.active.add if on else self.active.discard)(topic)
                    self.template = msg
                    if self.active:
                        self.off_due = None
                        if not self.motion:
                            self.motion = True
                            out.append(self._synth(msg, b"true"))
                            self.cam.snapshots.motion_started()
                            self.cam.log("motion ON  (AI: %s)" % b",".join(
                                x.split(b"/")[-1] for x in sorted(self.active)).decode())
                    elif self.motion and self.off_due is None:
                        self.off_due = time.monotonic() + OFF_HOLD
                elif any(topic.endswith(r) for r in RAW_MOTION_TOPICS) and op == b"Changed":
                    continue  # drop the unreliable pixel-motion signal
                else:
                    out.append(msg)
            out.append(body[pos:])
            new_body = b"".join(out)

            if self.motion and self.off_due is not None and time.monotonic() >= self.off_due:
                self.motion = False
                self.off_due = None
                end = RESP_END_RE.search(new_body)
                if end and self.template:
                    new_body = (new_body[:end.start()] + self._synth(self.template, b"false")
                                + new_body[end.start():])
                self.cam.log("motion OFF")
                self.cam.snapshots.motion_stopped()

        if new_body == body:
            return resp
        head = re.sub(rb"(?im)^content-length:\s*\d+", b"Content-Length: " + str(len(new_body)).encode(), head)
        return head + sep + new_body


class Camera:
    """Per-camera state; camera n listens on LISTEN_PORT+n / SNAP_LISTEN_PORT+n."""

    def __init__(self, index, host, prefix_logs):
        self.host = host
        self.listen_port = LISTEN_PORT + index
        self.snap_listen_port = SNAP_LISTEN_PORT + index
        self.prefix = "[%s] " % host if prefix_logs else ""
        self.stats = {"requests": 0, "injected": 0, "non200": 0, "snapshots_served": 0}
        self.stats_lock = threading.Lock()
        self.snapshots = SnapshotCache(self)
        self.translator = MotionTranslator(self)

    def log(self, msg):
        log(self.prefix + msg)

    def bump(self, key):
        with self.stats_lock:
            self.stats[key] += 1


def read_request(rfile):
    """Read one HTTP request. Returns (request_line, headers[list], body) or None on EOF."""
    line = rfile.readline(65536)
    while line in (b"\r\n", b"\n"):
        line = rfile.readline(65536)
    if not line:
        return None
    headers = []
    while True:
        h = rfile.readline(65536)
        if not h or h in (b"\r\n", b"\n"):
            break
        headers.append(h.rstrip(b"\r\n"))
    lower = {k.strip().lower(): v.strip() for k, _, v in (x.partition(b":") for x in headers)}
    body = b""
    if lower.get(b"transfer-encoding", b"").lower() == b"chunked":
        while True:
            size = int(rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                break
            body += rfile.read(size)
            rfile.readline()
        headers = [x for x in headers if x.split(b":")[0].strip().lower() != b"transfer-encoding"]
    elif b"content-length" in lower:
        body = rfile.read(int(lower[b"content-length"]))
    return line, headers, body


class Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def handle(self):
        cam = self.server.cam
        req = read_request(self.rfile)
        if req is None:
            return
        line, headers, body = req
        cam.bump("requests")
        port = self.server.upstream_port
        host = cam.host + ":" + str(port)
        authorized = False
        for x in headers:
            k, _, v = x.partition(b":")
            k = k.strip().lower()
            if k == b"host":
                host = v.strip().decode(errors="replace")
            elif k == b"authorization":
                authorized = True
        parts = line.split(b" ")
        path = parts[1].decode(errors="replace") if len(parts) > 1 else "/"

        if port == CAM_HTTP_PORT:
            # Only answer once Protect has authenticated (it retries after the
            # camera's 401 challenge), so unauthenticated callers get nothing.
            img = cam.snapshots.image_for_protect() if (
                authorized and path.startswith(SNAP_PATH.split("&")[0])) else None
            if img:
                self.wfile.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: "
                    + str(len(img)).encode() + b"\r\nConnection: close\r\n\r\n" + img)
                self.wfile.flush()
                cam.bump("snapshots_served")
                cam.log("served motion-start snapshot to Protect (%d KB)" % (len(img) // 1024))
                return
        else:
            new_body = inject_wsa(body, host, path) if body else None
            if new_body is not None:
                body = new_body
                cam.bump("injected")

        out = [line.rstrip(b"\r\n")]
        for x in headers:
            k = x.split(b":")[0].strip().lower()
            if k in (b"content-length", b"connection", b"keep-alive"):
                continue
            out.append(x)
        if body or parts[0] in (b"POST", b"PUT"):
            out.append(b"Content-Length: " + str(len(body)).encode())
        out.append(b"Connection: close")
        raw = b"\r\n".join(out) + b"\r\n\r\n" + body

        up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            up.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
            up.settimeout(90)
            up.connect((cam.host, port))
            up.sendall(raw)
            if "PullSubManager" in path:
                # Event responses are small: buffer, translate, then send.
                chunks = []
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                resp = b"".join(chunks)
                if LOG_EVENTS:
                    log_events(cam, resp)
                if MOTION_MODE == "ai":
                    resp = cam.translator.rewrite_response(resp)
                self.wfile.write(resp)
                self.wfile.flush()
                return
            first = True
            while True:
                chunk = up.recv(65536)
                if not chunk:
                    break
                if first:
                    first = False
                    status = chunk.split(b"\r\n", 1)[0]
                    challenge = port == CAM_HTTP_PORT and b" 401 " in status
                    if b" 200 " not in status and not challenge:
                        cam.bump("non200")
                        cam.log("non-200 from camera for %s %s: %s" % (
                            parts[0].decode(errors="replace"), path,
                            status.decode(errors="replace")))
                self.wfile.write(chunk)
            self.wfile.flush()
        except OSError as e:
            cam.log("upstream error for %s: %s" % (path, e))
        finally:
            up.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def stats_loop(cams):
    while True:
        time.sleep(3600)
        for cam in cams:
            with cam.stats_lock:
                cam.log("stats: %s" % cam.stats)


def serve(cam, listen_port, upstream_port):
    srv = Server((LISTEN_HOST, listen_port), Handler)
    srv.cam = cam
    srv.upstream_port = upstream_port
    log("listening on %s:%d -> %s:%d (mark 0x%x)" % (
        LISTEN_HOST, listen_port, cam.host, upstream_port, MARK))
    return srv


def main():
    if not CAM_HOSTS:
        log("SHIM_CAM_HOSTS is not set (see shim.conf); exiting")
        return 2
    if len(set(CAM_HOSTS)) != len(CAM_HOSTS):
        log("SHIM_CAM_HOSTS lists a camera twice; exiting")
        return 2
    if LISTEN_PORT + len(CAM_HOSTS) > SNAP_LISTEN_PORT:
        log("too many cameras for the port gap between SHIM_LISTEN_PORT and SHIM_SNAP_LISTEN_PORT; exiting")
        return 2
    cams = [Camera(i, h, len(CAM_HOSTS) > 1) for i, h in enumerate(CAM_HOSTS)]
    log("motion mode: %s; cameras: %d" % (MOTION_MODE, len(cams)))
    servers = []
    for cam in cams:
        cam.log("thumbnails: %s" % (
            "motion-start capture enabled (user %r)" % cam.snapshots.user if cam.snapshots.enabled()
            else "disabled" if not SNAPSHOTS
            else "no credentials in %s, passing through" % CRED_FILE))
        if SNAPSHOTS:
            servers.append(serve(cam, cam.snap_listen_port, CAM_HTTP_PORT))
        servers.append(serve(cam, cam.listen_port, CAM_PORT))
    threading.Thread(target=stats_loop, args=(cams,), daemon=True).start()
    for srv in servers[:-1]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[-1].serve_forever()


if __name__ == "__main__":
    sys.exit(main())
