import json
import os
import subprocess
import threading
import time
from functools import wraps
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_socketio import SocketIO

app = Flask(__name__)
app.secret_key = "ztim-lab-secret-change-me"
socketio = SocketIO(app, cors_allowed_origins="*")

# ---- Lab-grade login (demo only, not production auth) ----
LOGIN_USER = "admin"
LOGIN_PASS = "abc@123"


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

# ---- Paths (adjust here if your setup differs) ----
EVE_LOG = "/var/log/suricata/eve.json"
THREAT_LOG = "/var/log/threat_engine/service.log"
OVS_BRIDGE = "br-zt"

# ---- In-memory storage ----
threat_history = []
MAX_HISTORY = 500


def get_ovs_flows():
    """Return current OVS drop rules (active block rules)."""
    try:
        result = subprocess.run(
            ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", OVS_BRIDGE],
            capture_output=True, text=True, timeout=5
        )
        flows = []
        for line in result.stdout.strip().split("\n"):
            if "actions=drop" in line:
                flows.append(line.strip())
        return flows
    except Exception:
        return []


def get_blocked_ips():
    """Parse just the blocked source IPs out of the OVS drop flows."""
    import re
    ips = []
    for flow in get_ovs_flows():
        # Match nw_src=... (IPv4) or ipv6_src=... (IPv6)
        m = re.search(r"(?:nw_src|ipv6_src)=([^\s,]+)", flow)
        if m:
            ips.append(m.group(1))
    return ips


def get_connected_devices():
    """Read the OVS MAC-learning table (FDB) to list devices passing traffic through br-zt."""
    devices = []
    try:
        result = subprocess.run(
            ["sudo", "ovs-appctl", "fdb/show", OVS_BRIDGE],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        # Header line looks like: " port  VLAN  MAC                Age"
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                devices.append({
                    "port": parts[0],
                    "vlan": parts[1],
                    "mac": parts[2],
                    "age": parts[3],
                })
    except Exception:
        pass
    return devices


def get_service_status(service):
    """Check if a systemd service is active."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def tail_eve_log():
    """Watch Suricata eve.json for new alerts and push them over WebSocket."""
    # Wait for the log file to exist
    while not os.path.exists(EVE_LOG):
        time.sleep(2)
    with open(EVE_LOG, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alert = {
                            "timestamp": data.get("timestamp", ""),
                            "src_ip": data.get("src_ip", "N/A"),
                            "dest_ip": data.get("dest_ip", "N/A"),
                            "signature": data.get("alert", {}).get("signature", "N/A"),
                            "severity": data.get("alert", {}).get("severity", 0),
                            "category": data.get("alert", {}).get("category", "N/A"),
                            "protocol": data.get("proto", "N/A"),
                        }
                        threat_history.insert(0, alert)
                        if len(threat_history) > MAX_HISTORY:
                            threat_history.pop()
                        socketio.emit("new_alert", alert)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.5)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == LOGIN_USER and request.form.get("password") == LOGIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify(get_connected_devices())


@app.route("/api/threats")
@login_required
def api_threats():
    return jsonify(threat_history)


@app.route("/api/flows")
@login_required
def api_flows():
    return jsonify(get_ovs_flows())


@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "suricata": get_service_status("suricata"),
        "threat_engine": get_service_status("threat-engine"),
        "openvswitch": get_service_status("openvswitch-switch"),
    })


@app.route("/api/analytics/signatures")
@login_required
def api_sig_breakdown():
    """Count alerts grouped by signature (top signatures first)."""
    counts = {}
    for a in threat_history:
        sig = a.get("signature", "N/A")
        counts[sig] = counts.get(sig, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return jsonify([{"signature": s, "count": c} for s, c in ranked])


@app.route("/api/analytics/sources")
@login_required
def api_source_breakdown():
    """Count alerts grouped by source IP (most active first)."""
    counts = {}
    for a in threat_history:
        ip = a.get("src_ip", "N/A")
        counts[ip] = counts.get(ip, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return jsonify([{"src_ip": ip, "count": c} for ip, c in ranked])


@app.route("/api/analytics/blocked")
@login_required
def api_blocked_breakdown():
    """Return the list of blocked source IPs."""
    return jsonify(get_blocked_ips())


@app.route("/api/analytics/services")
@login_required
def api_service_detail():
    """Detailed per-service status."""
    services = {
        "Suricata IDS": "suricata",
        "Threat Engine": "threat-engine",
        "Open vSwitch": "openvswitch-switch",
    }
    detail = []
    for label, unit in services.items():
        detail.append({"name": label, "unit": unit, "status": get_service_status(unit)})
    return jsonify(detail)


if __name__ == "__main__":
    watcher = threading.Thread(target=tail_eve_log, daemon=True)
    watcher.start()
    socketio.run(app, host="0.0.0.0", port=5000)
