import json
import os
import subprocess
import threading
import time
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/threats")
def api_threats():
    return jsonify(threat_history)


@app.route("/api/flows")
def api_flows():
    return jsonify(get_ovs_flows())


@app.route("/api/status")
def api_status():
    return jsonify({
        "suricata": get_service_status("suricata"),
        "threat_engine": get_service_status("threat-engine"),
        "openvswitch": get_service_status("openvswitch-switch"),
    })


if __name__ == "__main__":
    watcher = threading.Thread(target=tail_eve_log, daemon=True)
    watcher.start()
    socketio.run(app, host="0.0.0.0", port=5000)
