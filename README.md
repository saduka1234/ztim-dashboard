# ZTIM Security Dashboard

Real-time monitoring dashboard for the Zero-Trust Intelligent Monitoring (ZTIM) lab.
Standalone Flask + SocketIO app — reads from Suricata, the threat engine, and OVS.
It does **not** modify the existing Phase 3 threat-engine pipeline.

## What it shows
- Login gate (lab-grade demo auth — see note below)
- Live threat feed (real-time Suricata alerts via WebSocket)
- Stats: total alerts, blocked IPs, unique sources, services up (all clickable for detail)
- Active OVS block rules (drop flows on `br-zt`)
- Connected devices (read passively from the OVS `br-zt` MAC table)
- Threat history table
- System health (Suricata, threat-engine, Open vSwitch)

## Login
Default credentials (lab demo only):
- Username: `admin`
- Password: `abc@123`

> Note: this is a lab-grade access gate for demonstration, not production
> authentication. Credentials are stored in `app.py` and traffic is plain HTTP.
> Change `LOGIN_USER`, `LOGIN_PASS`, and `app.secret_key` before any real use.

## Layout
```
ztim-dashboard/
├── app.py                   # Flask + SocketIO backend
├── templates/index.html     # Dashboard frontend
├── requirements.txt
├── ztim-dashboard.service   # systemd unit
└── README.md
```

## Setup on Ubuntu

Clone into the home directory:
```bash
cd ~
git clone https://github.com/<your-username>/ztim-dashboard.git
cd ztim-dashboard
```

Install dependencies:
```bash
pip3 install flask flask-socketio
```

Test run:
```bash
python3 app.py
```
Then browse to `http://<ubuntu-ip>:5000` (e.g. http://192.168.50.200:5000).
Press Ctrl+C to stop.

## Run as a service (auto-start on boot)
```bash
sudo cp ztim-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ztim-dashboard
sudo systemctl status ztim-dashboard
```

## Notes / paths
If your paths differ, edit the constants at the top of `app.py`:
- `EVE_LOG`   = /var/log/suricata/eve.json
- `THREAT_LOG`= /var/log/threat_engine/service.log
- `OVS_BRIDGE`= br-zt

The dashboard runs `sudo ovs-ofctl ... dump-flows` to read block rules. Running the
service as root (as in the unit file) keeps this working without a sudoers entry.
