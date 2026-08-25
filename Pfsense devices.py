"""
pfSense device inventory collector.

Connects to the pfSense firewall over SSH (read-only) and builds a list of
devices seen across all five departmental VLANs, rather than only the Server
VLAN segment visible to the OVS bridge br-zt.

Two sources are combined:
  * `arp -an`      - every host the firewall has resolved on any interface.
                     This is the primary source and catches static-IP hosts
                     such as the Windows Server domain controller.
  * DHCP leases    - adds hostnames where a lease exists.

VLAN membership is derived from the pfSense interface the host was seen on
(em1 = HR, em2 = Finance, ...). This is an interface-to-VLAN mapping, not
802.1Q tag inspection, and should be described that way in any write-up.

Credentials are read from /etc/ztim/pfsense.conf (root-readable only) so that
no password is stored in this file or in version control.
"""

import os
import re
import configparser
import threading
import time

try:
    import paramiko
except ImportError:  # keep the dashboard usable if paramiko is absent
    paramiko = None


CONFIG_PATH = "/etc/ztim/pfsense.conf"

# pfSense interface -> (VLAN ID, department). Taken from the console interface
# assignment list; update here if interfaces are ever reassigned.
INTERFACE_MAP = {
    "em0": (None, "WAN"),
    "em1": (10, "HR"),
    "em2": (20, "Finance"),
    "em3": (30, "IT"),
    "em4": (40, "Guest"),
    "em5": (50, "Server"),
}

# Fallback subnet -> (VLAN ID, department), used when the interface name is
# missing from the ARP line for any reason.
SUBNET_MAP = {
    "192.168.10.": (10, "HR"),
    "192.168.20.": (20, "Finance"),
    "192.168.30.": (30, "IT"),
    "192.168.40.": (40, "Guest"),
    "192.168.50.": (50, "Server"),
}

# ARP line, e.g.
#   ? (192.168.10.20) at 00:0c:29:16:d0:49 on em1 expires in 1183 seconds [ethernet]
ARP_RE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]{11,17})\s+on\s+(?P<iface>\w+)"
)

# ISC dhcpd lease block fields
LEASE_IP_RE = re.compile(r"^lease\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s*\{")
LEASE_HOST_RE = re.compile(r'client-hostname\s+"(?P<host>[^"]+)"')
LEASE_MAC_RE = re.compile(r"hardware\s+ethernet\s+(?P<mac>[0-9a-fA-F:]{11,17})")

# Commands run on the firewall. Both are read-only.
CMD_ARP = "arp -an"
CMD_LEASES = (
    "cat /var/dhcpd/var/db/dhcpd.leases 2>/dev/null || "
    "cat /var/db/dhcpd.leases 2>/dev/null || true"
)

# Cache so the dashboard's 5-second refresh does not open an SSH session each time.
_cache = {"devices": [], "fetched_at": 0.0, "error": None}
_cache_lock = threading.Lock()
CACHE_TTL = 60  # seconds


def _load_config():
    """Read SSH connection details. Returns dict or None if not configured."""
    if not os.path.exists(CONFIG_PATH):
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read(CONFIG_PATH)
        section = parser["pfsense"]
        return {
            "host": section.get("host", "192.168.50.1"),
            "port": section.getint("port", 22),
            "username": section.get("username", "admin"),
            "password": section.get("password", fallback=None),
            "key_file": section.get("key_file", fallback=None),
        }
    except Exception:
        return None


def classify(ip, iface):
    """Map a device to (vlan_id, department) using interface first, subnet second."""
    if iface in INTERFACE_MAP:
        return INTERFACE_MAP[iface]
    for prefix, value in SUBNET_MAP.items():
        if ip.startswith(prefix):
            return value
    return (None, "Unknown")


def parse_arp(output):
    """Parse `arp -an` output into a dict keyed by IP."""
    devices = {}
    for line in output.splitlines():
        m = ARP_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        iface = m.group("iface")
        vlan, dept = classify(ip, iface)
        devices[ip] = {
            "ip": ip,
            "mac": m.group("mac").lower(),
            "interface": iface,
            "vlan": vlan,
            "department": dept,
            "hostname": None,
            "source": "ARP",
        }
    return devices


def parse_leases(output):
    """Parse ISC dhcpd leases into {ip: {hostname, mac}}.

    Later blocks for the same IP overwrite earlier ones, which matches dhcpd's
    append-only file format where the last entry is current.
    """
    leases = {}
    current_ip = None
    current = {}
    for line in output.splitlines():
        stripped = line.strip()
        m = LEASE_IP_RE.match(stripped)
        if m:
            current_ip = m.group("ip")
            current = {"hostname": None, "mac": None}
            continue
        if current_ip is None:
            continue
        h = LEASE_HOST_RE.search(stripped)
        if h:
            current["hostname"] = h.group("host")
        mac = LEASE_MAC_RE.search(stripped)
        if mac:
            current["mac"] = mac.group("mac").lower()
        if stripped.startswith("}"):
            leases[current_ip] = current
            current_ip = None
    return leases


def merge(arp_devices, leases):
    """Add lease hostnames to ARP devices, and include lease-only hosts."""
    for ip, lease in leases.items():
        if ip in arp_devices:
            if lease.get("hostname"):
                arp_devices[ip]["hostname"] = lease["hostname"]
        elif lease.get("mac"):
            vlan, dept = classify(ip, None)
            arp_devices[ip] = {
                "ip": ip,
                "mac": lease["mac"],
                "interface": None,
                "vlan": vlan,
                "department": dept,
                "hostname": lease.get("hostname"),
                "source": "DHCP",
            }
    devices = list(arp_devices.values())
    # Sort by VLAN then by final IP octet so departments group together.
    def sort_key(d):
        try:
            last = int(d["ip"].split(".")[-1])
        except ValueError:
            last = 0
        return (d["vlan"] if d["vlan"] is not None else 999, last)
    devices.sort(key=sort_key)
    return devices


def _ssh_fetch(config):
    """Open an SSH session and return (arp_output, leases_output)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_args = {
            "hostname": config["host"],
            "port": config["port"],
            "username": config["username"],
            "timeout": 8,
            "banner_timeout": 8,
            "auth_timeout": 8,
        }
        if config.get("key_file"):
            connect_args["key_filename"] = config["key_file"]
        else:
            connect_args["password"] = config["password"]
            connect_args["look_for_keys"] = False
        client.connect(**connect_args)

        def run(cmd):
            _, stdout, _ = client.exec_command(cmd, timeout=10)
            return stdout.read().decode("utf-8", errors="replace")

        return run(CMD_ARP), run(CMD_LEASES)
    finally:
        client.close()


def get_devices(force=False):
    """Return (devices, error). Cached for CACHE_TTL seconds."""
    with _cache_lock:
        age = time.time() - _cache["fetched_at"]
        if not force and age < CACHE_TTL and _cache["fetched_at"] > 0:
            return _cache["devices"], _cache["error"]

    if paramiko is None:
        error = "paramiko is not installed (pip3 install paramiko)"
        with _cache_lock:
            _cache.update({"devices": [], "error": error, "fetched_at": time.time()})
        return [], error

    config = _load_config()
    if not config:
        error = f"pfSense credentials not configured at {CONFIG_PATH}"
        with _cache_lock:
            _cache.update({"devices": [], "error": error, "fetched_at": time.time()})
        return [], error

    try:
        arp_out, lease_out = _ssh_fetch(config)
        devices = merge(parse_arp(arp_out), parse_leases(lease_out))
        with _cache_lock:
            _cache.update({"devices": devices, "error": None, "fetched_at": time.time()})
        return devices, None
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        with _cache_lock:
            # Keep the last good data so a transient failure doesn't blank the panel.
            _cache.update({"error": error, "fetched_at": time.time()})
            return _cache["devices"], error


def summarise(devices):
    """Count devices per department, for the dashboard summary line."""
    counts = {}
    for d in devices:
        counts[d["department"]] = counts.get(d["department"], 0) + 1
    return counts
