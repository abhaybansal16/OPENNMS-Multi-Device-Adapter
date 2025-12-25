#!/usr/bin/env python3
import requests
import subprocess
import json
from datetime import datetime, timezone

BASE_URL = "http://localhost:8980/opennms/rest"
AUTH = ("admin", "Abhay@161204")
HEADERS = {"Accept": "application/json"}

RRD_BASE = "/opt/opennms/share/rrd/snmp"
DOCKER = ["docker", "exec", "opennms"]

def get_json(url):
    r = requests.get(url, auth=AUTH, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def rrd_fetch(rrd_path):
    cmd = DOCKER + ["rrdtool", "fetch", rrd_path, "AVERAGE", "-s", "-10min"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        lines = out.strip().splitlines()[1:]
        values = []
        for line in lines:
            val = line.split()[-1]
            if val != "nan":
                values.append(float(val))
        if values:
            return sum(values) / len(values)
    except Exception:
        pass
    return None

def collect_kpis(fs, foreign_id):
    base = f"{RRD_BASE}/{fs}/{foreign_id}"

    cpu = rrd_fetch(f"{base}/cpmCPUTotal5min.rrd")
    mem_used = rrd_fetch(f"{base}/ciscoMemoryPoolUsed.rrd")
    mem_free = rrd_fetch(f"{base}/ciscoMemoryPoolFree.rrd")

    return {
        "cpu_5min": cpu,
        "memory_used": mem_used,
        "memory_free": mem_free
    }

def main():
    devices = {}

    nodes_data = get_json(f"{BASE_URL}/nodes")
    nodes = nodes_data.get("node", [])

    for n in nodes:
        node_id = n["id"]
        node = get_json(f"{BASE_URL}/nodes/{node_id}")
        ifaces_data = get_json(f"{BASE_URL}/nodes/{node_id}/ipinterfaces")
        alarms_data = get_json(f"{BASE_URL}/alarms?node.id={node_id}")

        primary_ip = None
        interfaces = []

        for iface in ifaces_data.get("ipInterface", []):
            snmp = iface.get("snmpInterface")
            if not snmp:
                continue

            ip = iface.get("ipAddress")
            if iface.get("snmpPrimary") == "P":
                primary_ip = ip

            interfaces.append({
                "ifIndex": snmp.get("ifIndex"),
                "name": snmp.get("ifName"),
                "descr": snmp.get("ifDescr"),
                "ip": ip,
                "speed": snmp.get("ifSpeed"),
                "adminStatus": snmp.get("ifAdminStatus"),
                "operStatus": snmp.get("ifOperStatus")
            })

        alarms = []
        for a in alarms_data.get("alarm", []):
            alarms.append({
                "id": a.get("id"),
                "severity": a.get("severity"),
                "service": a.get("serviceType", {}).get("name") if a.get("serviceType") else None,
                "ip": a.get("ipAddress"),
                "description": a.get("logMessage"),
                "lastEventTime": a.get("lastEventTime")
            })

        fs = node.get("foreignSource")
        fid = node.get("foreignId")

        kpis = collect_kpis(fs, fid) if fs and fid else {}

        device_name = node.get("sysName") or node.get("label")

        devices[device_name] = {
            "node": {
                "id": node.get("id"),
                "name": node.get("sysName"),
                "label": node.get("label"),
                "ip": primary_ip,
                "location": node.get("sysLocation"),
                "description": node.get("sysDescription")
            },
            "interfaces": interfaces,
            "kpis": kpis,
            "alarms": alarms
        }

        print(f"[+] Collected {device_name}")

    output = {
        "devices": devices,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    with open("devices.json", "w") as f:
        json.dump(output, f, indent=2)

    print("\n[✓] Export completed -> devices.json")

if __name__ == "__main__":
    main()
