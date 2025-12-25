# OpenNMS Multi-Device Adapter

This project provides a Python-based adapter to collect KPIs, interfaces, and alarms for multiple devices from OpenNMS and export them into clean, minimal JSON files. It is intended as a proof-of-concept southbound adapter for EMS/NMS integrations and client demonstrations.

--------------------------------------------------
Features
--------------------------------------------------
- Connects to OpenNMS REST APIs
- Supports multiple devices automatically
- Exports one clean JSON per device
- KPIs collected:
  - CPU 5-minute average
  - Memory used
  - Memory free
- Filters only required operational data
- KPI source can be swapped later (SNMP/RESTCONF/Telemetry)

--------------------------------------------------
Prerequisites
--------------------------------------------------
- Docker and Docker Compose
- Python 3.9+
- Port 8980 free on host

--------------------------------------------------
OpenNMS Image
--------------------------------------------------
This setup uses:

opennms/horizon:bleed

Optimized for macOS (Apple Silicon / ARM).

--------------------------------------------------
Start OpenNMS
--------------------------------------------------
From project root:

docker-compose up -d

Wait 3–5 minutes for OpenNMS to initialize.

Open UI in browser:

http://localhost:8980/opennms

Login:
Username: admin
Password: admin

IMPORTANT: Change the password after first login.

--------------------------------------------------
Script Credentials
--------------------------------------------------
In export_devices.py, update if needed:

USERNAME = "admin"
PASSWORD = "admin"
BASE_URL = "http://localhost:8980/opennms/rest"

Always change these for production use.

--------------------------------------------------
Add Devices to OpenNMS
--------------------------------------------------
From UI:

Admin → Manage Nodes → Add Node

Provide:
- IP / Hostname
- SNMP version (v2c)
- Community string
- Node label

OpenNMS will auto-discover interfaces and start collecting data.

--------------------------------------------------
Custom SNMP Configuration Used
--------------------------------------------------
These files are mounted into the container:

opennms-config/datacollection/cisco.xml
opennms-config/snmp-graph.properties.d/cisco-cpu-cpm.graph.properties

They enable Cisco CPU and memory KPI collection.

--------------------------------------------------
Python Dependencies
--------------------------------------------------
Create a requirements.txt file with:

requests

Install dependencies:

pip install -r requirements.txt

--------------------------------------------------
Run the Adapter
--------------------------------------------------
Execute:

python3 export_devices.py

What it does:
- Fetches all nodes from OpenNMS
- Collects interfaces, alarms, and KPIs
- Writes one clean JSON file per device

Example outputs:
device_3.json
device_4.json

--------------------------------------------------
Sample Output
--------------------------------------------------
{
  "node": {
    "id": "3",
    "name": "cat8000v.cisco.com",
    "label": "CAT8kv-IOSXE",
    "ip": "10.10.20.48",
    "location": "DevNet-Lab"
  },
  "interfaces": [
    {
      "ifIndex": 1,
      "name": "Gi1",
      "descr": "GigabitEthernet1",
      "ip": "10.10.20.48",
      "speed": 1000000000,
      "adminStatus": 1,
      "operStatus": 1
    }
  ],
  "kpis": {
    "cpu_5min": 14.10,
    "memory_used": 198192226.35,
    "memory_free": 1881050069.7
  },
  "alarms": [
    {
      "id": 17,
      "severity": "MINOR",
      "service": "DNS",
      "ip": "192.168.1.1",
      "lastEventTime": 1766638276779
    }
  ],
  "timestamp": "2025-12-25T05:36:44Z"
}

--------------------------------------------------
KPI Source Strategy
--------------------------------------------------
Current:
KPIs are read from OpenNMS RRD files.

Later:
This can be replaced with:
- Direct SNMP polling
- RESTCONF / NETCONF
- Streaming telemetry
- Vendor APIs

The JSON schema remains unchanged.

--------------------------------------------------
Real Device Support
--------------------------------------------------
Any SNMP-enabled physical or virtual device can be added to OpenNMS.
Once added, just rerun the adapter to export its data.

--------------------------------------------------
Use Case
--------------------------------------------------
- EMS/NMS southbound adapter
- Multi-vendor normalization layer
- Client PoC and demo
- Integration prototype

--------------------------------------------------
Author
--------------------------------------------------
Abhay Bansal
OpenNMS Multi-Device Adapter – Proof of Concept
