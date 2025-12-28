# OpenNMS Multi-Device Adapter

Python-based adapter to collect KPIs, interfaces, and alarms from multiple devices in OpenNMS and export them into clean, standardized JSON files.

---

## 🚀 Features

- ✅ Connects to OpenNMS REST APIs
- ✅ Supports multiple devices automatically
- ✅ Exports one clean JSON per device
- ✅ Multi-vendor support (Cisco, Huawei, Juniper, Generic SNMP)
- ✅ Collects:
  - **KPIs**: CPU 5-minute average, Memory used/free
  - **Interfaces**: All network ports with status
  - **Alarms**: Active faults and events
  - **Inventory**: Device details and topology

---

## 📋 Prerequisites

- **Python 3.8+**
- **OpenNMS** running (Docker or standalone)
- **Network access** to OpenNMS REST API

---

## 🔧 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/abhaybansai16/OPENNMS-Multi-Device-Adapter.git
cd OPENNMS-Multi-Device-Adapter
```

### 2. Start OpenNMS with Docker Compose

```bash
# Start OpenNMS using the included docker-compose file
docker-compose up -d

# Check if containers are running
docker-compose ps

# Wait for OpenNMS to start (takes 2-3 minutes)
docker-compose logs -f opennms

# Verify OpenNMS is ready
curl -u admin:admin http://localhost:8980/opennms/
```

**Default credentials:** `admin` / `admin`

### 3. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

Or install manually:
```bash
pip3 install requests
```

### 4. Configure Connection (Optional)

The adapter works out-of-the-box with the Docker Compose setup. 

If needed, edit `export_devices.py` (lines 20-28):

```python
@dataclass
class Config:
    base_url: str = "http://localhost:8980/opennms/rest"  # OpenNMS URL
    username: str = "admin"                                 # Username
    password: str = "admin"                                 # Password (change after setup!)
    docker_container: str = "opennms"                      # Container name
```

### 5. Add Devices to OpenNMS

Before running the adapter, add your network devices to OpenNMS:

**Via Web UI:**
1. Open http://localhost:8980/opennms/
2. Login with `admin` / `admin`
3. Go to **Admin → Quick Add Node**
4. Enter device IP and SNMP community
5. Wait 5-10 minutes for data collection

**Via Provisioning (Recommended for multiple devices):**
```bash
# Create requisition
curl -u admin:admin -X POST \
  -H "Content-Type: application/xml" \
  http://localhost:8980/opennms/rest/requisitions \
  -d '<model-import foreign-source="MyNetwork">
        <node foreign-id="router1" node-label="Router-01">
          <interface ip-addr="10.10.20.48" status="1" snmp-primary="P"/>
        </node>
      </model-import>'

# Import and synchronize
curl -u admin:admin -X PUT \
  http://localhost:8980/opennms/rest/requisitions/MyNetwork/import
```

---

## ▶️ Usage

### Run the Adapter
```bash
python3 export_devices.py
```

### View Output
```bash
# View JSON output
cat devices.json

# View summary statistics
cat devices.json | jq '.metadata.statistics'

# View specific device
cat devices.json | jq '.devices["device-name"]'

# Check logs
cat adapter.log
```

---

## 📊 Output Format

The adapter generates a `devices.json` file with this structure:

```json
{
  "metadata": {
    "version": "2.0.0",
    "timestamp": "2025-12-27T14:30:00Z",
    "statistics": {
      "total_devices": 5,
      "devices_with_kpis": 4,
      "total_interfaces": 20,
      "total_alarms": 3
    }
  },
  "devices": {
    "router-01": {
      "node": {
        "id": "5",
        "name": "router-01",
        "ip": "10.10.20.48",
        "location": "DC-01",
        "description": "Cisco IOS-XE Router"
      },
      "kpis": {
        "cpu": {
          "utilization_5min": 14.5,
          "unit": "percent"
        },
        "memory": {
          "used_bytes": 197986896,
          "free_bytes": 1881255400,
          "utilization_percent": 9.52
        },
        "status": "success"
      },
      "interfaces": [
        {
          "ifIndex": 1,
          "name": "GigabitEthernet1",
          "ip": "10.10.20.48",
          "speed": 1000000000,
          "adminStatus": 1,
          "operStatus": 1
        }
      ],
      "alarms": [
        {
          "id": 30,
          "severity": "MINOR",
          "description": "Interface down"
        }
      ]
    }
  }
}
```

---

## 🔍 Supported Vendors

The adapter automatically detects and collects metrics from:

| Vendor | CPU Metric | Memory Metric | Status |
|--------|-----------|---------------|--------|
| **Cisco** | cpmCPUTotal5min | ciscoMemoryPoolUsed | ✅ Tested |
| **Huawei** | hwEntityCpuUsage | hwMemoryUsed | ✅ Ready |
| **Juniper** | jnxOperatingCPU | jnxOperatingBuffer | ✅ Ready |
| **Generic SNMP** | hrProcessorLoad | hrStorageUsed | ✅ Ready |

To add more vendors, edit `METRIC_PATTERNS` in the script (line 149).

---

## 🐛 Troubleshooting

### Issue: "Connection refused"
**Solution:** Check OpenNMS is running
```bash
# Docker
docker ps | grep opennms

# Standalone
curl http://localhost:8980/opennms/
```

### Issue: "Authentication failed"
**Solution:** Verify credentials in Config section of script

### Issue: "No devices found"
**Solution:** Check OpenNMS has discovered devices
```bash
curl -u admin:password http://localhost:8980/opennms/rest/nodes
```

### Issue: "All KPIs are null"
**Solution:** OpenNMS needs time to collect data (wait 5-10 minutes after device discovery)

Check if RRD files exist:
```bash
docker exec opennms ls /opt/opennms/share/rrd/snmp/
```

### Issue: "Docker mode detection fails"
**Solution:** Set environment variable
```bash
export USE_DOCKER=true
python3 export_devices.py
```

---

## ⚙️ Configuration Options

Edit the `Config` class in `export_devices.py`:

```python
@dataclass
class Config:
    base_url: str = "http://localhost:8980/opennms/rest"
    username: str = "admin"
    password: str = "password"
    rrd_base: str = "/opt/opennms/share/rrd/snmp"
    docker_container: str = "opennms"
    output_file: str = "devices.json"
    log_file: str = "adapter.log"
    collection_interval_minutes: int = 15
    include_interface_metrics: bool = True
    include_topology: bool = True
```

---

## 📁 Project Structure

```
OPENNMS-Multi-Device-Adapter/
├── export_devices.py          # Main adapter script
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── devices.json              # Output (generated)
├── adapter.log               # Logs (generated)
└── datacollection/           # OpenNMS config examples
    ├── cisco.xml
    └── snmp-graph.properties.d/
```

---

## 🔄 Scheduling Automatic Collection

### Using Cron (Linux/Mac)
```bash
# Edit crontab
crontab -e

# Add line to run every 15 minutes
*/15 * * * * cd /path/to/adapter && python3 export_devices.py
```

### Using Task Scheduler (Windows)
1. Open Task Scheduler
2. Create Basic Task
3. Trigger: Every 15 minutes
4. Action: Run `python3 export_devices.py`

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-vendor`)
3. Commit changes (`git commit -am 'Add Arista support'`)
4. Push to branch (`git push origin feature/new-vendor`)
5. Open a Pull Request

---

## 📝 Adding New Vendors

To add support for a new vendor:

1. Find the vendor's SNMP MIBs
2. Identify CPU and Memory OIDs
3. Add patterns to `METRIC_PATTERNS` in script:

```python
METRIC_PATTERNS = {
    'cpu': {
        'cisco': ['cpmCPUTotal5min.rrd'],
        'your_vendor': ['yourVendorCpu.rrd'],  # Add here
    },
    'memory': {
        'cisco_used': ['ciscoMemoryPoolUsed.rrd'],
        'your_vendor_used': ['yourVendorMemUsed.rrd'],  # Add here
    }
}
```

4. Test with your vendor's devices
5. Submit a PR!

---

## 📄 License

MIT License - See LICENSE file for details
