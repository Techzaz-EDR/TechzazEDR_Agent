# TechzazEDR Unified Security Agent

A consolidated threat detection engine running as a high-performance `.NET 10.0` console application. This agent combines Host-based Intrusion Detection (HIDS), Malware Scanning, and Network Traffic Analysis into a single, modular toolkit that streams real-time telemetry to the TechzazEDR Dashboard.

## 🛡️ Core Capabilities

### 1. Process & Registry Monitoring (HIDS)
Heuristic analysis of the live environment:
- **Process Masquerading**: Flags system binaries (e.g., `svchost.exe`) executing from untrusted or temporary paths.
- **Suspicious Path Execution**: Monitors `%TEMP%`, `%APPDATA%`, and `Downloads` for unauthorized executables.
- **Registry Persistence**: Scans Windows Startup keys (`Run`/`RunOnce`) for entries pointing to high-risk areas.

### 2. Malware & File Scanning
Deep inspection of the local file system:
- **Double Extension Detection**: Identifies spoofed files like `invoice.pdf.exe`.
- **Hidden Executables**: Flags executable files with "Hidden" attributes in common abuse directories.
- **YARA Integration**: Native support for **YARA 4.2+** rules via `yara64.exe` to detect complex malware signatures.

- **Spoofing**: Detecting ARP and DNS spoofing / MITM attempts.

## ⚙️ Detection Logic Functions

The agent employs a multi-layered detection strategy to provide holistic endpoint protection.

### 🧠 Heuristic Threat Detection
- **Masquerading Engine**: Uses a path-expectation matrix to verify if critical binaries (like `lsass.exe` or `svchost.exe`) are executing from legitimate system directories.
- **Persistence Scanner**: Iterates through Windows Registry keys (`Software\Microsoft\Windows\CurrentVersion\Run`) to find high-risk entries pointing to User Profile directories.
- **Behavioral Analysis**: Monitors for suspicious process parent-child relationships and unexpected execution of scripting engines (`powershell.exe`, `cmd.exe`).

### 📑 Signature-Based Detection
- **YARA Integration**: Seamlessly interfaces with `yara64.exe` to scan live processes and files against custom `.yar` rules.
- **Spoofed Extension Engine**: Detects the "Right-to-Left Override" trick and common double-extension techniques (`.docx.exe`).
- **Hidden File Detection**: Identifies executable content flagged with the `Hidden` attribute in untrusted paths like `AppData\Temp`.

### 📡 Network Anomaly Detection
- **Traffic Fingerprinting**: Analyzes packet headers to identify invalid TCP flag combinations (XMAS, NULL scans).
- **Entropy Analysis**: Calculates Shannon entropy on DNS queries to detect Domain Generation Algorithms (DGA) used by C2 servers.
- **Volume Inconsistency**: Threshold-based logic to flag SYN/UDP floods and massive data exfiltration events.

### 🔄 Multi-Threaded Operation
The agent utilizes `.NET` task parallelism to ensure detection engines run concurrently without impacting system performance:
- **Background Capture**: Network traffic is captured and stored in circular buffers for real-time analysis.
- **Periodic Scans**: HIDS engines execute on scheduled intervals or manual triggers.
- **Async Dispatching**: Alerts are queued and sent in the background via the `AlertDispatcher` to prevent execution blocking.

## 🔌 Integration & Pipeline

The agent acts as a telemetry producer for the TechzazEDR ecosystem. It serializes detections into a unified JSON format and pushes them to the backend API over HTTPS.

### The `SecurityAlert` Schema
```json
{
  "Timestamp": "2026-03-07T02:30:00Z",
  "RuleId": "NET-12",
  "Category": "Network",
  "Severity": "High",
  "Status": "New",
  "Details": {
    "title": "DNS Response from Unknown Resolver",
    "description": "Domain: malicious-c2-server.com",
    "source_ip": "104.21.5.10",
    "target_ip": "192.168.1.15"
  }
}
```

## 🚀 Execution & Usage

### Prerequisites
- **.NET 10.0 SDK**
- **Npcap**: Required for network capture features.
- **Administrator Privileges**: Essential for raw socket access and registry scanning.

### Running the Agent
```bash
dotnet run
```

### Main Menu Options
1. **Full System Security Scan**: Immediate HIDS and File scan.
2. **Network Pcap Analyzer**: 60-second live capture and automated DPI.
3. **Offline Pcap Analysis**: Load existing `.pcap` files for forensic review.
4. **Unified Mode**: Background network capture while running a system scan.

## ⚙️ Configuration (`config.json`)

| Setting | Description |
|:---|:---|
| `OrganizationApiKey` | Unique key to link alerts to your tenant dashboard. |
| `UntrustedExecutionPaths` | Paths targeted for aggressive monitoring (e.g., Temp, Downloads). |
| `ProcessPathExpectations` | Map of system processes to their legitimate directories. |
| `YaraRulesPath` | Directory containing `.yar` rule files. |

## 🛠️ Troubleshooting

- **"No interfaces found"**: Ensure **Npcap** is installed and you are running as **Administrator**.
- **"Access Denied"**: Registry scanning and process memory access require elevated privileges.
- **Alerts not showing in Dashboard**: 
  - Verify your `OrganizationApiKey` in `config.json`.
  - Check connectivity to the backend API (Default: `http://localhost:8000`).

---
> This project is designed for security enthusiasts and forensic analysts. Always use in a controlled environment.
