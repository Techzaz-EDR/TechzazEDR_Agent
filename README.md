# Unified Security Analyzer (CLI)

Unified Security Analyzer is a consolidated threat detection tool running as a single `.NET 10.0` console application. This project merges the capabilities of the **Process & File Analyser** (HIDS / Malware detection) and the **NetSuite PCAP Analyzer** (Network capture and anomaly detection) into one interactive toolkit.

## 🛡️ Core Capabilities

### 1. Process & Registry Monitoring (HIDS)
Validates the integrity of the live environment:
- **Process Masquerading**: Flags system binaries (e.g., `explorer.exe`) executing from untrusted locations.
- **Suspicious Path Execution**: Identifies scripts and executables executing from frequently abused directories (`%TEMP%`, `Downloads`, etc.).
- **Registry Persistence**: Scans Windows Startup keys (`Run`/`RunOnce`) for entries pointing to high-risk paths like `AppData`.

### 2. Malware & File Scanning
Inspects configured directories for file-based threats:
- **Double Extension Detection**: Detects spoofed extensions (e.g., `.pdf.exe`, `.txt.js`).
- **Hidden Executables**: Flags executable files with the "Hidden" attribute enabled in untrusted paths.
- **YARA Integration**: Seamlessly executes the official `yara64.exe` to scan paths against provided `.yar` rules, triggering alerts natively within the engine.

### 3. Network Traffic Analysis & Capture
Leverages `SharpPcap` and `PacketDotNet` to capture and inspect live network data. The analyzer categorizes detections into four primary categories:

#### Reconnaissance & Scanning
| ID | Name | Description | Logic / Threshold |
|:---|:---|:---|:---|
| **NET-1** | Port Scanning | Mapping open ports on a single or multiple hosts. | Unique ports >= 30 (or 5 for high-risk ports). |
| **NET-2** | Network Sweeps | Identifying active hosts using ICMP or ARP. | ICMP: 30+ targets, ARP: 40+ targets. |
| **NET-15** | Web Recon | Usage of automated web vulnerability scanners. | User-Agent matches (sqlmap, nmap, etc.) or high 404/403 rates. |

#### Denial of Service (DoS)
| ID | Name | Description | Logic / Threshold |
|:---|:---|:---|:---|
| **NET-3** | SYN Flood | Exhausting server resources with half-open TCP connections. | 500+ SYNs with < 10% ACK ratio. |
| **NET-4** | UDP Flood | Overwhelming the network with high-volume UDP traffic. | 10,000+ packets or 100+ unique destination ports. |
| **NET-5** | ICMP Flood | Sending excessive ICMP Echo Requests (Ping). | 5,000+ ICMP Echo Requests. |

#### Exploitation & Spoofing
| ID | Name | Description | Logic / Threshold |
|:---|:---|:---|:---|
| **NET-8** | Cleartext Credentials | Detecting sensitive data in unencrypted streams. | Regex/Keyword match for `password=`, `login=`, etc. |
| **NET-9** | Web Exploitation | Detecting common web-based attack signatures. | Match for `union select` (SQLi), `<script>` (XSS), etc. |
| **NET-11** | ARP Spoofing | Detecting MAC address inconsistencies (MITM). | Detects when a known IP changes its associated MAC. |
| **NET-12** | DNS Spoofing | Detecting unauthorized DNS responses. | Responses originating from unknown/rogue resolvers. |

#### Data Exfiltration & Anomalies
| ID | Name | Description | Logic / Threshold |
|:---|:---|:---|:---|
| **NET-7** | DNS / DGA | Detecting Domain Generation Algorithms (C2 traffic). | High entropy (>3.8), long domains, or high NXDOMAIN rate. |
| **NET-14** | Data Exfiltration | Detecting large-scale outbound data transfers. | 500 MB+ transferred to an external (non-private) IP. |
| **NET-16** | TTL Anomaly | Detecting packet injection or routing inconsistencies. | Jumps > 32 in IP Time-to-Live (TTL) values. |
| **NET-1** | TCP Flag Anomaly | Detecting stealth scans with invalid flag combinations. | >= 5 packets with FIN-only, NULL, or XMAS flags. |

## 🚀 Execution & Usage

Because network capture requires raw socket access, **running the application as Administrator is highly recommended**.

### Running the App
```bash
dotnet run
```

### Sample Alerts
When a threat is detected, the program outputs color-coded alerts to the console:

**Process & File Alert Examples:**
- `[System Scan ALERT] MAL (High): System Process Masquerading - System process svchost.exe running from illegitimate location: C:\Users\Public\svchost.exe. Expected one of: C:\Windows\System32\, C:\Windows\SysWOW64\`
- `[System Scan ALERT] MAL (Medium): Double Extension Detection - Potential malicious file detected: payment_receipt.pdf.exe`
- `[System Scan ALERT] MAL (High): YARA Match: Ransomware_WannaCry - File matched YARA rule 'Ransomware_WannaCry': my_document.exe`

**Network Alert Examples:**
- `[NET-1] Port Scanning Detected`
- `   Source: 192.168.1.15`
- `   Details: Unique Ports: 35`
- `[NET-12] DNS Response from Unknown Resolver`
- `   Source: 104.21.5.10`
- `   Details: Domain: malicious-c2-server.com`

### Main Menu Options

When you launch the program, you are presented with the following interactive menu:

1. **Run Process & File System Security Scan**
   Executes a full, immediate scan of local processes, registry keys, and untrusted directories. Outputs color-coded alerts to the console.

2. **Run Network Pcap Analyzer (Live Capture + Analysis)**
   Automatically selects the optimal network interface, promiscuously captures 60 seconds of traffic, saves it to the `pcap/` folder, and then runs threat analysis.

3. **Analyze Existing Pcap File**
   Reads all files from the local `pcap/` directory and allows you to select one to parse for anomalies and indicators of compromise.

4. **Run Both at Once (System Scan + Network Capture)**
   Utilizes `.NET` task concurrency. Captures 60 seconds of network traffic in the background while simultaneously performing the local System Process & File Scan. It then waits for both to finish and outputs a single, consolidated report.

5. **Exit**
   Closes the application.

## ⚙️ Configuration

Modify `config.json` to customize the detection scope for the HIDS engine:
- `TrustedExecutionPaths`: Whitelisted directories for system binaries.
- `UntrustedExecutionPaths`: High-risk zones targeted for deep monitoring.
- `TrustedSystemProcesses`: List of legitimate system process names.
- `YaraRulesPath`: Directory containing `.yar` rules (default: `Rules\Yara`).

Network Analyzer DNS Whitelisting:
- Local IP resolving (`192.168.1.1`), `8.8.8.8`, and `1.1.1.1` are inherently trusted internally when evaluating `NET-12` (DNS Spoofing).

## 🛠️ Technology Stack
- **Framework**: .NET 10 (Windows Console)
- **Core Dependencies**: `SharpPcap`, `PacketDotNet`, `dnYara`, `Microsoft.Win32.Registry`, `System.Text.Json`, `yara64.exe` (CLI dependency).
- **Architecture**: Modular heuristic detection engine combined with real-time network protocol parsers.

---
> [!IMPORTANT]
> This project is a Proof-of-Concept for educational and forensic demonstration. Ensure that the required libraries (like Npcap) are installed on your system for the network features to work correctly.
