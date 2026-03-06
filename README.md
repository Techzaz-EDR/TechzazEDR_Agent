# Unified Security Analyzer (CLI)

Unified Security Analyzer is a consolidated threat detection tool running as a single `.NET 10.0` console application. This project merges the capabilities of the **Process & File Analyser** (HIDS / Malware detection) and the **NetSuite PCAP Analyzer** (Network capture and anomaly detection) into one interactive toolkit.

## 🛡️ Core Capabilities

### 1. Process & Registry Monitoring (HIDS)
Validates the integrity of the live environment:
- **Process Masquerading**: Flags system binaries executing from untrusted locations.
- **Suspicious Path Execution**: Identifies scripts executing from frequently abused directories (`%TEMP%`, `Downloads`, etc.).
- **Registry Persistence**: Scans Windows Startup keys (`Run`/`RunOnce`) for entries pointing to high-risk paths.

### 2. Malware & File Scanning
Inspects configured directories for file-based threats:
- **Double Extension Detection**: Detects spoofed extensions (e.g., `.pdf.exe`).
- **Hidden Executables**: Flags executable files with the "Hidden" attribute.
- **YARA Integration**: Seamlessly executes the official `yara64.exe` to scan paths against provided `.yar` rules.

### 3. Network Traffic Analysis & Capture
Leverages `SharpPcap` and `PacketDotNet` to capture and inspect live network data:
- **Real-time Capture**: Intercept packets from wireless or ethernet interfaces.
- **Offline Analysis**: Analyze existing `.pcap` files.
- **Security Logic**: Detects reconnaissance (Port Scans), DoS (SYN floods), Expioitation (Cleartext credentials, web exploits), and Data Exfiltration.

## 🚀 Execution & Usage

Because network capture requires raw socket access, **running the application as Administrator is highly recommended**.

### Running the App
```bash
dotnet run
```

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
