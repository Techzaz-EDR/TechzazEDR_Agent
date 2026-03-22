using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using WinEDR_MVP.Config;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;
using WinEDR_MVP.Rules.HIDS;
using WinEDR_MVP.Rules.Malware;
using System.Text.Json;
using System.Linq;

// PCAP Analyzer namespaces
using NetSuite;

namespace TechzazEdrWindowsAgent
{
    class Program
    {
        private static DetectionEngine _engine = null!;
        private static AlertManager _alertManager = null!;
        private static AppConfig _config = null!;
        private static CommandService _commandService = null!;

        static async Task Main(string[] args)
        {
            Console.Title = "TechzazEdr Windows Agent";

            // Initialize configuration and command sync
            SetupConfig();
            InitializeCommandSync();

            while (true)
            {
                Console.WriteLine("\n========================================");
                Console.WriteLine("       TECHZAZEDR WINDOWS AGENT        ");
                Console.WriteLine("========================================");
                Console.WriteLine("1. Integrated Analysis (System Scan + PCAP File)");
                Console.WriteLine("2. Live Security Analyzer (System Scan + Live Capture)");
                Console.WriteLine("3. Exit");
                Console.Write("\nSelect an option (1-3): ");

                string? choice = Console.ReadLine();

                if (choice == "1")
                {
                    await RunPcapAnalysis();
                }
                else if (choice == "2")
                {
                    await RunBothAtOnce();
                }
                else if (choice == "3")
                {
                    break;
                }

                // Show consolidated alert dispatch summary after ANY scan option that initialized the manager
                if (_alertManager != null)
                {
                    var (success, failure) = await _alertManager.WaitForDispatchesAsync();
                    if (success > 0 || failure > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [✓] SYNC: Successfully dispatched {success} alerts to dashboard{(failure > 0 ? $" ({failure} failed)" : "")}.");
                        Console.ResetColor();
                    }
                }
                else
                {
                    Console.WriteLine("Invalid option.");
                }
            }

            Console.WriteLine("\nSession Complete. Press any key to exit.");
            Console.ReadKey();
        }

        // --- Process & File Analyser Integration ---

        static async Task RunProcessAndFileScan(bool silent = false)
        {
            SetupConfig();
            SetupEngine(silent);
            
            string timestamp = DateTime.Now.ToString("HH:mm:ss");

            if (!silent)
            {
                Console.WriteLine($"[{timestamp}] [*] INITIALIZING: Full System Security Scan...");
                Console.WriteLine($"[{timestamp}] [i] CONFIG: Loaded {_config.ProcessPathExpectations.Count + _config.UntrustedExecutionPaths.Count} trusted/monitored paths, {Directory.GetFiles(_config.YaraRulesPath, "*.yar", SearchOption.AllDirectories).Length} YARA rules.");
            }
            
            var stats = _engine.RunCycle();

            if (!silent) 
                Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [✓] SCAN COMPLETE: {stats.ItemsChecked} items checked, {stats.AlertsFound} alerts found.");
        }

        static void SetupConfig()
        {
            string configPath = "config.json";
            if (!File.Exists(configPath))
            {
                CreateDefaultConfig(configPath);
            }
            _config = AppConfig.Load(configPath);
        }

        static void SetupEngine(bool silent)
        {
            // Initialize the dispatcher to send alerts to the backend
            var backendUrl = "https://techzazedrdashboard-backend-production.up.railway.app"; // Can be moved to AppConfig if desired
            var dispatcher = new AlertDispatcher(backendUrl, _config.OrganizationApiKey, _config.AgentId);

            _alertManager = new AlertManager("alerts.log", dispatcher);
            _alertManager.SilentMode = silent;
            _engine = new DetectionEngine(_alertManager);

            // Register Rules
            _engine.RegisterRule(new SystemProcessMasqueradingRule(_config));
            _engine.RegisterRule(new SuspiciousExecutionRule(_config));
            _engine.RegisterRule(new StartupPersistenceRule());
            _engine.RegisterRule(new FileScannerRule(_config));
            _engine.RegisterRule(new YaraScannerRule(_config));
        }

        static void CreateDefaultConfig(string path)
        {
            var config = new AppConfig();
            
            // HIDS P1: Extended System Process Mappings (from CSVs)
            var expectations = config.ProcessPathExpectations;

            // System32 (64-bit/Native)
            AddExpectation(expectations, "svchost.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "lsass.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "csrss.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "winlogon.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "services.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "smss.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "explorer.exe", @"C:\Windows\");
            AddExpectation(expectations, "taskhostw.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "spoolsv.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "dllhost.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "conhost.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "wininit.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "wmiprvse.exe", @"C:\Windows\System32\wbem\");
            AddExpectation(expectations, "audiodg.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "lsm.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "fontdrvhost.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "sihost.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "ctfmon.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "rundll32.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "wermgr.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "taskmgr.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\");
            AddExpectation(expectations, "cmd.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "mshta.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "regsvr32.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "bitsadmin.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "certutil.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "schtasks.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "whoami.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "net.exe", @"C:\Windows\System32\");
            AddExpectation(expectations, "netsh.exe", @"C:\Windows\System32\");

            // SysWOW64 (32-bit on 64-bit)
            AddExpectation(expectations, "svchost.exe", @"C:\Windows\SysWOW64\");
            AddExpectation(expectations, "powershell.exe", @"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\");
            AddExpectation(expectations, "cmd.exe", @"C:\Windows\SysWOW64\");
            AddExpectation(expectations, "regsvr32.exe", @"C:\Windows\SysWOW64\");
            AddExpectation(expectations, "mshta.exe", @"C:\Windows\SysWOW64\");
            AddExpectation(expectations, "rundll32.exe", @"C:\Windows\SysWOW64\");

            // High-Risk Monitoring Paths
            config.UntrustedExecutionPaths.Add(@"%USERPROFILE%\Downloads");
            config.UntrustedExecutionPaths.Add(@"%USERPROFILE%\AppData\Local\Temp");
            config.UntrustedExecutionPaths.Add(@"%USERPROFILE%\Desktop");

            config.YaraRulesPath = @"Rules\Yara";

            var options = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, JsonSerializer.Serialize(config, options));
        }

        static void AddExpectation(Dictionary<string, List<string>> dict, string process, string path)
        {
            if (!dict.ContainsKey(process)) dict[process] = new List<string>();
            if (!dict[process].Contains(path)) dict[process].Add(path);
        }

        // --- PCAP Analyzer Integration ---

        static async Task RunPcapCaptureAndAnalysis(bool silent = false)
        {
            SetupConfig();
            SetupEngine(silent);
            _alertManager.SilentMode = silent; 

            string pcapDir = GetPcapDir();

            string capturedFile = CaptureService.Run(pcapDir);

            if (string.IsNullOrEmpty(capturedFile) || !File.Exists(capturedFile))
            {
                Console.WriteLine("Capture failed or file was not created. Aborting analysis.");
                return;
            }

            Console.WriteLine("\nCapture Complete. Proceeding to Analysis...\n");
            AnalysisService.Run(capturedFile, _alertManager);
        }

        static async Task RunPcapAnalysis()
        {
            string pcapDir = GetPcapDir();
            
            var files = Directory.GetFiles(pcapDir, "*.pcap");
            
            if (files.Length == 0)
            {
                Console.WriteLine($"No .pcap files found in {pcapDir}");
                return;
            }

            // Automatically select the first existing pcap file
            string targetFile = files[0];

            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [*] INITIALIZING: Integrated System & PCAP Analysis...");
            await RunProcessAndFileScan(silent: true);

            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [i] NETWORK: Analyzing PCAP: {Path.GetFileName(targetFile)}...");
            
            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("             COMBINED SECURITY ANALYSIS REPORT             ");
            Console.WriteLine(new string('=', 60));

            Console.WriteLine("\n--- 1. SYSTEM PROCESS & FILE SCAN RESULTS ---");
            _alertManager.PrintAllAlerts();
            if (_alertManager.GetAlerts().Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("NO SYSTEM/FILE THREATS DETECTED.");
                Console.ResetColor();
            }

            Console.WriteLine("\n--- 2. NETWORK PCAP ANALYSIS RESULTS ---");
            AnalysisService.Run(targetFile, _alertManager, skipHeader: true);
        }

        static string GetPcapDir()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            DirectoryInfo? dir = new DirectoryInfo(baseDir);
            
            while (dir != null && !dir.GetFiles("*.csproj").Any())
            {
                dir = dir.Parent;
            }

            string projectRoot = dir?.FullName ?? Directory.GetCurrentDirectory();
            string pcapDir = Path.Combine(projectRoot, "pcap");
            if (!Directory.Exists(pcapDir)) Directory.CreateDirectory(pcapDir);

            return pcapDir;
        }

        static async Task RunBothAtOnce()
        {
            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [*] INITIALIZING: Simultaneous Live Capture & System Scan...");
            
            string pcapDir = GetPcapDir();
            
            // Start network capture in the background
            Task<string> captureTask = Task.Run(() => CaptureService.Run(pcapDir));

            // Run system scan on the main thread while capture is ongoing, but keep it silent
            await RunProcessAndFileScan(silent: true);

            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [i] WAITING: Finalizing Network Capture (60s total)...");
            string capturedFile = await captureTask;

            if (string.IsNullOrEmpty(capturedFile) || !File.Exists(capturedFile))
            {
                Console.WriteLine("Capture failed or file was not created. Aborting PCAP analysis.");
                return;
            }

            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("             COMBINED SECURITY ANALYSIS REPORT             ");
            Console.WriteLine(new string('=', 60));

            Console.WriteLine("\n--- 1. SYSTEM PROCESS & FILE SCAN RESULTS ---");
            _alertManager.PrintAllAlerts();
            if (_alertManager.GetAlerts().Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("NO SYSTEM/FILE THREATS DETECTED.");
                Console.ResetColor();
            }

            Console.WriteLine("\n--- 2. NETWORK PCAP ANALYSIS RESULTS ---");
            AnalysisService.Run(capturedFile, _alertManager, skipHeader: true);
        }

        private static void InitializeCommandSync()
        {
            var backendUrl = "https://techzazedrdashboard-backend-production.up.railway.app";
            _commandService = new CommandService(backendUrl, _config.OrganizationApiKey, _config.AgentId, ExecuteRemoteCommand);
            _commandService.Start();
        }

        private static async Task ExecuteRemoteCommand(string command)
        {
            switch (command.ToLower())
            {
                case "run_hids_scan":
                case "system_scan":
                    await RunProcessAndFileScan(silent: false);
                    break;
                case "run_network_scan":
                case "network_scan":
                    await RunPcapCaptureAndAnalysis(silent: false);
                    break;
                case "run_full_scan":
                case "full_scan":
                case "run_remote_scan":
                case "remote_scan":
                    await RunBothAtOnce();
                    break;
                case "update_config":
                    SetupConfig();
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] CONFIG: Reloaded configuration.");
                    break;
                default:
                    throw new Exception($"Unknown command: {command}");
            }

            // Show alert dispatch summary after remote scan
            if (_alertManager != null)
            {
                var (success, failure) = await _alertManager.WaitForDispatchesAsync();
                if (success > 0 || failure > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] SYNC: Successfully dispatched {success} alerts to dashboard{(failure > 0 ? $" ({failure} failed)" : "")}.");
                    Console.ResetColor();
                }
            }
        }
    }
}
