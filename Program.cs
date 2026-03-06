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

namespace UnifiedSecurityAnalyzer
{
    class Program
    {
        private static DetectionEngine _engine = null!;
        private static AlertManager _alertManager = null!;
        private static AppConfig _config = null!;

        static async Task Main(string[] args)
        {
            Console.Title = "Unified Security Analyzer";

            while (true)
            {
                Console.WriteLine("\n========================================");
                Console.WriteLine("       UNIFIED SECURITY ANALYZER        ");
                Console.WriteLine("========================================");
                Console.WriteLine("1. Run Process & File System Security Scan");
                Console.WriteLine("2. Run Network Pcap Analyzer (Live Capture + Analysis)");
                Console.WriteLine("3. Run Process & File System Security Scan and Analyze Existing Pcap File");
                Console.WriteLine("4. Run Both at Once (Live Network Capture + System Scan)");
                Console.WriteLine("5. Exit");
                Console.Write("\nSelect an option (1-5): ");

                string? choice = Console.ReadLine();

                if (choice == "1")
                {
                    RunProcessAndFileScan();
                }
                else if (choice == "2")
                {
                    RunPcapCaptureAndAnalysis();
                }
                else if (choice == "3")
                {
                    RunPcapAnalysis();
                }
                else if (choice == "4")
                {
                    await RunBothAtOnce();
                }
                else if (choice == "5")
                {
                    break;
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

        static void RunProcessAndFileScan(bool silent = false)
        {
            SetupConfig();
            SetupEngine(silent);
            
            if (!silent) 
                Console.WriteLine("\n>>> Starting Full System Security Scan (Processes, Registry & Files)...");
            
            _engine.RunCycle();
            
            if (!silent) 
                Console.WriteLine("\n>>> Scan Complete.");
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
            _alertManager = new AlertManager();
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

        static void RunPcapCaptureAndAnalysis()
        {
            string pcapDir = GetPcapDir();

            string capturedFile = CaptureService.Run(pcapDir);

            if (string.IsNullOrEmpty(capturedFile) || !File.Exists(capturedFile))
            {
                Console.WriteLine("Capture failed or file was not created. Aborting analysis.");
                return;
            }

            Console.WriteLine("\nCapture Complete. Proceeding to Analysis...\n");
            AnalysisService.Run(capturedFile);
        }

        static void RunPcapAnalysis()
        {
            string pcapDir = GetPcapDir();
            
            // Filter out the live capture file natively generated by the app
            var files = Directory.GetFiles(pcapDir, "*.pcap")
                                 .Where(f => Path.GetFileName(f) != "60snetcapture.pcap")
                                 .ToArray();
            
            if (files.Length == 0)
            {
                Console.WriteLine($"No external .pcap files found in {pcapDir} (ignoring '60snetcapture.pcap').");
                return;
            }

            // Automatically select the first existing pcap file
            string targetFile = files[0];

            Console.WriteLine("\n>>> Running Full System Security Scan (Processes, Registry & Files)...");
            RunProcessAndFileScan(silent: true);

            Console.WriteLine($"\n>>> Analyzing PCAP: {Path.GetFileName(targetFile)}...\n");
            
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
            AnalysisService.Run(targetFile, skipHeader: true);
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
            Console.WriteLine("\n>>> Initiating Simultaneous Network Capture and System Scan...");
            
            string pcapDir = GetPcapDir();
            
            // Start network capture in the background
            Task<string> captureTask = Task.Run(() => CaptureService.Run(pcapDir));

            // Run system scan on the main thread while capture is ongoing, but keep it silent
            RunProcessAndFileScan(silent: true);

            Console.WriteLine("\n>>> Waiting for Network Capture (60s total) to complete before analysis...");
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
            AnalysisService.Run(capturedFile, skipHeader: true);
        }
    }
}
