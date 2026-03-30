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
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Application = System.Windows.Forms.Application;
using System.Text;
using Microsoft.Win32.SafeHandles;

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

        // Notification Event
        public static Action<string, string>? OnNotification;

        // Win32 Interop
        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")]
        private static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("user32.dll")]
        private static extern bool RemoveMenu(IntPtr hMenu, uint nPosition, uint nFlags);
        [DllImport("user32.dll")]
        private static extern bool EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable);
        [DllImport("user32.dll")]
        private static extern bool DeleteMenu(IntPtr hMenu, uint nPosition, uint nFlags);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;
        private const uint SC_CLOSE = 0xF060;
        private const uint MF_BYCOMMAND = 0x00000000;
        private const uint MF_GRAYED = 0x00000001;
        private const uint MF_DISABLED = 0x00000002;
        private static bool _isConsoleVisible = false;
        private static IntPtr _consoleHandle = IntPtr.Zero;

        static async Task Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Hide the console (silent startup)
            HideConsole();

            // Initialize configuration and command sync
            SetupConfig();
            InitializeCommandSync();

            // Notify user of startup
            // OnNotification?.Invoke("Agent Active", "TechzazEDR is monitoring from the system tray.");

            // Run the tray application loop
            Application.Run(new TrayIconContext());
        }

        // --- Process & File Analyser Integration ---

        public static async Task<bool> RunProcessAndFileScan(bool silent = false, string? cmdId = null)
        {
            SetupConfig();
            SetupEngine(silent);
            
            string timestamp = DateTime.Now.ToString("HH:mm:ss");

            if (!silent)
            {
                Console.WriteLine($"[{timestamp}] [*] INITIALIZING: Full System Security Scan...");
                Console.WriteLine($"[{timestamp}] [i] CONFIG: Loaded {_config.ProcessPathExpectations.Count + _config.UntrustedExecutionPaths.Count} trusted/monitored paths, {Directory.GetFiles(_config.YaraRulesPath, "*.yar", SearchOption.AllDirectories).Length} YARA rules.");
            }
            
            var stats = await _engine.RunCycle(cmdId != null ? () => IsCancelled(cmdId) : null);

            if (stats.AlertsFound < 0) return true; // Engine returned abort (stats logic would need update or check IsCancelled)
            if (await IsCancelled(cmdId)) return true;

            if (!silent) 
                Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [✓] SCAN COMPLETE: {stats.ItemsChecked} items checked, {stats.AlertsFound} alerts found.");
            
            return false;
        }

        static void SetupConfig()
        {
            string configPath = "config.json";
            if (!File.Exists(configPath))
            {
                CreateDefaultConfig(configPath);
            }
            _config = AppConfig.Load(configPath);

            // Migrate legacy machine-name AgentId to a stable UUID.
            // agent_id  = internal Firestore key (never shown to users, never changes)
            // agent_name = display label (shown in dashboard, can be renamed by admin)
            if (!IsValidGuid(_config.AgentId))
            {
                // Preserve the old machine-name value as the display name if AgentName not set separately
                if (string.IsNullOrWhiteSpace(_config.AgentName) || _config.AgentName == _config.AgentId)
                    _config.AgentName = _config.AgentId; // keep e.g. "INUKA-VIVOBOOKP" as display name

                _config.AgentId = Guid.NewGuid().ToString();
                SaveConfig(configPath, _config);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] CONFIG: Migrated AgentId to stable UUID. Display name: {_config.AgentName}");
            }
        }

        static void SetupEngine(bool silent)
        {
            // Initialize the dispatcher to send alerts to the backend
            var backendUrl = ResolveBackendUrl();
            var dispatcher = new AlertDispatcher(backendUrl, _config.OrganizationApiKey, _config.AgentId, _config.AgentName);

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

        public static void ToggleConsole()
        {
            if (_isConsoleVisible)
            {
                HideConsole();
            }
            else
            {
                ShowConsole();
            }
        }

        public static void ShowConsole()
        {
            if (_consoleHandle == IntPtr.Zero)
            {
                // Allocate on first request (not during silent startup)
                AllocConsole();
                _consoleHandle = GetConsoleWindow();

                // Redirect standard output to the new console
                var outStream = Console.OpenStandardOutput();
                var writer = new StreamWriter(outStream, Console.OutputEncoding) { AutoFlush = true };
                Console.SetOut(writer);
                
                var errStream = Console.OpenStandardError();
                var errWriter = new StreamWriter(errStream, Console.OutputEncoding) { AutoFlush = true };
                Console.SetError(errWriter);
            }
            
            if (_consoleHandle != IntPtr.Zero)
            {
                // Consistently ensure close button is disabled before showing
                IntPtr hMenu = GetSystemMenu(_consoleHandle, false);
                if (hMenu != IntPtr.Zero)
                {
                    DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
                    RemoveMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
                    EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
                }

                ShowWindow(_consoleHandle, SW_SHOW);
                _isConsoleVisible = true;
            }
        }

        public static void HideConsole()
        {
            if (_consoleHandle == IntPtr.Zero)
                _consoleHandle = GetConsoleWindow();

            if (_consoleHandle != IntPtr.Zero)
            {
                ShowWindow(_consoleHandle, SW_HIDE);
            }
            _isConsoleVisible = false;
        }

        public static bool IsConsoleVisible() => _isConsoleVisible;

        static void AddExpectation(Dictionary<string, List<string>> dict, string process, string path)
        {
            if (!dict.ContainsKey(process)) dict[process] = new List<string>();
            if (!dict[process].Contains(path)) dict[process].Add(path);
        }

        /// <summary>Returns true if value is a well-formed UUID/GUID.</summary>
        static bool IsValidGuid(string value) => Guid.TryParse(value, out _);

        /// <summary>Persists the current config back to disk.</summary>
        static void SaveConfig(string path, AppConfig config)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(path, JsonSerializer.Serialize(config, options));
        }

        // --- PCAP Analyzer Integration ---

        static async Task<bool> RunPcapCaptureAndAnalysis(bool silent = false, string? cmdId = null)
        {
            SetupConfig();
            SetupEngine(silent);
            _alertManager.SilentMode = silent; 
            _alertManager.DispatchDisabled = false;

            string pcapDir = GetPcapDir();

            string capturedFile = await CaptureService.Run(pcapDir, cmdId != null ? () => IsCancelled(cmdId) : null);
            if (await IsCancelled(cmdId)) return true;

            if (string.IsNullOrEmpty(capturedFile) || !File.Exists(capturedFile))
            {
                Console.WriteLine("Capture failed or file was not created. Aborting analysis.");
                return false;
            }

            Console.WriteLine("\nCapture Complete. Proceeding to Analysis...\n");
            AnalysisService.Run(capturedFile, _alertManager);
            return await IsCancelled(cmdId);
        }

        public static async Task RunPcapAnalysis()
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
            await RunProcessAndFileScan(silent: true, cmdId: null);

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

        public static async Task RunBothAtOnce(string? cmdId = null)
        {
            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] [*] INITIALIZING: Simultaneous Live Capture & System Scan...");
            
            string pcapDir = GetPcapDir();
            
            // Start network capture in the background
            Task<string?> captureTask = Task.Run(async () => await CaptureService.Run(pcapDir, cmdId != null ? () => IsCancelled(cmdId) : null));

            // Run system scan on the main thread while capture is ongoing, but keep it silent
            if (await RunProcessAndFileScan(silent: true, cmdId: cmdId)) return;

            if (await IsCancelled(cmdId)) return;
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

        // ── ONE-TIME: Run a scan on reproducibility_testfiles and save the baseline ──
        static async Task GenerateReproducibilityBaseline()
        {
            string testFolder = "reproducibility_testfiles";
            string baselinePath = Path.Combine(testFolder, "baseline_results.json");

            if (!Directory.Exists(testFolder)) return;
            if (File.Exists(baselinePath))
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] REPRO: Baseline already exists at {baselinePath}. Skipping generation.");
                return;
            }

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [*] REPRO: Generating baseline from {testFolder}...");

            // Use a no-dispatch AltertManager so nothing goes to the dashboard
            var silentManager = new AlertManager("repro_baseline.log", null);
            silentManager.SilentMode = true;

            // Temporarily point untrusted paths to test folder
            var originalPaths = _config.UntrustedExecutionPaths.ToList();
            _config.UntrustedExecutionPaths.Clear();
            _config.UntrustedExecutionPaths.Add(testFolder);

            // var backendUrl = "https://techzazedrdashboard-backend-production.up.railway.app";
            var backendUrl = "http://localhost:8000";
            var dispatcher = new AlertDispatcher(backendUrl, _config.OrganizationApiKey, _config.AgentId, _config.AgentName);
            var savedAlertManager = _alertManager;
            _alertManager = silentManager;
            _engine = new DetectionEngine(_alertManager);
            _engine.RegisterRule(new SystemProcessMasqueradingRule(_config));
            _engine.RegisterRule(new SuspiciousExecutionRule(_config));
            _engine.RegisterRule(new StartupPersistenceRule());
            _engine.RegisterRule(new FileScannerRule(_config));
            _engine.RegisterRule(new YaraScannerRule(_config));
            await _engine.RunCycle();

            // PCAP in testfolder
            var pcapFiles = Directory.GetFiles(testFolder, "*.pcap");
            if (pcapFiles.Length > 0)
                AnalysisService.Run(pcapFiles[0], silentManager, skipHeader: true);

            // Collect unique RuleIds
            var ruleIds = silentManager.GetAlerts().Select(a => a.RuleId).Distinct().OrderBy(x => x).ToList();

            // Save
            var json = JsonSerializer.Serialize(new { GeneratedAt = DateTime.UtcNow, ExpectedAlertRuleIds = ruleIds }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(baselinePath, json);

            // Restore
            _config.UntrustedExecutionPaths.Clear();
            foreach (var path in originalPaths) _config.UntrustedExecutionPaths.Add(path);
            _alertManager = savedAlertManager;
            SetupEngine(silent: false);

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] REPRO: Baseline saved with {ruleIds.Count} expected rule IDs: [{string.Join(", ", ruleIds)}]");
        }

        // ── REPRODUCIBILITY TEST: compare live scan results vs baseline ──
        static async Task RunReproducibilityTest(string cmdId)
        {
            string testFolder = "reproducibility_testfiles";
            string baselinePath = Path.Combine(testFolder, "baseline_results.json");

            if (!Directory.Exists(testFolder))
            {
                Console.WriteLine($"[Reproducibility] Error: Folder {testFolder} not found.");
                return;
            }

            if (!File.Exists(baselinePath))
            {
                Console.WriteLine($"[Reproducibility] No baseline found. Generating now...");
                await GenerateReproducibilityBaseline();
            }

            Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] [*] STARTING REPRODUCIBILITY TEST...");
            if (await IsCancelled(cmdId)) return;

            // Use an AlertManager that dispatches alerts to the dashboard
            var backendUrl = ResolveBackendUrl();
            var dispatcher = new AlertDispatcher(backendUrl, _config.OrganizationApiKey, _config.AgentId, _config.AgentName);
            var silentManager = new AlertManager("repro_test.log", dispatcher);
            silentManager.SilentMode = true; // Prevent console spam, but allow network dispatch

            var originalPaths = _config.UntrustedExecutionPaths.ToList();
            _config.UntrustedExecutionPaths.Clear();
            _config.UntrustedExecutionPaths.Add(testFolder);

            var savedAlertManager = _alertManager;
            _alertManager = silentManager;
            _engine = new DetectionEngine(_alertManager);
            _engine.RegisterRule(new SystemProcessMasqueradingRule(_config));
            _engine.RegisterRule(new SuspiciousExecutionRule(_config));
            _engine.RegisterRule(new StartupPersistenceRule());
            _engine.RegisterRule(new FileScannerRule(_config));
            _engine.RegisterRule(new YaraScannerRule(_config));

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] SCANNING: {testFolder}...");
            if (await IsCancelled(cmdId)) return;
            await _engine.RunCycle(() => IsCancelled(cmdId));

            var pcapFiles = Directory.GetFiles(testFolder, "*.pcap");
            if (pcapFiles.Length > 0)
            {
                if (await IsCancelled(cmdId)) return;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] ANALYZING: {Path.GetFileName(pcapFiles[0])}...");
                AnalysisService.Run(pcapFiles[0], silentManager, skipHeader: true);
            }

            // Restore original context
            _config.UntrustedExecutionPaths.Clear();
            foreach (var path in originalPaths) _config.UntrustedExecutionPaths.Add(path);
            _alertManager = savedAlertManager;
            SetupEngine(silent: false);

            // Compare with baseline
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] COMPARING: Alerts with baseline...");
            var generatedIds = silentManager.GetAlerts().Select(a => a.RuleId).Distinct().ToList();

            int totalExpected = 0;
            int matched = 0;

            try {
                var jsonText = File.ReadAllText(baselinePath);
                var baseline = JsonSerializer.Deserialize<JsonElement>(jsonText);
                var expectedIds = baseline.GetProperty("ExpectedAlertRuleIds").EnumerateArray()
                                          .Select(x => x.GetString()).ToList();
                totalExpected = expectedIds.Count;
                foreach (var id in expectedIds)
                    if (id != null && generatedIds.Contains(id)) matched++;
            } catch (Exception ex) {
                Console.WriteLine($"[Reproducibility] Error reading baseline: {ex.Message}");
            }

            double percentage = totalExpected > 0 ? (double)matched / totalExpected * 100 : 0;

            // Print report
            Console.WriteLine("\n" + new string('-', 40));
            Console.WriteLine("       REPRODUCIBILITY TEST REPORT        ");
            Console.WriteLine(new string('-', 40));
            Console.WriteLine($"Generated Alert IDs : [{string.Join(", ", generatedIds)}]");
            Console.WriteLine($"Matched Rule IDs    : {matched} / {totalExpected}");
            Console.ForegroundColor = percentage >= 100 ? ConsoleColor.Green : (percentage >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red);
            Console.WriteLine($"MATCHINGNESS SCORE  : {percentage:F1}%");
            Console.ResetColor();
            Console.WriteLine(new string('-', 40));

            // Final cancellation check before reporting
            if (await IsCancelled(cmdId)) return;

            // Patch the score back to the command document (visible in dashboard)
            string scoreResult = $"{percentage:F1}% ({matched}/{totalExpected})";
            await _commandService.UpdateStatusWithResult(cmdId, "completed", scoreResult);
        }

        static async Task<bool> IsCancelled(string? cmdId)
        {
            if (string.IsNullOrEmpty(cmdId)) return false;
            var status = await _commandService.GetCommandStatus(cmdId);
            if (status == "cancelled")
            {
                _alertManager.DispatchDisabled = true;
                _alertManager.StopDispatching();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [!] ABORTED: Command {cmdId} cancelled by user.");
                return true;
            }
            return false;
        }

        private static void InitializeCommandSync()
        {
            var backendUrl = ResolveBackendUrl();
            _commandService = new CommandService(
                backendUrl,
                _config.OrganizationApiKey,
                _config.AgentId,
                _config.AgentName,
                (cmdId, command, parameters) => ExecuteRemoteCommand(cmdId, command, parameters)
            );
            _commandService.Start();
            _commandService.OnCommandReceived += (cmd) => 
            {
                OnNotification?.Invoke("Remote Command Received", $"Executing command: {cmd}");
            };
        }

        private static string ResolveBackendUrl()
        {
            const string local = "http://127.0.0.1:8000";
            const string remote = "https://techzazedrdashboard-backend-production.up.railway.app";

            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(2);
                var resp = client.GetAsync(local + "/health").GetAwaiter().GetResult();
                if (resp.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] BACKEND: Using local server ({local})");
                    return local;
                }
            }
            catch
            {
                // local backend is unreachable
            }

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] BACKEND: Local unavailable, using Railway ({remote})");
            return remote;
        }

        private static async Task ExecuteRemoteCommand(string cmdId, string command, Dictionary<string, System.Text.Json.JsonElement> parameters)
        {
            switch (command.ToLower())
            {
                case "run_hids_scan":
                case "system_scan":
                    await RunProcessAndFileScan(silent: false, cmdId: cmdId);
                    break;
                case "run_network_scan":
                case "network_scan":
                    await RunPcapCaptureAndAnalysis(silent: false, cmdId: cmdId);
                    break;
                case "run_full_scan":
                case "full_scan":
                case "run_remote_scan":
                case "remote_scan":
                    await RunBothAtOnce(cmdId: cmdId);
                    break;
                case "run_test_scan":
                    await RunReproducibilityTest(cmdId);
                    return; // Score already patched in the method, skip dispatch summary below
                case "update_config":
                    SetupConfig();
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] CONFIG: Reloaded configuration.");
                    break;
                case "update_agent_name":
                    if (parameters.TryGetValue("agent_name", out var nameEl))
                    {
                        string newName = nameEl.GetString() ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(newName))
                        {
                            _config.AgentName = newName;
                            SaveConfig("config.json", _config);
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] CONFIG: Agent name updated to '{newName}' and saved to config.json.");
                        }
                        else
                        {
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [!] CONFIG: update_agent_name received empty name — ignored.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [!] CONFIG: update_agent_name missing 'agent_name' parameter.");
                    }
                    break;
                default:
                    throw new Exception($"Unknown command: {command}");
            }

            // Do not show dispatch summary if cancelled
            if (await IsCancelled(cmdId)) return;

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
