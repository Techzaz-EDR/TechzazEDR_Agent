using System;
using System.Collections.Generic;
using System.Diagnostics;
using WinEDR_MVP.Config;
using WinEDR_MVP.Interfaces;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.HIDS
{
    // HIDS-P2 & HIDS-P3: Suspicious Execution
    public class SuspiciousExecutionRule : IDetectionRule
    {
        public string RuleId => "HIDS-P2/P3";
        public string Name => "Suspicious Process Execution";
        public string Description => "Detects processes or scripts running from user-writable directories.";
        public int ItemsChecked { get; private set; }

        private readonly AppConfig _config;

        public SuspiciousExecutionRule(AppConfig config)
        {
            _config = config;
        }

        public List<DetectionEvent> Evaluate()
        {
            var events = new List<DetectionEvent>();
            var processes = Process.GetProcesses();
            ItemsChecked = processes.Length;

            foreach (var proc in processes)
            {
                try
                {
                    if (proc.MainModule == null) continue;
                    string path = proc.MainModule.FileName; 
                    
                    foreach (var badPath in _config.UntrustedExecutionPaths)
                    {
                        // Expand environment variables in config paths if needed, or assume absolute/special folder
                        string expandedBadPath = Environment.ExpandEnvironmentVariables(badPath);
                        
                        // Check if path is within untrusted directory
                        if (path.StartsWith(expandedBadPath, StringComparison.OrdinalIgnoreCase))
                        {
                            string procName = proc.ProcessName.ToLower();
                            bool isScriptEngine = procName.Contains("powershell") || procName.Contains("cmd") || procName.Contains("wscript") || procName.Contains("cscript");
                            
                            if (isScriptEngine)
                            {
                                events.Add(new DetectionEvent
                                {
                                    RuleId = "HIDS-P3", 
                                    RuleName = "Suspicious Execution Path",
                                    Severity = AlertSeverity.Medium,
                                    Type = AlertType.TROJ,
                                    Description = $"Script engine {proc.ProcessName} running in untrusted path context: {path}",
                                    Metadata = new { ProcessId = proc.Id, Path = path }
                                });
                            }
                            else
                            {
                                // HIDS-P2
                                events.Add(new DetectionEvent
                                {
                                    RuleId = "HIDS-P2",
                                    RuleName = "Suspicious Executable Path",
                                    Severity = AlertSeverity.Medium,
                                    Type = AlertType.MAL,
                                    Description = $"Executable {proc.ProcessName} running from untrusted path: {path}",
                                    Metadata = new { ProcessId = proc.Id, Path = path }
                                });
                            }
                        }
                    }
                }
                catch { }
            }
            return events;
        }
    }
}
