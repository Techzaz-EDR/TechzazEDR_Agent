using System;
using System.Collections.Generic;
using System.Diagnostics;
using WinEDR_MVP.Config;
using WinEDR_MVP.Interfaces;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.HIDS
{
    // HIDS-P1: System Process Masquerading
    public class SystemProcessMasqueradingRule : IDetectionRule
    {
        public string RuleId => "HIDS-P1";
        public string Name => "System Process Masquerading";
        public string Description => "Detects system processes running outside legitimate paths.";
        public int ItemsChecked { get; private set; }

        private readonly AppConfig _config;

        public SystemProcessMasqueradingRule(AppConfig config)
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
                    string processName = proc.ProcessName.ToLower() + (proc.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? "" : ".exe");
                    
                    // Precise Mapping Check: If we have an expected path for this process
                    if (_config.ProcessPathExpectations.TryGetValue(processName, out var allowedPaths))
                    {
                        string? path = proc.MainModule?.FileName;
                        if (string.IsNullOrEmpty(path)) continue;

                        bool isLegit = false;
                        foreach (var allowed in allowedPaths)
                        {
                            // If expectation is a specific file path
                            if (allowed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            {
                                if (path.Equals(allowed, StringComparison.OrdinalIgnoreCase))
                                {
                                    isLegit = true;
                                    break;
                                }
                            }
                            // If expectation is a directory path
                            else
                            {
                                if (path.StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                                {
                                    isLegit = true;
                                    break;
                                }
                            }
                        }

                        if (!isLegit)
                        {
                            events.Add(new DetectionEvent
                            {
                                RuleId = RuleId,
                                RuleName = Name,
                                Severity = AlertSeverity.High,
                                Type = AlertType.MAL,
                                Description = $"System process {processName} running from illegitimate location: {path}. Expected one of: {string.Join(", ", allowedPaths)}",
                                Metadata = new { ProcessId = proc.Id, Path = path }
                            });
                        }
                    }
                }
                catch { /* Access denied or process exited */ }
            }
            return events;
        }
    }
}
