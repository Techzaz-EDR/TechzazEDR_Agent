using System;
using System.Collections.Generic;
using Microsoft.Win32;
using WinEDR_MVP.Interfaces;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Rules.HIDS
{
    public class StartupPersistenceRule : IDetectionRule
    {
        public string RuleId => "HIDS-B1";
        public string Name => "Startup Persistence";
        public string Description => "Detects suspicious entries in Windows Startup Registry keys.";
        public int ItemsChecked { get; private set; }
        
        public List<DetectionEvent> Evaluate()
        {
            var events = new List<DetectionEvent>();
            ItemsChecked = 0;
            // Key locations
            string[] keys = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                ItemsChecked++;
                                string? value = key.GetValue(valueName)?.ToString();
                                // MVP Heuristic: If it points to AppData or Temp, flag it.
                                if (value != null && (value.Contains("AppData", StringComparison.OrdinalIgnoreCase) || 
                                                      value.Contains("Temp", StringComparison.OrdinalIgnoreCase)))
                                {
                                    events.Add(new DetectionEvent
                                    {
                                        RuleId = "HIDS-B1",
                                        RuleName = "Suspicious Startup Item",
                                        Severity = AlertSeverity.Medium,
                                        Type = AlertType.MAL,
                                        Description = $"Registry Persistence found in {keyPath}: {valueName} -> {value}",
                                        Metadata = new { FilePath = value, RegistryKey = keyPath, ValueName = valueName }
                                    });
                                }
                            }
                        }
                    }
                }
                catch {}
            }
            return events;
        }
    }
}
