using System;
using System.Collections.Generic;
using System.Threading;
using WinEDR_MVP.Interfaces;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public class DetectionEngine
    {
        private readonly List<IDetectionRule> _rules = new List<IDetectionRule>();
        private readonly AlertManager _alertManager;

        public DetectionEngine(AlertManager alertManager)
        {
            _alertManager = alertManager;
        }

        public void RegisterRule(IDetectionRule rule)
        {
            _rules.Add(rule);
        }

        public void RunCycle()
        {
            Console.WriteLine($"Running detection cycle at {DateTime.Now}...");
            foreach (var rule in _rules)
            {
                try
                {
                    var events = rule.Evaluate();
                    if (events != null && events.Count > 0)
                    {
                        foreach (var evt in events)
                        {
                            var alert = new Alert
                            {
                                RuleId = evt.RuleId,
                                Title = evt.RuleName,
                                Description = evt.Description,
                                Severity = evt.Severity,
                                Type = evt.Type,
                                SourceProcess = "System", // Default, can be refined
                                Metadata = evt.Metadata
                            };
                            _alertManager.AddAlert(alert);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error executing rule {rule.RuleId}: {ex.Message}");
                }
            }
        }
    }
}
