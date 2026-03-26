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

        public struct DetectionStats
        {
            public int ItemsChecked;
            public int AlertsFound;
        }

        public async Task<DetectionStats> RunCycle(Func<Task<bool>>? cancellationCheck = null)
        {
            DetectionStats stats = new DetectionStats();
            foreach (var rule in _rules)
            {
                if (cancellationCheck != null && await cancellationCheck()) break;

                try
                {
                    var events = rule.Evaluate();
                    stats.ItemsChecked += rule.ItemsChecked;
                    
                    if (events != null && events.Count > 0)
                    {
                        stats.AlertsFound += events.Count;
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
            return stats;
        }
    }
}
