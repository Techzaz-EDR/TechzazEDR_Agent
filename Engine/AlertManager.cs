using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public class AlertManager
    {
        private readonly List<Alert> _alerts = new List<Alert>();
        private readonly string _logPath;
        private readonly object _lock = new object();

        public bool SilentMode { get; set; } = false;

        public event Action<Alert>? OnAlert;

        public AlertManager(string logPath = "alerts.log")
        {
            _logPath = logPath;
        }

        public void AddAlert(Alert alert)
        {
            lock (_lock)
            {
                _alerts.Add(alert);
                LogAlert(alert);
                OnAlert?.Invoke(alert);
                
                if (!SilentMode)
                {
                    // Console output for CLI interaction
                    Console.ForegroundColor = alert.Severity == AlertSeverity.High ? ConsoleColor.Red : (alert.Severity == AlertSeverity.Medium ? ConsoleColor.Yellow : ConsoleColor.White);
                    Console.WriteLine($"[System Scan ALERT] {alert.Type} ({alert.Severity}): {alert.Title} - {alert.Description}");
                    Console.ResetColor();
                }
            }
        }

        private void LogAlert(Alert alert)
        {
            try
            {
                var json = JsonSerializer.Serialize(alert);
                File.AppendAllText(_logPath, json + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to log alert: {ex.Message}");
            }
        }

        public List<Alert> GetAlerts()
        {
            lock(_lock)
            {
                return new List<Alert>(_alerts);
            }
        }

        public void PrintAllAlerts()
        {
            lock (_lock)
            {
                foreach (var alert in _alerts)
                {
                    Console.ForegroundColor = alert.Severity == AlertSeverity.High ? ConsoleColor.Red : (alert.Severity == AlertSeverity.Medium ? ConsoleColor.Yellow : ConsoleColor.White);
                    Console.WriteLine($"[System Scan ALERT] {alert.Type} ({alert.Severity}): {alert.Title} - {alert.Description}");
                    Console.ResetColor();
                }
            }
        }
    }
}
