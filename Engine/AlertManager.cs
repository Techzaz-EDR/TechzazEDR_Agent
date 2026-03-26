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
        private readonly List<Task<bool>> _dispatchTasks = new List<Task<bool>>();
        private readonly AlertDispatcher? _dispatcher;

        public int SuccessCount { get; private set; } = 0;
        public int FailureCount { get; private set; } = 0;

        public bool SilentMode { get; set; } = false;
        public AlertDispatcher? Dispatcher => _dispatcher;

        public event Action<Alert>? OnAlert;

        public AlertManager(string logPath = "alerts.log", AlertDispatcher? dispatcher = null)
        {
            _logPath = logPath;
            _dispatcher = dispatcher;
        }

        public void AddAlert(Alert alert)
        {
            lock (_lock)
            {
                _alerts.Add(alert);
                LogAlert(alert);
                OnAlert?.Invoke(alert);
                
                // Track the dispatch task and its result
                if (_dispatcher != null)
                {
                    var task = _dispatcher.DispatchAsync(alert);
                    _dispatchTasks.Add(task);
                }
                
                if (!SilentMode)
                {
                    PrintSingleAlert(alert);
                }
            }
        }

        private void PrintSingleAlert(Alert alert)
        {
            DateTime now = DateTime.Now;
            string timestamp = now.ToString("HH:mm:ss");
            
            Console.WriteLine(new string('-', 75));
            Console.ForegroundColor = alert.Severity == AlertSeverity.High ? ConsoleColor.Red : (alert.Severity == AlertSeverity.Medium ? ConsoleColor.Yellow : ConsoleColor.White);
            Console.WriteLine($"[{timestamp}] [!] ALERT: {alert.Type} ({alert.Severity})");
            Console.ResetColor();
            
            Console.WriteLine($"               Name: {alert.Title}");
            
            string path = GetMetadataValue(alert.Metadata, "Path") ?? "N/A";
            Console.WriteLine($"               Path: {path}");
            Console.WriteLine($"               Reason: {alert.Description}");
            Console.WriteLine(new string('-', 75));
        }

        private string? GetMetadataValue(object metadata, string key)
        {
            if (metadata == null) return null;
            
            try
            {
                // Try to find the property using reflection (for anonymous types)
                var property = metadata.GetType().GetProperty(key);
                if (property != null)
                {
                    return property.GetValue(metadata)?.ToString();
                }

                // If it's a Dictionary (like in AnalysisService)
                if (metadata is Dictionary<string, string> dict)
                {
                    if (dict.TryGetValue(key, out var val)) return val;
                }

                // Try to serialize and deserialize if it's a JsonElement
                if (metadata is JsonElement element && element.ValueKind == JsonValueKind.Object)
                {
                    if (element.TryGetProperty(key, out var prop))
                    {
                        return prop.GetString();
                    }
                }
            }
            catch { }
            
            return null;
        }

        public async Task<(int success, int failure)> WaitForDispatchesAsync()
        {
            List<Task<bool>> tasksToWait;
            lock (_lock)
            {
                tasksToWait = new List<Task<bool>>(_dispatchTasks);
            }
            
            if (tasksToWait.Count > 0)
            {
                var results = await Task.WhenAll(tasksToWait);
                
                int currentSuccess = 0;
                int currentFailure = 0;
                
                foreach (bool success in results)
                {
                    if (success) currentSuccess++;
                    else currentFailure++;
                }

                lock (_lock)
                {
                    SuccessCount += currentSuccess;
                    FailureCount += currentFailure;
                    _dispatchTasks.Clear();
                }

                return (currentSuccess, currentFailure);
            }

            return (0, 0);
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
                    PrintSingleAlert(alert);
                }
            }
        }
    }
}
