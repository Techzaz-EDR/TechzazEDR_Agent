using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace WinEDR_MVP.Config
{
    public class AppConfig
    {
        public List<string> TrustedSystemProcesses { get; set; } = new List<string>();
        public List<string> TrustedExecutionPaths { get; set; } = new List<string>();
        public List<string> UntrustedExecutionPaths { get; set; } = new List<string>();
        public Dictionary<string, List<string>> ProcessPathExpectations { get; set; } = new Dictionary<string, List<string>>();
        public Dictionary<string, RuleConfig> Rules { get; set; } = new Dictionary<string, RuleConfig>();
        public int NetworkScanWindowSeconds { get; set; } = 30;
        public string YaraRulesPath { get; set; } = @"Rules\Yara";

        public static AppConfig Load(string path)
        {
            if (!File.Exists(path)) return new AppConfig();
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
        }
    }

    public class RuleConfig
    {
        public bool Enabled { get; set; } = true;
        public int Threshold { get; set; }
        public string Severity { get; set; } = string.Empty;
    }
}
