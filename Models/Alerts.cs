using System;

namespace WinEDR_MVP.Models
{
    public enum AlertSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum AlertType
    {
        MAL,    // Malware
        TROJ,   // Trojan
        BACK,   // Backdoor
        RECON,  // Reconnaissance
        RANSOM, // Ransomware
        INFO,   // Informational/Other
        Network // Network Forensics
    }

    public class Alert
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public AlertSeverity Severity { get; set; }
        public AlertType Type { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string SourceProcess { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public object Metadata { get; set; } = new object();
    }

    public class DetectionEvent
    {
        public string RuleId { get; set; } = string.Empty;
        public string RuleName { get; set; } = string.Empty;
        public AlertSeverity Severity { get; set; }
        public AlertType Type { get; set; }
        public string Description { get; set; } = string.Empty;
        public object Metadata { get; set; } = new object(); // Flexible payload (Process info, Network info)
    }
}
