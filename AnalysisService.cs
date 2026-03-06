using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using System.Net;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace NetSuite
{
    public class AnalysisService
    {
        // --- Static Trackers ---
        static int totalPackets = 0;
        static Dictionary<string, SourceMetrics> sourceStats = new Dictionary<string, SourceMetrics>();
        static Dictionary<string, string> arpTable = new Dictionary<string, string>(); // IP -> MAC
        static List<Alert> alerts = new List<Alert>();

        // High Risk Ports for NET-1
        static readonly HashSet<int> highRiskPorts = new HashSet<int> { 21, 22, 23, 445, 3389, 4444 };

        public class SourceMetrics
        {
            public string Ip { get; set; } = "";
            public HashSet<int> UniqueDstPorts = new HashSet<int>();
            public int AbnormalFlagPackets = 0;
            public HashSet<string> IcmpUniqueDstIps = new HashSet<string>();
            public HashSet<string> ArpUniqueTargetIps = new HashSet<string>();
            public Dictionary<string, ConnMetrics> Connections = new Dictionary<string, ConnMetrics>(); // TargetIP:Port -> Metrics
            public int UdpPackets = 0;
            public int IcmpEchoRequests = 0;
            public List<(DateTime Time, long Bytes, string DstIp)> OutboundFlows = new List<(DateTime, long, string)>();
            public Dictionary<string, List<DateTime>> DnsQueries = new Dictionary<string, List<DateTime>>(); // Domain -> List of Times
            public int NxDomainCount = 0;
            public int TotalDnsQueries = 0;
            public List<int> TtlValues = new List<int>();
            public Dictionary<int, int> HttpStatusCodeCounts = new Dictionary<int, int>();
            public int MaliciousUserAgentMatches = 0;
        }

        public class ConnMetrics
        {
            public int SynCount = 0;
            public int AckCount = 0;
            public int TotalPackets = 0;
            public long TotalBytes = 0;
            public DateTime StartTime;
            public DateTime LastTime;
        }

        public class Alert
        {
            public string Id { get; set; } = "";
            public string Message { get; set; } = "";
            public string Source { get; set; } = "";
            public string Target { get; set; } = "";
            public string Details { get; set; } = "";
        }

        public static void Run(string pcapFile, bool skipHeader = false)
        {
            if (!File.Exists(pcapFile))
            {
                Console.WriteLine($"Error: File not found at path: {pcapFile}");
                return;
            }

            // Reset
            totalPackets = 0;
            sourceStats.Clear();
            arpTable.Clear();
            alerts.Clear();

            try
            {
                using (ICaptureDevice device = new CaptureFileReaderDevice(pcapFile))
                {
                    device.Open();
                    device.OnPacketArrival += (s, e) => ProcessPacket(e.GetPacket());
                    device.Capture();
                }
                
                EvaluateRules();
                PrintReport(skipHeader);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Critical Error: {ex.Message}");
            }
        }

        private static void ProcessPacket(RawCapture raw)
        {
            totalPackets++;
            Packet packet;
            try {
                packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            } catch { return; }
            
            // NET-2/11: ARP
            var arp = packet.Extract<ArpPacket>();
            if (arp != null) HandleArp(arp);

            // Layer 3: IP
            var ip = packet.Extract<IPPacket>();
            if (ip == null) return;

            string srcIp = ip.SourceAddress.ToString();
            string dstIp = ip.DestinationAddress.ToString();
            
            if (!sourceStats.TryGetValue(srcIp, out var metrics))
            {
                metrics = new SourceMetrics { Ip = srcIp };
                sourceStats[srcIp] = metrics;
            }

            // NET-16: TTL
            metrics.TtlValues.Add(ip.TimeToLive);

            // Layer 4: ICMP
            var icmp = packet.Extract<IcmpV4Packet>();
            if (icmp != null)
            {
                if (icmp.TypeCode == IcmpV4TypeCode.EchoRequest)
                {
                    metrics.IcmpEchoRequests++;
                    metrics.IcmpUniqueDstIps.Add(dstIp);
                }
            }

            // Layer 4: UDP
            var udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                metrics.UdpPackets++;
                metrics.UniqueDstPorts.Add(udp.DestinationPort);
                
                // NET-7/12/13: DNS (UDP 53)
                if (udp.DestinationPort == 53 || udp.SourcePort == 53) HandleDns(metrics, udp.PayloadData, udp.SourcePort == 53, srcIp, dstIp);
            }

            // Layer 4: TCP
            var tcp = packet.Extract<TcpPacket>();
            if (tcp != null)
            {
                string connKey = $"{dstIp}:{tcp.DestinationPort}";
                if (!metrics.Connections.TryGetValue(connKey, out var conn)) 
                {
                    conn = new ConnMetrics { StartTime = raw.Timeval.Date };
                    metrics.Connections[connKey] = conn;
                }
                conn.LastTime = raw.Timeval.Date;
                conn.TotalPackets++;
                conn.TotalBytes += tcp.PayloadData?.Length ?? 0;

                // NET-1: Ports & Flags
                if (tcp.Synchronize) metrics.UniqueDstPorts.Add(tcp.DestinationPort);
                if (IsAbnormalTcpFlags(tcp)) metrics.AbnormalFlagPackets++;

                // NET-3: SYN Flood
                if (tcp.Synchronize && !tcp.Acknowledgment) conn.SynCount++;
                if (tcp.Acknowledgment) conn.AckCount++;

                // NET-8/9/15: Payload Rules
                if (tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                {
                    HandlePayload(metrics, tcp.PayloadData, srcIp, dstIp, tcp.DestinationPort, tcp.SourcePort);
                }
            }

            // NET-14: Exfiltration
            if (IsExternal(ip.DestinationAddress))
            {
                metrics.OutboundFlows.Add((raw.Timeval.Date, (long)raw.Data.LongLength, dstIp));
            }
        }

        private static bool IsAbnormalTcpFlags(TcpPacket tcp)
        {
            // FIN Scan: Only FIN
            if (tcp.Finished && !tcp.Synchronize && !tcp.Reset && !tcp.Push && !tcp.Acknowledgment && !tcp.Urgent) return true;
            // NULL Scan: No flags
            if (!tcp.Finished && !tcp.Synchronize && !tcp.Reset && !tcp.Push && !tcp.Acknowledgment && !tcp.Urgent) return true;
            // XMAS Scan: FIN, PSH, URG
            if (tcp.Finished && tcp.Push && tcp.Urgent) return true;
            return false;
        }

        private static void HandleArp(ArpPacket arp)
        {
            string senderIp = arp.SenderProtocolAddress.ToString();
            string senderMac = arp.SenderHardwareAddress.ToString();

            // NET-11: Spoofing
            if (arpTable.ContainsKey(senderIp) && arpTable[senderIp] != senderMac)
            {
                alerts.Add(new Alert { Id = "NET-11", Message = "ARP Spoofing Detected", Source = senderIp, Details = $"MAC changed from {arpTable[senderIp]} to {senderMac}" });
            }
            arpTable[senderIp] = senderMac;

            if (arp.Operation == ArpOperation.Request)
            {
                if (!sourceStats.TryGetValue(senderIp, out var metrics))
                {
                    metrics = new SourceMetrics { Ip = senderIp };
                    sourceStats[senderIp] = metrics;
                }
                metrics.ArpUniqueTargetIps.Add(arp.TargetProtocolAddress.ToString());
            }
        }

        private static void HandleDns(SourceMetrics m, byte[] data, bool isResponse, string src, string dst)
        {
            if (data == null || data.Length < 12) return;
            try {
                m.TotalDnsQueries++;
                string domain = ParseDnsDomain(data);
                if (string.IsNullOrEmpty(domain)) return;

                if (!m.DnsQueries.TryGetValue(domain, out var queryTimes))
                {
                    queryTimes = new List<DateTime>();
                    m.DnsQueries[domain] = queryTimes;
                }
                queryTimes.Add(DateTime.Now);

                if (isResponse) {
                    // Check NXDOMAIN (RCODE = 3 in byte 3)
                    if ((data[3] & 0x0F) == 3) m.NxDomainCount++;
                }

                // NET-12: Spoofing (Simplified)
                if (isResponse && !IsKnownResolver(src)) {
                    alerts.Add(new Alert { Id = "NET-12", Message = "DNS Response from Unknown Resolver", Source = src, Target = dst, Details = $"Domain: {domain}" });
                }
            } catch {}
        }

        private static string ParseDnsDomain(byte[] data)
        {
            StringBuilder sb = new StringBuilder();
            int pos = 12; // Skip ID, Flags, Counts
            try {
                while (pos < data.Length && data[pos] != 0) {
                    int len = data[pos];
                    if (pos + 1 + len > data.Length) break;
                    sb.Append(Encoding.ASCII.GetString(data, pos + 1, len)).Append(".");
                    pos += len + 1;
                }
            } catch { return ""; }
            return sb.ToString().TrimEnd('.');
        }

        private static void HandlePayload(SourceMetrics m, byte[] data, string src, string dst, int dPort, int sPort)
        {
            string payload = Encoding.ASCII.GetString(data);
            string lower = payload.ToLower();

            // NET-8: Cleartext
            if (lower.Contains("password=") || lower.Contains("login=") || lower.Contains("user ") || lower.Contains("pass "))
            {
                alerts.Add(new Alert { Id = "NET-8", Message = "Cleartext Credentials Found", Source = src, Target = dst, Details = $"Context: {lower.Substring(0, Math.Min(50, lower.Length))}" });
            }

            // NET-9: SQLi / XSS
            if (lower.Contains("union select") || lower.Contains("<script>") || lower.Contains("../") || lower.Contains("etc/passwd")) 
            {
                 alerts.Add(new Alert { Id = "NET-9", Message = "Web Exploitation Signature", Source = src, Target = dst, Details = $"Payload match: {lower.Substring(0, Math.Min(50, lower.Length))}" });
            }

            // NET-15: Web Recon
            var scanners = new[] { "sqlmap", "nmap", "masscan", "dirbuster", "nikto" };
            foreach (var s in scanners) if (lower.Contains(s)) m.MaliciousUserAgentMatches++;

            // Detect HTTP Status (simplified)
            if (payload.StartsWith("HTTP/1.")) {
                var parts = payload.Split(' ');
                if (parts.Length > 1 && int.TryParse(parts[1], out int code)) {
                    if (!m.HttpStatusCodeCounts.TryGetValue(code, out int count)) count = 0;
                    m.HttpStatusCodeCounts[code] = count + 1;
                }
            }
        }

        private static void EvaluateRules()
        {
            foreach (var m in sourceStats.Values)
            {
                // NET-1: Port Scan
                int scanThreshold = m.UniqueDstPorts.Any(p => highRiskPorts.Contains(p)) ? 5 : 30;
                if (m.UniqueDstPorts.Count >= scanThreshold)
                    alerts.Add(new Alert { Id = "NET-1", Message = "Port Scanning Detected", Source = m.Ip, Details = $"Unique Ports: {m.UniqueDstPorts.Count}" });
                if (m.AbnormalFlagPackets >= 5)
                    alerts.Add(new Alert { Id = "NET-1", Message = "Abnormal TCP Flags Detected", Source = m.Ip, Details = $"Packets: {m.AbnormalFlagPackets}" });

                // NET-2: Sweeps
                if (m.IcmpUniqueDstIps.Count >= 30)
                    alerts.Add(new Alert { Id = "NET-2", Message = "ICMP Sweep Detected", Source = m.Ip, Details = $"Unique Targets: {m.IcmpUniqueDstIps.Count}" });
                if (m.ArpUniqueTargetIps.Count >= 40)
                    alerts.Add(new Alert { Id = "NET-2", Message = "ARP Sweep Detected", Source = m.Ip, Details = $"Unique Targets: {m.ArpUniqueTargetIps.Count}" });

                // NET-4/5: Floods
                if (m.UdpPackets >= 10000 || m.UniqueDstPorts.Count >= 100)
                    alerts.Add(new Alert { Id = "NET-4", Message = "UDP Flood Detected", Source = m.Ip, Details = $"Packets: {m.UdpPackets}, Ports: {m.UniqueDstPorts.Count}" });
                if (m.IcmpEchoRequests >= 5000)
                    alerts.Add(new Alert { Id = "NET-5", Message = "ICMP Flood Detected", Source = m.Ip, Details = $"Requests: {m.IcmpEchoRequests}" });

                // NET-3: SYN Flood
                foreach (var connPair in m.Connections) {
                    var conn = connPair.Value;
                    if (conn.SynCount >= 500 && (conn.AckCount == 0 || (double)conn.AckCount / conn.SynCount <= 0.1))
                        alerts.Add(new Alert { Id = "NET-3", Message = "SYN Flood Detected", Source = m.Ip, Target = connPair.Key, Details = $"SYN: {conn.SynCount}, ACK: {conn.AckCount}" });
                }

                // NET-7/13: DNS
                double nxRate = m.TotalDnsQueries > 0 ? (double)m.NxDomainCount / m.TotalDnsQueries : 0;
                int dnsCond = 0;
                if (m.DnsQueries.Keys.Any(d => CalculateEntropy(d) >= 3.8)) dnsCond++;
                if (m.DnsQueries.Keys.Any(d => d.Length >= 20)) dnsCond++;
                if (nxRate >= 0.6 && m.TotalDnsQueries >= 20) dnsCond++;
                if (m.DnsQueries.Count >= 25) dnsCond++;
                if (dnsCond >= 2) alerts.Add(new Alert { Id = "NET-7", Message = "Suspicious DNS / DGA Pattern", Source = m.Ip, Details = $"Unique Domains: {m.DnsQueries.Count}, NX Rate: {nxRate:P}" });

                // NET-14: Exfiltration
                long totalOut = m.OutboundFlows.Sum(f => f.Bytes);
                if (totalOut >= 500 * 1024 * 1024)
                    alerts.Add(new Alert { Id = "NET-14", Message = "Large Outbound Transfer", Source = m.Ip, Details = $"Bytes: {totalOut / 1024 / 1024} MB" });

                // NET-15: Web App
                int authFailures = m.HttpStatusCodeCounts.GetValueOrDefault(401) + m.HttpStatusCodeCounts.GetValueOrDefault(403);
                if (m.MaliciousUserAgentMatches >= 1 || authFailures >= 20 || m.HttpStatusCodeCounts.GetValueOrDefault(404) >= 50)
                    alerts.Add(new Alert { Id = "NET-15", Message = "Web Reconnaissance Detected", Source = m.Ip, Details = $"Scanner Match: {m.MaliciousUserAgentMatches}, 404s: {m.HttpStatusCodeCounts.GetValueOrDefault(404)}" });

                // NET-16: TTL
                if (m.TtlValues.Count > 10) {
                    int massiveJump = 0;
                    for(int i=1; i<m.TtlValues.Count; i++) if (Math.Abs(m.TtlValues[i] - m.TtlValues[i-1]) > 32) massiveJump++;
                    if (massiveJump >= 3) alerts.Add(new Alert { Id = "NET-16", Message = "TTL Anomaly Detected", Source = m.Ip, Details = $"Large TTL Fluctuations: {massiveJump}" });
                }
            }
        }

        private static double CalculateEntropy(string s) {
            var map = new Dictionary<char, int>();
            foreach (char c in s) { if (!map.TryGetValue(c, out int count)) count = 0; map[c] = count + 1; }
            double result = 0;
            foreach (var count in map.Values) {
                double p = (double)count / s.Length;
                result -= p * Math.Log2(p);
            }
            return result;
        }

        private static bool IsExternal(IPAddress ip) {
            byte[] bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return true;
            if (bytes[0] == 10) return false;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
            if (bytes[0] == 192 && bytes[1] == 168) return false;
            return true;
        }

        private static bool IsKnownResolver(string ip) => ip == "8.8.8.8" || ip == "1.1.1.1" || ip == "8.8.4.4" || ip == "192.168.1.1";

        private static void PrintReport(bool skipHeader)
        {
            if (!skipHeader)
            {
                Console.WriteLine("\n" + new string('=', 60));
                Console.WriteLine("             ENHANCED SECURITY ANALYSIS REPORT             ");
                Console.WriteLine(new string('=', 60));
            }

            Console.WriteLine($"Total Packets Processed: {totalPackets}");
            Console.WriteLine($"Detection Window: 60 Seconds");
            Console.WriteLine(new string('-', 60));

            if (alerts.Count == 0) {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("NO THREATS DETECTED.");
                Console.ResetColor();
            } else {
                foreach (var alert in alerts.OrderBy(a => a.Id)) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[{alert.Id}] {alert.Message}");
                    Console.ResetColor();
                    Console.WriteLine($"   Source: {alert.Source}");
                    if (!string.IsNullOrEmpty(alert.Target)) Console.WriteLine($"   Target: {alert.Target}");
                    Console.WriteLine($"   Details: {alert.Details}");
                    Console.WriteLine();
                }
            }
            Console.WriteLine(new string('=', 60) + "\n");
        }
    }
}
