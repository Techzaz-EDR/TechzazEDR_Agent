using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using WinEDR_MVP.Models;

namespace WinEDR_MVP.Engine
{
    public class AlertDispatcher
    {
        private readonly HttpClient _httpClient;
        private readonly string _backendUrl;
        private readonly string _organizationApiKey;
        private readonly string _agentId;

        public AlertDispatcher(string backendUrl, string organizationApiKey)
        {
            _httpClient = new HttpClient();
            _backendUrl = backendUrl.TrimEnd('/');
            _organizationApiKey = organizationApiKey;
            // Use MachineName as the default AgentId
            _agentId = Environment.MachineName; 
        }

        public async Task DispatchAsync(Alert alert)
        {
            try
            {
                // Map the internal Alert to the specific JSON schema required by the backend
                var payload = new
                {
                    Timestamp = alert.Timestamp.ToString("o"), // ISO 8601 format
                    RuleId = alert.RuleId,
                    Category = alert.Type.ToString(),
                    Severity = alert.Severity.ToString(),
                    Status = "New",
                    Details = alert.Metadata // The frontend expects the custom payload in Details
                };

                var jsonPayload = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                // Route to /api/v1/alerts?agent_id=...
                string url = $"{_backendUrl}/api/v1/alerts?agent_id={_agentId}";
                
                // Initialize http request
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("x-api-key", _organizationApiKey);
                request.Content = content;

                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[AlertDispatcher] Failed to dispatch alert: {response.StatusCode}");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[AlertDispatcher] Error connecting to backend: {ex.Message}");
                Console.ResetColor();
            }
        }
    }
}
