using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
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
        private CancellationTokenSource _cts = new CancellationTokenSource();

        public AlertDispatcher(string backendUrl, string organizationApiKey, string agentId)
        {
            _httpClient = new HttpClient();
            _backendUrl = backendUrl.TrimEnd('/');
            _organizationApiKey = organizationApiKey;
            _agentId = agentId; 
        }

        public void Stop()
        {
            _cts.Cancel();
            _cts.Dispose();
            _cts = new CancellationTokenSource();
        }

        public async Task<bool> DispatchAsync(Alert alert)
        {
            try
            {
                var token = _cts.Token;
                if (token.IsCancellationRequested) return false;
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

                var response = await _httpClient.SendAsync(request, token);

                return response.IsSuccessStatusCode;
            }
            catch (TaskCanceledException)
            {
                // Dispatch was cancelled, return false
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
