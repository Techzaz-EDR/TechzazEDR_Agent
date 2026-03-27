using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WinEDR_MVP.Engine
{
    public class CommandService
    {
        private readonly HttpClient _httpClient;
        private readonly string _backendUrl;
        private readonly string _organizationApiKey;
        private readonly string _agentId;
        private readonly string _agentName;
        private readonly Func<string, string, Task> _commandExecutor;
        private bool _isRunning;

        public CommandService(string backendUrl, string organizationApiKey, string agentId, string agentName, Func<string, string, Task> commandExecutor)
        {
            _httpClient = new HttpClient();
            _backendUrl = backendUrl.TrimEnd('/');
            _organizationApiKey = organizationApiKey;
            _agentId = agentId;
            _agentName = agentName;
            _commandExecutor = commandExecutor;
        }

        public void Start()
        {
            if (_isRunning) return;
            _isRunning = true;
            Task.Run(() => PollLoop());
        }

        public void Stop()
        {
            _isRunning = false;
        }

        private async Task PollLoop()
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [i] SYNC: Command polling service started for Agent: {_agentId}");
            
            while (_isRunning)
            {
                try
                {
                    await PollAndExecute();
                }
                catch (Exception ex)
                {
                    // Silent fail to keep polling
                    Console.WriteLine($"Poll error: {ex.Message}");
                }
                
                await Task.Delay(5000); // Poll every 5 seconds
            }
        }

        private async Task PollAndExecute()
        {
            string url = $"{_backendUrl}/api/v1/commands/poll?agent_id={_agentId}&agent_name={Uri.EscapeDataString(_agentName)}";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("x-api-key", _organizationApiKey);

            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode) return;

            var json = await response.Content.ReadAsStringAsync();
            var commands = JsonSerializer.Deserialize<List<JsonElement>>(json);

            if (commands == null || commands.Count == 0) return;

            foreach (var cmd in commands)
            {
                string cmdId = cmd.GetProperty("id").GetString()!;
                string cmdName = cmd.GetProperty("command").GetString()!;

                Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] [!] COMMAND RECEIVED: {cmdName} (ID: {cmdId})");
                
                // 1. Acknowledge
                await UpdateStatus(cmdId, "executing");

                try
                {
                    // 2. Execute (pass both cmdId and cmdName)
                    await _commandExecutor(cmdId, cmdName);
                    
                    // 3. Complete
                    await UpdateStatus(cmdId, "completed");
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [✓] COMMAND COMPLETE: {cmdName}");
                }
                catch (Exception ex)
                {
                    await UpdateStatus(cmdId, "failed");
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [X] COMMAND FAILED: {cmdName} - {ex.Message}");
                }
            }
        }

        public async Task<string?> GetCommandStatus(string cmdId)
        {
            string url = $"{_backendUrl}/api/v1/commands/{cmdId}?agent_id={_agentId}";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("x-api-key", _organizationApiKey);

            try
            {
                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode) return null;

                var json = await response.Content.ReadAsStringAsync();
                var cmd = JsonSerializer.Deserialize<JsonElement>(json);
                return cmd.GetProperty("status").GetString();
            }
            catch
            {
                return null;
            }
        }

        private async Task UpdateStatus(string cmdId, string status)
        {
            string url = $"{_backendUrl}/api/v1/commands/{cmdId}?agent_id={_agentId}&status={status}";
            var request = new HttpRequestMessage(HttpMethod.Patch, url);
            request.Headers.Add("x-api-key", _organizationApiKey);
            
            await _httpClient.SendAsync(request);
        }

        public async Task UpdateStatusWithResult(string cmdId, string status, string result)
        {
            string url = $"{_backendUrl}/api/v1/commands/{cmdId}?agent_id={_agentId}&status={status}";
            var request = new HttpRequestMessage(HttpMethod.Patch, url);
            request.Headers.Add("x-api-key", _organizationApiKey);
            request.Content = new StringContent(
                JsonSerializer.Serialize(new { result }),
                Encoding.UTF8,
                "application/json"
            );
            await _httpClient.SendAsync(request);
        }
    }
}
