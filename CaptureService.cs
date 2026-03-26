using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetSuite
{
    public class CaptureService
    {
        public static async Task<string?> Run(string outputDir, Func<Task<bool>>? cancellationCheck = null)
        {

            try
            {
                // Retrieve the device list
                var devices = CaptureDeviceList.Instance;

                // If no devices were found print an error
                if (devices.Count < 1)
                {
                    Console.WriteLine("No devices were found on this machine.");
                    return null;
                }

                // 1. Device Enumeration & Selection
                Console.WriteLine("Scanning Network Devices...");
                ILiveDevice selectedDevice = null;
                int i = 0;

                // Keywords to prioritize
                var wifiKeywords = new[] { "Wi-Fi", "Wireless", "WLAN", "802.11", "Intel(R) Wi-Fi", "Qualcomm Atheros", "Realtek RTL8822" };
                var ethernetKeywords = new[] { "Ethernet", "GbE", "Controller", "Realtek PCIe GBE", "Intel(R) Ethernet Connection" };

                // Iterate and list devices, also looking for the best match
                foreach (var dev in devices)
                {
                    // Logic to prioritize devices
                    string desc = dev.Description ?? "";
                    
                    bool isMatch = false;
                    foreach (var k in wifiKeywords) if (desc.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0) isMatch = true;
                    foreach (var k in ethernetKeywords) if (desc.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0) isMatch = true;

                    // If we found a "likely" device and haven't selected one yet, pick it.
                    if (isMatch && selectedDevice == null)
                    {
                        selectedDevice = dev;
                    }

                    i++;
                }

                // Fallback: If no keyword match found, use the first device (index 0) if available
                if (selectedDevice == null && devices.Count > 0)
                {
                    selectedDevice = devices[0];
                }
                
                if (selectedDevice == null)
                {
                    Console.WriteLine("No capture devices found.");
                    return null;
                }

                Console.WriteLine($"Automatically selected device: {selectedDevice.Name} - {selectedDevice.Description}");

                // 2. Configuration
                selectedDevice.Open(DeviceModes.Promiscuous, 1000);

                // 3. Capture Loop Setup
                // Ensure output directory exists
                if (!Directory.Exists(outputDir))
                {
                    Directory.CreateDirectory(outputDir);
                }

                // Create a timestamped filename to avoid overwrites (or just use 120snetcapture.pcap if strictly requested, 
                // but for a suite, a timestamp is better. However, strict adherence to previous logic = fixed name. 
                // Let's stick to the previous fixed name pattern but maybe add a timestamp if user didn't forbid it.
                // The previous conversation history showed user wanting timestamped filename in "Refining NetRecorder Output",
                // but the current code I read had "30snetcapture.pcap". 
                // I will use "120snetcapture.pcap" to match the exact code I read, but maybe make it safer?
                // Actually, let's stick to the code I read: "120snetcapture.pcap".
                var captureFilename = Path.Combine(outputDir, "60snetcapture.pcap");
                
                Console.WriteLine($"Capture will be saved to: {captureFilename}");

                var writer = new CaptureFileWriterDevice(captureFilename);
                writer.Open(selectedDevice.LinkType);

                Console.WriteLine("Recording started...");

                // Setup the event handler to write to file
                selectedDevice.OnPacketArrival += (sender, e) =>
                {
                    writer.Write(e.GetPacket());
                };

                selectedDevice.StartCapture();
                
                // 4. Timer Logic
                int durationMs = 60000;
                int elapsedMs = 0;
                int stepMs = 500;

                while (elapsedMs < durationMs)
                {
                    if (cancellationCheck != null && await cancellationCheck())
                    {
                        Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] [!] ABORTING: Network capture cancelled by user.");
                        break;
                    }
                    await Task.Delay(stepMs);
                    elapsedMs += stepMs;
                }

                // Stop capture
                selectedDevice.StopCapture();
                writer.Close(); 
                selectedDevice.Close();

                Console.WriteLine($"Capture successfully saved to: {captureFilename}");
                return captureFilename;

            }
            catch (DllNotFoundException)
            {
                Console.WriteLine("Error: DllNotFoundException. Npcap is likely not installed.");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unexpected error occurred during capture: {ex.Message}");
                return null;
            }
        }
    }
}
