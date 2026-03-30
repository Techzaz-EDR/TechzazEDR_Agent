using System;
using System.Drawing;
using System.Windows.Forms;
using TechzazEdrWindowsAgent;

namespace TechzazEdrWindowsAgent
{
    public class TrayIconContext : ApplicationContext
    {
        private NotifyIcon _notifyIcon;
        private ContextMenuStrip _contextMenu;
        private ToolStripMenuItem _toggleConsoleItem;

        public TrayIconContext()
        {
            // Initialize Context Menu
            _contextMenu = new ContextMenuStrip();
            _contextMenu.Items.Add("Run Integrated Analysis", null, OnRunIntegratedAnalysis);
            _contextMenu.Items.Add("Run Live Security Analyzer", null, OnRunLiveCapture);
            _contextMenu.Items.Add(new ToolStripSeparator());
            _toggleConsoleItem = new ToolStripMenuItem("Show Console", null, OnToggleConsole);
            _contextMenu.Items.Add(_toggleConsoleItem);
            _contextMenu.Items.Add(new ToolStripSeparator());
            _contextMenu.Items.Add("Exit", null, OnExit);

            // Initialize Notify Icon
            _notifyIcon = new NotifyIcon()
            {
                Icon = new Icon(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.ico")),
                ContextMenuStrip = _contextMenu,
                Visible = true,
                Text = "TechzazEDR Agent"
            };

            _notifyIcon.DoubleClick += (s, e) => OnToggleConsole(s, e);
            
            // Set initial state of console toggle based on Program state
            _toggleConsoleItem.Text = Program.IsConsoleVisible() ? "Hide Console" : "Show Console";
            
            // Register for global notifications
            Program.OnNotification += (title, message) => ShowNotification(title, message);
        }

        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            _notifyIcon.ShowBalloonTip(3000, title, message, icon);
        }

        private async void OnRunIntegratedAnalysis(object? sender, EventArgs e)
        {
            ShowNotification("Internal Analysis Started", "Performing System & PCAP scan...");
            await Program.RunPcapAnalysis();
        }

        private async void OnRunLiveCapture(object? sender, EventArgs e)
        {
            ShowNotification("Live Analyzer Started", "Performing simultaneous capture & scan...");
            await Program.RunBothAtOnce();
        }

        private void OnToggleConsole(object? sender, EventArgs e)
        {
            Program.ToggleConsole();
            _toggleConsoleItem.Text = Program.IsConsoleVisible() ? "Hide Console" : "Show Console";
        }

        private void OnExit(object? sender, EventArgs e)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            Application.Exit();
            Environment.Exit(0);
        }
    }
}
