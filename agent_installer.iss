; TechzazEDR Agent Professional Installer
; Designed for Windows 10/11 x64

[Setup]
AppName=TechzazEDR Security Agent
AppVersion=1.0.0
DefaultDirName={commonpf}\TechzazEDR
DefaultGroupName=TechzazEDR
OutputDir=.\installer_output
OutputBaseFilename=TechzazEDR_Agent_Setup
SetupIconFile=icon.ico
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "Run TechzazEDR Agent on system startup"; GroupDescription: "Post-installation options:"; Flags: checkedonce

[Files]
; Base Binaries
Source: "bin\Release\net10.0-windows\TechzazEdrWindowsAgent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\TechzazEdrWindowsAgent.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\TechzazEdrWindowsAgent.runtimeconfig.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\TechzazEdrWindowsAgent.deps.json"; DestDir: "{app}"; Flags: ignoreversion

; Dependencies
Source: "bin\Release\net10.0-windows\PacketDotNet.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\SharpPcap.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\dnYara.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net10.0-windows\dnYara.Interop.dll"; DestDir: "{app}"; Flags: ignoreversion

; Runtimes (Recursive)
Source: "bin\Release\net10.0-windows\runtimes\*"; DestDir: "{app}\runtimes"; Flags: ignoreversion recursesubdirs createallsubdirs

; Configuration & Assets
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "Rules\*"; DestDir: "{app}\Rules"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\TechzazEDR Agent"; Filename: "{app}\TechzazEdrWindowsAgent.exe"; IconFilename: "{app}\icon.ico"
Name: "{commondesktop}\TechzazEDR Agent"; Filename: "{app}\TechzazEdrWindowsAgent.exe"; Tasks: desktopicon; IconFilename: "{app}\icon.ico"

[Registry]
; Start on Startup (HKLM required for administrative agents)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TechzazEDRAgent"; ValueData: """{app}\TechzazEdrWindowsAgent.exe"""; Tasks: startup; Flags: uninsdeletevalue

[Run]
Filename: "{app}\TechzazEdrWindowsAgent.exe"; Description: "{cm:LaunchProgram,TechzazEDR Agent}"; Flags: nowait postinstall skipifsilent

[Code]
var
  BootstrapPage: TInputFileWizardPage;
  NpcapInstallerFound: Boolean;

procedure InitializeWizard;
begin
  // Check if Npcap installer is present in the source folder (optional)
  NpcapInstallerFound := FileExists(ExpandConstant('{src}\npcap-installer.exe'));

  // Create a custom page to browse for the bootstrap script (Moved to wpSelectTasks)
  BootstrapPage := CreateInputFilePage(wpSelectTasks,
    'Agent Configuration', 'Select your bootstrap script',
    'To finalize the agent setup, please select the bootstrap.ps1 file you downloaded from the TechzazEDR Dashboard.');

  BootstrapPage.Add('Bootstrap File (.ps1):', 'PowerShell Scripts|*.ps1|All files|*.*', '.ps1');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = BootstrapPage.ID then
  begin
    if BootstrapPage.Values[0] = '' then
    begin
      MsgBox('You must select a bootstrap.ps1 file to proceed with the agent configuration.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  BootstrapPath: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // 1. Handle Bootstrap Execution
    BootstrapPath := BootstrapPage.Values[0];
    if (BootstrapPath <> '') and FileExists(BootstrapPath) then
    begin
      WizardForm.StatusLabel.Caption := 'Configuring Agent...';
      // Run PowerShell script with Bypass policy
      if not Exec('powershell.exe', 
        '-ExecutionPolicy Bypass -File "' + BootstrapPath + '"', 
        ExpandConstant('{app}'), 
        SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      begin
        MsgBox('Bootstrap configuration failed. You may need to run the script manually as administrator.', mbError, MB_OK);
      end;
    end;

    // 2. Handle Npcap Installation Prompt
    if MsgBox('TechzazEDR requires Npcap to perform network monitoring. Would you like to install it now?', mbConfirmation, MB_YESNO) = IDYES then
    begin
       // If bundled, run it. Otherwise, open the download page.
       if NpcapInstallerFound then
         Exec(ExpandConstant('{src}\npcap-installer.exe'), '', '', SW_SHOW, ewWaitUntilTerminated, ResultCode)
       else
         ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;
