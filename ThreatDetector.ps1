Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem
# ASCII Art for Creator
$asciiArt = @"
▄▄▄█████▓ ██░ ██  ██▀███  ▓█████ ▄▄▄     ▄▄▄█████▓    ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███  
▓  ██▒ ▓▒▓██░ ██▒▓██ ▒ ██▒▓█   ▀▒████▄   ▓  ██▒ ▓▒   ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒ ▓██░ ▒░▒██▀▀██░▓██ ░▄█ ▒▒███  ▒██  ▀█▄ ▒ ▓██░ ▒░   ▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
░ ▓██▓ ░ ░▓█ ░██ ▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██░ ▓██▓ ░    ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
  ▒██▒ ░ ░▓█▒░██▓░██▓ ▒██▒░▒████▒▓█   ▓██▒ ▒██▒ ░    ░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
  ▒ ░░    ▒ ░░▒░▒░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░ ▒ ░░       ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░     ▒ ░▒░ ░  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░   ░        ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░
  ░       ░  ░░ ░  ░░   ░    ░    ░   ▒    ░          ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░ 
          ░  ░  ░   ░        ░  ░     ░  ░            ░  ░  ░   ░              ░             ░  ░   ░     
                                                                                                          
         Str1k3r0p - Advanced Threat Detection
"@
Write-Host $asciiArt -ForegroundColor Green
Write-Host ">>> Enterprise Advanced Threat Detector started..." -ForegroundColor Cyan
Write-Host "Created by: Str1k3r0p" -ForegroundColor Yellow
$logFile = "C:\threat_detector.log"
$quarantinePath = "C:\ThreatQuarantine\"
$threatIntelPath = "C:\ThreatIntel\"
$hashDatabasePath = "C:\ThreatIntel\HashDatabase.json"
$threatCachePath = "C:\ThreatIntel\ThreatCache.json"
$configPath = "$threatIntelPath\config.json"
# Ensure directories exist
@($quarantinePath, $threatIntelPath) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}
# Comprehensive threat detection patterns
$malwareTypes = @{
    "Cryptominer" = @("*xmrig*", "*miner*", "*monero*", "*ethereum*", "*cryptonight*", "*coinhive*", "*minexmr*")
    "Ransomware" = @("*ransom*", "*encrypt*", "*lock*", "*.locked", "*.encrypted", "*cryptolocker*", "*wannacry*")
    "Trojan" = @("*trojan*", "*backdoor*", "*reverse_shell*", "*netcat*", "*nc*", "*bind*", "*meterpreter*")
    "Botnet" = @("*bot*", "*c2*", "*command_and_control*", "*zeus*", "*emotet*", "*trickbot*")
    "Spyware" = @("*spy*", "*keylog*", "*monitor*", "*stealer*", "*credential*", "*password*")
    "Downloader" = @("*downloader*", "*installer*", "*payload*", "*dropper*", "*loader*")
    "Rootkit" = @("*rootkit*", "*hidden*", "*system*", "*kernel*", "*driver*")
    "Worm" = @("*worm*", "*spread*", "*replicate*", "*network_share*")
    "Adware" = @("*adware*", "*popup*", "*browser_hijack*", "*toolbar*")
}
# Suspicious content patterns for file analysis
$suspiciousContentPatterns = @(
    "http://.*\.onion/",
    "stratum\+tcp://",
    "mining pool",
    "cryptonight",
    "ransom note",
    "send bitcoin",
    "decryption key",
    "command and control",
    "reverse shell",
    "base64 encoded",
    "powershell -enc",
    "eval\(base64_decode",
    "document\.write\(unescape\("
)
# Registry locations to monitor
$suspiciousRegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Classes\exefile\shell\open\command"
)
# Network indicators
$suspiciousDomains = @("*.bit.ly", "*.tinyurl.com", "*.go.link", "*.rebrand.ly", "*.shorte.st", "*.adf.ly")
$suspiciousTLDs = @(".ru", ".cn", ".br", ".in", ".ua", ".kp", ".su", ".cc", ".tk", ".ml", ".ga", ".cf")
$suspiciousIPRanges = @("192.168.100.", "10.10.10.", "172.16.10.", "185.163.45.", "45.9.148.", "91.215.85.")
# Suspicious processes and behaviors
$suspiciousProcessNames = @(
    "miner", "xmrig", "cpuminer", "ccminer", "ethminer", 
    "powershell", "cmd", "wscript", "cscript", "mshta", 
    "rundll32", "regsvr32", "schtasks", "bitsadmin", "certutil"
)
# Whitelists
$whitelistedIPs = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
$whitelistedServices = @("NVAgent", "NvContainerLocalSystem", "NvDisplay.ContainerLocalSystem", 
                        "MozillaMaintenance", "GoogleUpdate", "OneDrive", "SecurityHealthService")
$whitelistedTasks = @("NvDriverUpdate", "NVIDIA", "GoogleUpdate", "OneDrive", "Microsoft")
$whitelistedFiles = @("nvagent.dll", "nvcontainer.exe", "nvidia.exe", "googleupdate.exe", "onedrive.exe")
# Performance counters
$perfCounters = @{
    "CPU Usage" = 0
    "Memory Usage" = 0
    "Network Connections Checked" = 0
    "Alerts Triggered" = 0
    "Threats Detected" = @{ }
    "Behavioral Anomalies" = 0
    "Last Check Time" = Get-Date
}
# Initialize threat counters and databases
foreach ($threatType in $malwareTypes.Keys) {
    $perfCounters["Threats Detected"][$threatType] = 0
}
# ==================== PROGRESS DISPLAY FUNCTIONS ====================
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [int]$SecondsRemaining
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -SecondsRemaining $SecondsRemaining
}
function Show-ScanProgress {
    param(
        [string]$ScanType,
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem
    )
    $percent = if ($Total -gt 0) { [math]::Round(($Current / $Total) * 100) } else { 0 }
    $status = "Scanning: $CurrentItem"
    Show-Progress -Activity "Threat Detection - $ScanType" -Status $status -PercentComplete $percent -SecondsRemaining 0
}
# ==================== UTILITY FUNCTIONS ====================
function Initialize-EventLog {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("EnterpriseThreatDetector")) {
            [System.Diagnostics.EventLog]::CreateEventSource("EnterpriseThreatDetector", "Application")
        }
    }
    catch {
        Write-Host "Warning: Could not create event log source." -ForegroundColor Yellow
    }
}
function Write-EventLogEntry {
    param([string]$Message, [string]$EntryType = "Information", [int]$EventId = 1000)
    try {
        Write-EventLog -LogName "Application" -Source "EnterpriseThreatDetector" -Message $Message -EntryType $EntryType -EventId $EventId
    }
    catch {
        Write-Log -Message "EventLog Failed: $Message" -Level "INFO"
    }
}
function Write-Log {
    param([string]$Message, [string]$Level = "INFO", [string]$ThreatType = "General")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [$ThreatType] $Message"
    Add-Content $logFile $logEntry -ErrorAction SilentlyContinue
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ALERT" { Write-Host $logEntry -ForegroundColor Red -BackgroundColor Black }
        "DETECTION" { Write-Host $logEntry -ForegroundColor Magenta }
        default { Write-Host $logEntry -ForegroundColor Green }
    }
    if ($Level -eq "ALERT" -or $Level -eq "ERROR") {
        $eventType = if ($Level -eq "ALERT") { "Warning" } else { "Error" }
        Write-EventLogEntry -Message $Message -EntryType $eventType
    }
}
function Check-Performance {
    $currentCPU = (Get-Process -Id $pid).CPU
    $currentMemory = (Get-Process -Id $pid).WorkingSet / 1MB
    $perfCounters["CPU Usage"] = $currentCPU
    $perfCounters["Memory Usage"] = $currentMemory
    $sleepTime = 45
    if ($currentCPU -gt 20 -or $currentMemory -gt 200) {
        $sleepTime = 120
        Write-Log -Message "High resource usage. Increasing interval to 120 seconds." -Level "WARNING"
    }
    # Log performance every 15 minutes
    if ((Get-Date).Minute % 15 -eq 0) {
        $threatSummary = ($perfCounters["Threats Detected"].GetEnumerator() | 
                        Where-Object { $_.Value -gt 0 } | 
                        ForEach-Object { "$($_.Key):$($_.Value)" }) -join ", "
        $perfMessage = "Performance: CPU: ${currentCPU}%, Memory: ${currentMemory}MB, Threats: [$threatSummary], Anomalies: $($perfCounters['Behavioral Anomalies'])"
        Write-Log -Message $perfMessage -Level "INFO"
    }
    return $sleepTime
}
function Load-ThreatIntelligence {
    $threatFeeds = @(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
        "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"
    )
    $feedCount = $threatFeeds.Count
    for ($i = 0; $i -lt $feedCount; $i++) {
        $feed = $threatFeeds[$i]
        Show-ScanProgress -ScanType "Threat Intelligence" -Current ($i + 1) -Total $feedCount -CurrentItem "Loading $feed"
        try {
            $feed = $feed.Trim()
            $content = Invoke-WebRequest -Uri $feed -UseBasicParsing -TimeoutSec 15
            $outputPath = "$threatIntelPath\$(($feed -split '/')[-1])"
            $content.Content | Out-File $outputPath
            Write-Log -Message "Loaded threat feed: $($feed)" -Level "INFO"
        }
        catch {
            $ex = $_.Exception
            $msg = $ex.Message
            Write-Log -Message "Failed to load threat feed $($feed): $msg" -Level "WARNING"
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Progress -Activity "Threat Intelligence" -Completed
}
function Resolve-DNSWithTimeout {
    param([string]$ip, [int]$timeoutMs = 1000)
    $job = Start-Job -ScriptBlock {
        param($ip)
        try {
            return [System.Net.Dns]::GetHostEntry($ip).HostName
        }
        catch {
            return "Unresolved"
        }
    } -ArgumentList $ip
    if (Wait-Job $job -Timeout ($timeoutMs / 1000)) {
        $domain = Receive-Job $job
        Remove-Job $job -Force
        return $domain
    }
    else {
        Remove-Job $job -Force
        return "Timeout"
    }
}
function Get-ProcessForensics {
    param([int]$ProcessId)
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $wmiProcess = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId"
        $parent = if ($wmiProcess) { $wmiProcess.ParentProcessId } else { $null }
        $commandLine = if ($wmiProcess) { $wmiProcess.CommandLine } else { $null }
        return @{
            ProcessName = $process.ProcessName
            ProcessId = $process.Id
            ParentProcessId = $parent
            CommandLine = $commandLine
            Path = $process.Path
            StartTime = $process.StartTime
            CPU = $process.CPU
            MemoryMB = ($process.WorkingSet / 1MB)
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        return @{ Error = $msg }
    }
}
function Block-IP {
    param($ip, $domain, $processId, $processName, $threatType)
    if ($whitelistedIPs -contains $ip) { return }
    $ruleName = "Block_$ip"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "Block_Inbound_$ip" -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
        Alert-Threat -ThreatType $threatType -Message "Blocked malicious connection: $processName (PID: $processId) -> $ip ($domain)" -Details @{
            IP = $ip
            Domain = $domain
            ProcessId = $processId
            ProcessName = $processName
        } -Severity "High"
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Failed to block IP $($ip): $msg" -Level "ERROR"
    }
}
# ==================== ENHANCEMENT: HASH DATABASE ====================
function Initialize-HashDatabase {
    if (Test-Path $hashDatabasePath) {
        # Fix for older PowerShell versions - remove -AsHashtable parameter
        $jsonContent = Get-Content $hashDatabasePath -Raw
        try {
            # Try to convert with AsHashtable first (PowerShell 6+)
            $global:hashDatabase = $jsonContent | ConvertFrom-Json -AsHashtable
        }
        catch {
            # Fallback for older PowerShell versions
            $jsonObj = $jsonContent | ConvertFrom-Json
            $global:hashDatabase = @{
                KnownMalicious = @{}
                KnownClean = @{}
                Suspicious = @{}
            }
            # Manually populate the hashtable structure
            if ($jsonObj.KnownMalicious) {
                $jsonObj.KnownMalicious.PSObject.Properties | ForEach-Object {
                    $global:hashDatabase.KnownMalicious[$_.Name] = $_.Value
                }
            }
            if ($jsonObj.KnownClean) {
                $jsonObj.KnownClean.PSObject.Properties | ForEach-Object {
                    $global:hashDatabase.KnownClean[$_.Name] = $_.Value
                }
            }
            if ($jsonObj.Suspicious) {
                $jsonObj.Suspicious.PSObject.Properties | ForEach-Object {
                    $global:hashDatabase.Suspicious[$_.Name] = $_.Value
                }
            }
        }
    }
    else {
        $global:hashDatabase = @{
            KnownMalicious = @{ }
            KnownClean = @{ }
            Suspicious = @{ }
        }
        $global:hashDatabase | ConvertTo-Json | Out-File $hashDatabasePath
    }
    Write-Log -Message "Hash database initialized with $($global:hashDatabase.KnownMalicious.Count) malicious hashes" -Level "INFO"
}
function Update-HashDatabase {
    param([string]$Hash, [string]$Status, [string]$FilePath, [string]$ThreatType)
    if (-not $global:hashDatabase.$Status.ContainsKey($Hash)) {
        $global:hashDatabase.$Status[$Hash] = @{
            FirstSeen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            LastSeen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            FilePaths = @($FilePath)
            ThreatType = $ThreatType
            Count = 1
        }
    }
    else {
        $global:hashDatabase.$Status[$Hash].LastSeen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $global:hashDatabase.$Status[$Hash].Count++
        if ($FilePath -notin $global:hashDatabase.$Status[$Hash].FilePaths) {
            $global:hashDatabase.$Status[$Hash].FilePaths += $FilePath
        }
    }
    $global:hashDatabase | ConvertTo-Json | Out-File $hashDatabasePath
}
# ==================== ENHANCEMENT: THREAT CACHE ====================
function Initialize-ThreatCache {
    if (Test-Path $threatCachePath) {
        # Fix for older PowerShell versions - remove -AsHashtable parameter
        $jsonContent = Get-Content $threatCachePath -Raw
        try {
            # Try to convert with AsHashtable first (PowerShell 6+)
            $global:threatCache = $jsonContent | ConvertFrom-Json -AsHashtable
        }
        catch {
            # Fallback for older PowerShell versions
            $jsonObj = $jsonContent | ConvertFrom-Json
            $global:threatCache = @{
                IPAddresses = @{ }
                Domains = @{ }
                FileHashes = @{ }
                ProcessNames = @{ }
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            # Manually populate the hashtable structure
            if ($jsonObj.IPAddresses) {
                $jsonObj.IPAddresses.PSObject.Properties | ForEach-Object {
                    $global:threatCache.IPAddresses[$_.Name] = $_.Value
                }
            }
            if ($jsonObj.Domains) {
                $jsonObj.Domains.PSObject.Properties | ForEach-Object {
                    $global:threatCache.Domains[$_.Name] = $_.Value
                }
            }
            if ($jsonObj.FileHashes) {
                $jsonObj.FileHashes.PSObject.Properties | ForEach-Object {
                    $global:threatCache.FileHashes[$_.Name] = $_.Value
                }
            }
            if ($jsonObj.ProcessNames) {
                $jsonObj.ProcessNames.PSObject.Properties | ForEach-Object {
                    $global:threatCache.ProcessNames[$_.Name] = $_.Value
                }
            }
        }
    }
    else {
        $global:threatCache = @{
            IPAddresses = @{ }
            Domains = @{ }
            FileHashes = @{ }
            ProcessNames = @{ }
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $global:threatCache | ConvertTo-Json | Out-File $threatCachePath
    }
    Write-Log -Message "Threat cache initialized" -Level "INFO"
}
# ==================== ENHANCEMENT: PROCESS TREE ANALYSIS ====================
function Get-ProcessTree {
    param([int]$ProcessId)
    $processTree = @{ }
    $process = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId"
    if ($process) {
        $processTree[$ProcessId] = @{
            Name = $process.Name
            ProcessId = $process.ProcessId
            ParentProcessId = $process.ParentProcessId
            CommandLine = $process.CommandLine
            Children = @()
        }
        # Get child processes
        $children = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ParentProcessId = $ProcessId"
        foreach ($child in $children) {
            $processTree[$ProcessId].Children += $child.ProcessId
            $childTree = Get-ProcessTree -ProcessId $child.ProcessId
            $processTree += $childTree
        }
    }
    return $processTree
}
function Analyze-ProcessChain {
    param([int]$ProcessId)
    $processChain = @()
    $currentPid = $ProcessId
    # Walk up the process chain
    while ($currentPid -ne $null -and $currentPid -ne 0) {
        $process = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $currentPid"
        if ($process) {
            $processChain += @{
                ProcessId = $currentPid
                Name = $process.Name
                CommandLine = $process.CommandLine
                ParentProcessId = $process.ParentProcessId
            }
            $currentPid = $process.ParentProcessId
        }
        else {
            break
        }
    }
    return $processChain
}
# ==================== ENHANCEMENT: REGISTRY THREAT DETECTION ====================
function Detect-RegistryThreats {
    $detections = @()
    $regCount = $suspiciousRegistryPaths.Count
    for ($i = 0; $i -lt $regCount; $i++) {
        $regPath = $suspiciousRegistryPaths[$i]
        Show-ScanProgress -ScanType "Registry" -Current ($i + 1) -Total $regCount -CurrentItem "Checking $regPath"
        if (Test-Path $regPath) {
            try {
                $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                foreach ($item in $items.PSObject.Properties) {
                    if ($item.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                        $value = $item.Value
                        foreach ($threatType in $malwareTypes.Keys) {
                            foreach ($pattern in $malwareTypes[$threatType]) {
                                if ($value -like $pattern) {
                                    $detections += @{
                                        Type = $threatType
                                        RegistryPath = $regPath
                                        RegistryValue = $value
                                        Severity = "High"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                $ex = $_.Exception
                $msg = $ex.Message
                Write-Log -Message "Error accessing registry path $($regPath): $msg" -Level "ERROR"
            }
        }
        Start-Sleep -Milliseconds 50
    }
    Write-Progress -Activity "Registry Scan" -Completed
    return $detections
}
# ==================== ENHANCEMENT: MEMORY ANALYSIS ====================
function Analyze-ProcessMemory {
    param([int]$ProcessId)
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $memoryStats = @{
            ProcessId = $ProcessId
            ProcessName = $process.ProcessName
            WorkingSetMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
            PrivateMemoryMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            VirtualMemoryMB = [math]::Round($process.VirtualMemorySize64 / 1MB, 2)
            Handles = $process.HandleCount
            Threads = $process.Threads.Count
            StartTime = $process.StartTime
        }
        # Check for memory anomalies
        if ($memoryStats.WorkingSetMB -gt 500 -and $process.ProcessName -notin @("chrome", "firefox", "msedge")) {
            $memoryStats.Anomaly = "HighMemoryUsage"
            $perfCounters["Behavioral Anomalies"]++
        }
        return $memoryStats
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        return @{ Error = $msg }
    }
}
# ==================== ENHANCEMENT: FILE CONTENT ANALYSIS ====================
function Analyze-FileContent {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    $suspiciousIndicators = @()
    $fileInfo = Get-Item $FilePath
    # Only analyze certain file types
    $analyzeExtensions = @('.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd')
    if ($fileInfo.Extension -notin $analyzeExtensions) { return $null }
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        if ($content.Length -gt 10MB) {
            # Skip very large files
            return @{ Warning = "File too large for content analysis" }
        }
        foreach ($pattern in $suspiciousContentPatterns) {
            if ($content -match $pattern) {
                $suspiciousIndicators += @{
                    Pattern = $pattern
                    Matches = $matches[0]
                }
            }
        }
        return @{
            FilePath = $FilePath
            SizeBytes = $fileInfo.Length
            SuspiciousIndicators = $suspiciousIndicators
            IndicatorCount = $suspiciousIndicators.Count
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        return @{ Error = $msg }
    }
}
# ==================== ENHANCEMENT: SECURE QUARANTINE ====================
function Secure-Quarantine {
    param([string]$FilePath, [string]$ThreatType)
    if (-not (Test-Path $FilePath)) { return $null }
    $fileInfo = Get-Item $FilePath
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $quarantineName = "$($fileInfo.BaseName)_$($ThreatType)_$timestamp$($fileInfo.Extension)"
    $quarantineFile = Join-Path $quarantinePath $quarantineName
    $zipFile = $quarantineFile + ".zip"
    try {
        # Get file hash and metadata
        $fileHash = Get-FileHash $FilePath -Algorithm SHA256
        $fileAnalysis = Analyze-FileContent $FilePath
        $memoryAnalysis = if ($fileInfo.Extension -eq '.exe') { 
            Analyze-ProcessMemory -ProcessId (Get-Process -Name $fileInfo.BaseName -ErrorAction SilentlyContinue | Select-Object -First 1).Id 
        } else { $null }
        # Create quarantine package
        $quarantineData = @{
            OriginalPath = $FilePath
            QuarantinePath = $zipFile
            FileName = $fileInfo.Name
            FileSize = $fileInfo.Length
            FileHash = $fileHash.Hash
            QuarantineTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ThreatType = $ThreatType
            FileAnalysis = $fileAnalysis
            MemoryAnalysis = $memoryAnalysis
        }
        # Compress file with metadata
        $metadataFile = Join-Path $quarantinePath "metadata_$timestamp.json"
        $quarantineData | ConvertTo-Json -Depth 5 | Out-File $metadataFile
        # Create compressed quarantine package
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            (Split-Path $metadataFile),
            $zipFile,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )
        # Remove original file and metadata
        Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
        Remove-Item $metadataFile -Force -ErrorAction SilentlyContinue
        # Update hash database
        Update-HashDatabase -Hash $fileHash.Hash -Status "KnownMalicious" -FilePath $FilePath -ThreatType $ThreatType
        Write-Log -Message "Securely quarantined file: $FilePath -> $zipFile" -Level "INFO" -ThreatType $ThreatType
        return $quarantineData
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Failed to quarantine file $($FilePath): $msg" -Level "ERROR"
        return $null
    }
}
# ==================== ENHANCEMENT: ADVANCED PERSISTENCE DETECTION ====================
function Detect-AdvancedPersistence {
    $detections = @()
    # Check WMI event subscriptions
    try {
        $wmiEvents = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        foreach ($event in $wmiEvents) {
            $query = $event.Query
            if ($query -match ($suspiciousContentPatterns -join '|')) {
                $detections += @{
                    Type = "Persistence"
                    Technique = "WMI Event Subscription"
                    Query = $query
                    Severity = "High"
                }
            }
        }
    }
    catch { }
    # Check startup folders
    $startupFolders = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $folderCount = $startupFolders.Count
    for ($i = 0; $i -lt $folderCount; $i++) {
        $folder = $startupFolders[$i]
        Show-ScanProgress -ScanType "Persistence" -Current ($i + 1) -Total $folderCount -CurrentItem "Checking $folder"
        if (Test-Path $folder) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $contentAnalysis = Analyze-FileContent $_.FullName
                if ($contentAnalysis.IndicatorCount -gt 0) {
                    $detections += @{
                        Type = "Persistence"
                        Technique = "Startup Folder"
                        FilePath = $_.FullName
                        Analysis = $contentAnalysis
                        Severity = "Medium"
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    Write-Progress -Activity "Persistence Scan" -Completed
    return $detections
}
# ==================== ENHANCED NETWORK ANALYSIS ====================
function Analyze-NetworkPatterns {
    param([object]$Connection)
    $analysis = @{
        Connection = $Connection
        Protocol = $Connection.Protocol
        Direction = if ($Connection.RemoteAddress -match "^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") { "Internal" } else { "External" }
        PortCategory = switch ($Connection.RemotePort) {
            { $_ -in @(22, 23, 25, 53, 80, 110, 143, 443, 993, 995) } { "Standard" }
            { $_ -in @(3389, 5900, 5901) } { "Remote Access" }
            { $_ -in @(4444, 5555, 6666, 7777, 8888, 9999) } { "Suspicious" }
            default { "Other" }
        }
        DataRate = if ($Connection.BytesSent -or $Connection.BytesReceived) {
            [Math]::Round(($Connection.BytesSent + $Connection.BytesReceived) / 1024, 2) # KB/s
        } else { 0 }
    }
    return $analysis
}
# ==================== ADVANCED FILE REPUTATION ====================
function Check-FileReputation {
    param([string]$FilePath)
    $fileHash = Get-FileHash $FilePath -Algorithm SHA256
    $hash = $fileHash.Hash
    # Check local hash database first
    if ($global:hashDatabase.KnownMalicious.ContainsKey($hash)) {
        return @{
            Status = "Malicious"
            Confidence = 1.0
            Source = "Local Database"
            Details = $global:hashDatabase.KnownMalicious[$hash]
        }
    }
    # Check if in threat cache
    if ($global:threatCache.FileHashes.ContainsKey($hash)) {
        return @{
            Status = "Suspicious"
            Confidence = 0.8
            Source = "Threat Cache"
            Details = $global:threatCache.FileHashes[$hash]
        }
    }
    # Default to clean if not found in databases
    return @{
        Status = "Clean"
        Confidence = 0.9
        Source = "Local Analysis"
    }
}
# ==================== THREAT HUNTING ENGINE ====================
function Hunt-Threats {
    $hunts = @()
    # Hunt for hidden processes
    Show-Progress -Activity "Threat Hunting" -Status "Scanning for hidden processes" -PercentComplete 25
    $hiddenProcesses = Get-Process | Where-Object {
        $_.MainWindowTitle -eq "" -and 
        $_.ProcessName -notlike "*explorer*" -and
        $_.ProcessName -notlike "*svchost*" -and
        $_.ProcessName -notlike "*services*"
    }
    foreach ($proc in $hiddenProcesses) {
        $hunts += @{
            Type = "HiddenProcess"
            ProcessName = $proc.ProcessName
            ProcessId = $proc.Id
            Path = $proc.Path
            Risk = "Medium"
        }
    }
    # Hunt for unusual network patterns
    Show-Progress -Activity "Threat Hunting" -Status "Scanning network connections" -PercentComplete 75
    $unusualConnections = Get-NetTCPConnection | Where-Object {
        $_.State -eq "Established" -and
        $_.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999) -and
        $_.RemoteAddress -notmatch "^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\."
    }
    foreach ($conn in $unusualConnections) {
        $hunts += @{
            Type = "UnusualConnection"
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            ProcessId = $conn.OwningProcess
            Risk = "High"
        }
    }
    Write-Progress -Activity "Threat Hunting" -Completed
    return $hunts
}
# ==================== AUTOMATED RESPONSE SYSTEM ====================
function Execute-AutomatedResponse {
    param(
        [string]$ThreatType,
        [string]$Action,
        [object]$Details
    )
    switch ($Action) {
        "Quarantine" {
            if ($Details.FilePath) {
                Secure-Quarantine -FilePath $Details.FilePath -ThreatType $ThreatType
            }
        }
        "BlockNetwork" {
            if ($Details.IP) {
                Block-IP -ip $Details.IP -domain $Details.Domain -processId $Details.ProcessId -processName $Details.ProcessName -threatType $ThreatType
            }
        }
        "TerminateProcess" {
            if ($Details.ProcessId) {
                try {
                    Stop-Process -Id $Details.ProcessId -Force -ErrorAction SilentlyContinue
                    Write-Log -Message "Automatically terminated process: $($Details.ProcessName) (PID: $($Details.ProcessId))" -Level "ALERT" -ThreatType $ThreatType
                }
                catch {
                    $ex = $_.Exception
                    $msg = $ex.Message
                    Write-Log -Message "Failed to terminate process: $msg" -Level "ERROR"
                }
            }
        }
        "LogOnly" {
            $detailsJson = ConvertTo-Json $Details -Compress
            Write-Log -Message "Automated response logged: $ThreatType detected with details: $detailsJson" -Level "INFO" -ThreatType $ThreatType
        }
    }
}
# ==================== STRUCTURED LOGGING ====================
function Write-StructuredLog {
    param(
        [string]$ThreatType,
        [string]$Action,
        [string]$Message,
        [object]$Details,
        [string]$Severity = "INFO"
    )
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ThreatType = $ThreatType
        Action = $Action
        Message = $Message
        Details = $Details
        Severity = $Severity
        ComputerName = $env:COMPUTERNAME
        ProcessId = $PID
    }
    $logEntry | ConvertTo-Json | Out-File -FilePath $logFile -Append
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Severity] [$ThreatType] $Message" -ForegroundColor ([System.ConsoleColor]::Green)
}
# ==================== THREAT CORRELATION ENGINE ====================
function Correlate-Threats {
    param([array]$Detections)
    $correlations = @()
    
    # Look for patterns across detections
    # Filter out detections that don't have ProcessId or Type properties
    $validDetections = $Detections | Where-Object { $_ -and $_.ProcessId -and $_.Type }
    
    if ($validDetections.Count -gt 0) {
        # Group by ProcessId to find processes involved in multiple threats
        $processGroups = $validDetections | Group-Object ProcessId | Where-Object { $_.Count -gt 1 }
        foreach ($group in $processGroups) {
            # Extract unique threat types from this process group
            $threatTypes = $group.Group | Where-Object { $_.Type } | ForEach-Object { $_.Type } | Sort-Object -Unique
            
            $correlations += @{
                Type = "ProcessCorrelation"
                ProcessId = $group.Name
                ThreatCount = $group.Count
                ThreatTypes = $threatTypes
                RiskLevel = "High"
            }
        }
    }
    
    # Look for temporal patterns (group by date/time if available)
    # Note: This requires detections to have TimeStamp properties
    $temporalGroups = $Detections | Where-Object { $_.TimeStamp } | Group-Object TimeStamp | Where-Object { $_.Count -gt 3 }
    foreach ($pattern in $temporalGroups) {
        $correlations += @{
            Type = "TemporalPattern"
            TimeWindow = $pattern.Name
            DetectionCount = $pattern.Count
            RiskLevel = "Medium"
        }
    }
    
    return $correlations
}
# ==================== DASHBOARD GENERATION ====================
function Generate-Dashboard {
    $dashboardPath = "$threatIntelPath\dashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $threatStats = $perfCounters["Threats Detected"] | ForEach-Object {
        "<tr><td>$($_.Key)</td><td>$($_.Value)</td></tr>"
    } -join "`n"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Threat Detection Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .metric { font-size: 2em; font-weight: bold; }
        .threat-table { width: 100%; border-collapse: collapse; }
        .threat-table th, .threat-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .threat-table th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Threat Detection Dashboard</h1>
    <p>Created by: Str1k3r0p</p>
    <div class="dashboard">
        <div class="card">
            <h3>Performance Metrics</h3>
            <p>CPU: $($perfCounters["CPU Usage"] | ForEach-Object { [Math]::Round($_, 2) })%</p>
            <p>Memory: $($perfCounters["Memory Usage"] | ForEach-Object { [Math]::Round($_, 2) })MB</p>
        </div>
        <div class="card">
            <h3>Threat Statistics</h3>
            <table class="threat-table">
                <tr><th>Threat Type</th><th>Detections</th></tr>
                $threatStats
            </table>
        </div>
        <div class="card">
            <h3>Recent Activity</h3>
            <pre>$(Get-Content $logFile -Tail 20)</pre>
        </div>
    </div>
</body>
</html>
"@
    $html | Out-File $dashboardPath
    Write-Log -Message "Dashboard generated: $dashboardPath" -Level "INFO"
}
# ==================== CONFIGURATION MANAGEMENT ====================
function Initialize-Configuration {
    if (Test-Path $configPath) {
        # Fix for older PowerShell versions - remove -AsHashtable parameter
        $jsonContent = Get-Content $configPath -Raw
        try {
            # Try to convert with AsHashtable first (PowerShell 6+)
            $global:config = $jsonContent | ConvertFrom-Json -AsHashtable
        }
        catch {
            # Fallback for older PowerShell versions
            $global:config = $jsonContent | ConvertFrom-Json
        }
    }
    else {
        # Create default configuration
        $global:config = @{
            ScanInterval = 45
            MaxFileSize = 10MB
            EnableLogging = $true
            EnableAlerts = $true
            EnableQuarantine = $true
            SuspiciousThreshold = 70
            Whitelist = @(
                "8.8.8.8",
                "1.1.1.1"
            )
        }
        $global:config | ConvertTo-Json | Out-File $configPath
    }
    Write-Log -Message "Configuration loaded" -Level "INFO"
}
function Load-Configuration {
    if (Test-Path $configPath) {
        # Fix for older PowerShell versions - remove -AsHashtable parameter
        $jsonContent = Get-Content $configPath -Raw
        try {
            # Try to convert with AsHashtable first (PowerShell 6+)
            $global:config = $jsonContent | ConvertFrom-Json -AsHashtable
        }
        catch {
            # Fallback for older PowerShell versions
            $global:config = $jsonContent | ConvertFrom-Json
        }
        return $global:config
    }
    else {
        Initialize-Configuration
        return $global:config
    }
}
# ==================== ENHANCED PROCESS DETECTION ====================
function Get-SuspiciousProcesses {
    $detections = @()
    Show-Progress -Activity "Process Analysis" -Status "Querying WMI for suspicious processes" -PercentComplete 50
    # Use simpler WMI queries to avoid syntax issues
    try {
        # Check for miner processes
        $minerProcesses = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%miner%' OR Name LIKE '%xmrig%'" -ErrorAction SilentlyContinue
        foreach ($proc in $minerProcesses) {
            $detections += @{
                Type = "Cryptominer"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "High"
            }
        }
        # Check for suspicious command line patterns
        $suspiciousProcesses = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '% -e %' OR CommandLine LIKE '%reverse%'" -ErrorAction SilentlyContinue
        foreach ($proc in $suspiciousProcesses) {
            $detections += @{
                Type = "Trojan"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "High"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error querying WMI for processes: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Process Analysis" -Completed
    return $detections
}
# ==================== MODULAR THREAT DETECTION FUNCTIONS ====================
function Detect-Cryptominer {
    $detections = @()
    Show-Progress -Activity "Cryptominer Detection" -Status "Scanning for mining processes" -PercentComplete 50
    # Simplified WMI query
    try {
        $processes = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%miner%' OR Name LIKE '%xmrig%' OR CommandLine LIKE '%pool%'" -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $detections += @{
                Type = "Cryptominer"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "High"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error in cryptominer detection: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Cryptominer Detection" -Completed
    return $detections
}
function Detect-Ransomware {
    $detections = @()
    Show-Progress -Activity "Ransomware Detection" -Status "Scanning for encryption processes" -PercentComplete 33
    # Check for encryption-related processes
    try {
        $processes = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%ransom%' OR Name LIKE '%encrypt%'" -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $detections += @{
                Type = "Ransomware"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "Critical"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error in ransomware detection: $msg" -Level "ERROR"
    }
    Show-Progress -Activity "Ransomware Detection" -Status "Checking for encrypted files" -PercentComplete 66
    # Check for encrypted file extensions
    try {
        $encryptedFiles = Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Extension -in @('.locked', '.encrypted', '.crypt') } |
                         Select-Object -First 5
        if ($encryptedFiles) {
            $detections += @{
                Type = "Ransomware"
                Files = $encryptedFiles.Count
                Extensions = ($encryptedFiles.Extension | Select-Object -Unique)
                Severity = "Critical"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error checking for encrypted files: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Ransomware Detection" -Completed
    return $detections
}
function Detect-Trojan {
    $detections = @()
    Show-Progress -Activity "Trojan Detection" -Status "Scanning for suspicious command lines" -PercentComplete 50
    # Simplified WMI query
    try {
        $processes = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '% -e %' OR CommandLine LIKE '%reverse%' OR CommandLine LIKE '%bind%'" -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $detections += @{
                Type = "Trojan"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "High"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error in trojan detection: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Trojan Detection" -Completed
    return $detections
}
function Detect-Botnet {
    $detections = @()
    Show-Progress -Activity "Botnet Detection" -Status "Analyzing network connections" -PercentComplete 50
    # Check for C2 communication patterns
    try {
        $connections = Get-NetTCPConnection | Where-Object {
            $_.State -eq "Established" -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::"
        }
        $connCount = $connections.Count
        $currentConn = 0
        foreach ($conn in $connections) {
            $currentConn++
            Show-ScanProgress -ScanType "Botnet" -Current $currentConn -Total $connCount -CurrentItem "Checking connection to $($conn.RemoteAddress)"
            $remoteIP = $conn.RemoteAddress
            $domain = Resolve-DNSWithTimeout $remoteIP
            # Check for suspicious domains and TLDs
            $isSuspicious = $suspiciousDomains | Where-Object { $domain -like $_ } -or
                           $suspiciousTLDs | Where-Object { $domain -like "*$_" } -or
                           $suspiciousIPRanges | Where-Object { $remoteIP -like "$_*" }
            if ($isSuspicious) {
                $detections += @{
                    Type = "Botnet"
                    RemoteIP = $remoteIP
                    Domain = $domain
                    ProcessId = $conn.OwningProcess
                    Severity = "High"
                }
            }
            Start-Sleep -Milliseconds 10
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error in botnet detection: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Botnet Detection" -Completed
    return $detections
}
function Detect-Spyware {
    $detections = @()
    Show-Progress -Activity "Spyware Detection" -Status "Scanning for keyloggers and spyware" -PercentComplete 50
    # Simplified WMI query
    try {
        $processes = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name LIKE '%keylog%' OR Name LIKE '%spy%' OR CommandLine LIKE '%steal%'" -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $detections += @{
                Type = "Spyware"
                ProcessName = $proc.Name
                ProcessId = $proc.ProcessId
                CommandLine = $proc.CommandLine
                Severity = "Medium"
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error in spyware detection: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Spyware Detection" -Completed
    return $detections
}
# ==================== BEHAVIORAL ANALYSIS ====================
function Detect-BehavioralAnomalies {
    $anomalies = @()
    Show-Progress -Activity "Behavioral Analysis" -Status "Analyzing process chains" -PercentComplete 33
    # Check for unusual process chains
    $suspiciousProcesses = Get-Process | Where-Object { $_.ProcessName -in @('cmd', 'powershell', 'wscript', 'cscript') }
    $procCount = $suspiciousProcesses.Count
    $currentProc = 0
    foreach ($proc in $suspiciousProcesses) {
        $currentProc++
        Show-ScanProgress -ScanType "Behavioral" -Current $currentProc -Total $procCount -CurrentItem "Analyzing $($proc.ProcessName)"
        $processChain = Analyze-ProcessChain $proc.Id
        if ($processChain.Count -gt 3) {
            # Long process chain might indicate exploitation
            $anomalies += @{
                Type = "Behavioral"
                Anomaly = "LongProcessChain"
                ProcessId = $proc.Id
                ProcessName = $proc.ProcessName
                ChainLength = $processChain.Count
                Severity = "Medium"
            }
        }
        Start-Sleep -Milliseconds 50
    }
    Show-Progress -Activity "Behavioral Analysis" -Status "Checking network connections" -PercentComplete 66
    # Check for unusual network connections
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999)) {
                $anomalies += @{
                    Type = "Behavioral"
                    Anomaly = "SuspiciousPort"
                    ProcessId = $conn.OwningProcess
                    RemotePort = $conn.RemotePort
                    RemoteAddress = $conn.RemoteAddress
                    Severity = "High"
                }
            }
        }
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Error analyzing network connections: $msg" -Level "ERROR"
    }
    Write-Progress -Activity "Behavioral Analysis" -Completed
    return $anomalies
}
# ==================== AI-POWERED THREAT SCORING ====================
function Calculate-ThreatScore {
    param(
        [object]$Detection,
        [object]$ProcessInfo,
        [object]$FileAnalysis,
        [object]$MemoryAnalysis
    )
    $score = 0
    $confidence = 0
    # Base scoring from detection type
    switch ($Detection.Type) {
        "Cryptominer" { $score += 80; $confidence += 0.8 }
        "Ransomware" { $score += 95; $confidence += 0.9 }
        "Trojan" { $score += 75; $confidence += 0.7 }
        "Botnet" { $score += 70; $confidence += 0.6 }
        "Spyware" { $score += 60; $confidence += 0.5 }
        "Downloader" { $score += 65; $confidence += 0.6 }
        "Persistence" { $score += 70; $confidence += 0.7 }
        default { $score += 50; $confidence += 0.4 }
    }
    # Behavioral anomalies boost score
    if ($ProcessInfo -and $ProcessInfo.CommandLine -match "base64|powershell.*-enc") {
        $score += 15
        $confidence += 0.2
    }
    # File analysis impacts
    if ($FileAnalysis -and $FileAnalysis.IndicatorCount -gt 0) {
        $score += $FileAnalysis.IndicatorCount * 5
        $confidence += $FileAnalysis.IndicatorCount * 0.1
    }
    # Memory anomalies
    if ($MemoryAnalysis -and $MemoryAnalysis.Anomaly) {
        $score += 20
        $confidence += 0.3
    }
    # Normalize score
    $score = [Math]::Min($score, 100)
    $confidence = [Math]::Min($confidence, 1.0)
    return @{
        Score = $score
        Confidence = [Math]::Round($confidence, 2)
        RiskLevel = switch ($score) {
            { $_ -ge 90 } { "Critical" }
            { $_ -ge 75 } { "High" }
            { $_ -ge 60 } { "Medium" }
            { $_ -ge 40 } { "Low" }
            default { "Informational" }
        }
    }
}
# ==================== REAL-TIME THREAT INTELLIGENCE WITH DAILY MALICIOUS DNS ====================
function Update-DailyMaliciousDNS {
    # This function downloads and updates daily malicious DNS records
    try {
        Show-Progress -Activity "DNS Update" -Status "Downloading malicious DNS list" -PercentComplete 50
        $dnsFeed = "https://raw.githubusercontent.com/Str1k3r0p/malicious-dns-list/main/daily_malicious_dns.txt"
        $content = Invoke-WebRequest -Uri $dnsFeed -UseBasicParsing -TimeoutSec 15
        # Save to local file
        $dnsFilePath = "$threatIntelPath\daily_malicious_dns.txt"
        $content.Content | Out-File $dnsFilePath
        # Parse and add to threat cache
        $maliciousDNS = $content.Content -split "`n" | Where-Object { $_ -and $_ -notmatch "^#" }
        Show-Progress -Activity "DNS Update" -Status "Processing DNS entries" -PercentComplete 75
        $dnsCount = $maliciousDNS.Count
        $currentDns = 0
        foreach ($dns in $maliciousDNS) {
            $currentDns++
            $dns = $dns.Trim()
            if ($dns -and $dns -notmatch "^\s*$") {
                Update-ThreatCache -Type "Domains" -Value $dns -ThreatType "MaliciousDNS" -Details @{
                    Source = "DailyMaliciousDNS"
                    AddedDate = Get-Date
                }
            }
        }
        Write-Log -Message "Updated daily malicious DNS records: $($maliciousDNS.Count) entries loaded" -Level "INFO"
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        Write-Log -Message "Failed to update daily malicious DNS: $msg" -Level "WARNING"
    }
    finally {
        Write-Progress -Activity "DNS Update" -Completed
    }
}
function Update-ThreatIntelligenceRealtime {
    # Auto-update from multiple sources every hour
    $sources = @{
        "VirusTotal" = "https://www.virustotal.com/api/v3/intelligence/feeds"
        "AbuseIPDB" = "https://api.abuseipdb.com/api/v2/check"
        "MISP" = "https://misp.example.com/feeds"
        "Custom" = "https://your-custom-feed.com/threats.json"
    }
    $sourceCount = $sources.Count
    $currentSource = 0
    foreach ($sourceName in $sources.Keys) {
        $currentSource++
        Show-ScanProgress -ScanType "Threat Intel" -Current $currentSource -Total $sourceCount -CurrentItem "Updating $sourceName"
        try {
            $data = Invoke-RestMethod -Uri $sources[$sourceName] -TimeoutSec 10
            # Process and store in threat cache
            $data | ConvertTo-Json | Out-File "$threatIntelPath\$sourceName.json"
            Write-Log -Message "Updated threat intelligence from $($sourceName)" -Level "INFO"
        }
        catch {
            $ex = $_.Exception
            $msg = $ex.Message
            Write-Log -Message "Failed to update $($sourceName): $msg" -Level "WARNING"
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Progress -Activity "Threat Intelligence" -Completed
}
# ==================== DEEP MEMORY ANALYSIS ====================
function Detect-ProcessInjection {
    param([int]$ProcessId)
    $injections = @()
    # Check for suspicious memory access patterns
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $modules = $process.Modules
        foreach ($module in $modules) {
            # Look for modules loaded from unusual paths
            if ($module.FileName -and $module.FileName -match "Temp|AppData") {
                $injections += @{
                    Module = $module.ModuleName
                    Path = $module.FileName
                    SuspiciousLocation = $true
                }
            }
        }
    }
    catch {
        # Handle process access issues gracefully
    }
    return $injections
}
function Analyze-ProcessMemoryRegions {
    param([int]$ProcessId)
    # Advanced memory region analysis
    $regions = @()
    # This would require more advanced techniques or external tools
    # For now, basic analysis of memory usage patterns
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $memInfo = @{
            ProcessId = $ProcessId
            WorkingSet = $process.WorkingSet64
            PrivateMemory = $process.PrivateMemorySize64
            VirtualMemory = $process.VirtualMemorySize64
            PeakWorkingSet = $process.PeakWorkingSet64
        }
        # Detect memory pressure patterns
        if ($memInfo.WorkingSet -gt 1GB) {
            $memInfo.HighMemoryUsage = $true
        }
        return $memInfo
    }
    catch {
        $ex = $_.Exception
        $msg = $ex.Message
        return @{ Error = $msg }
    }
}
# ==================== COMPREHENSIVE REPORTING ====================
function Generate-ComprehensiveReport {
    $reportDate = Get-Date -Format "yyyyMMdd_HHmmss"
    $htmlReportPath = "$threatIntelPath\Threat_Report_$reportDate.html"
    $jsonReportPath = "$threatIntelPath\Threat_Report_$reportDate.json"
    Show-Progress -Activity "Report Generation" -Status "Collecting system information" -PercentComplete 25
    # Collect report data
    $reportData = @{
        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SystemInfo = Get-SystemInfo
        ThreatSummary = $perfCounters["Threats Detected"]
        RecentDetections = Get-Content $logFile -Tail 100 -ErrorAction SilentlyContinue
        HashDatabaseStats = @{
            MaliciousHashes = $global:hashDatabase.KnownMalicious.Count
            CleanHashes = $global:hashDatabase.KnownClean.Count
            SuspiciousHashes = $global:hashDatabase.Suspicious.Count
        }
        ThreatCacheStats = @{
            CachedIPs = $global:threatCache.IPAddresses.Count
            CachedDomains = $global:threatCache.Domains.Count
            CachedHashes = $global:threatCache.FileHashes.Count
        }
        PerformanceMetrics = $perfCounters
    }
    Show-Progress -Activity "Report Generation" -Status "Generating JSON report" -PercentComplete 50
    # Generate JSON report
    $reportData | ConvertTo-Json -Depth 5 | Out-File $jsonReportPath
    Show-Progress -Activity "Report Generation" -Status "Generating HTML report" -PercentComplete 75
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Threat Detection Report - $($reportData.ReportDate)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .threat-table { width: 100%; border-collapse: collapse; }
        .threat-table th, .threat-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .threat-table th { background-color: #f2f2f2; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffe6cc; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #e6ffcc; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Threat Detection Report</h1>
        <p>Generated: $($reportData.ReportDate)</p>
        <p>Created by: Str1k3r0p</p>
    </div>
    <div class="section">
        <h2>System Information</h2>
        <pre>$($reportData.SystemInfo | ConvertTo-Json)</pre>
    </div>
    <div class="section">
        <h2>Threat Summary</h2>
        <table class="threat-table">
            <tr><th>Threat Type</th><th>Detections</th></tr>
            $(($reportData.ThreatSummary.GetEnumerator() | ForEach-Object {
                "<tr><td>$($_.Key)</td><td>$($_.Value)</td></tr>"
            }) -join "`n")
        </table>
    </div>
    <div class="section">
        <h2>Performance Metrics</h2>
        <pre>$($reportData.PerformanceMetrics | ConvertTo-Json)</pre>
    </div>
</body>
</html>
"@
    $htmlReport | Out-File $htmlReportPath
    Write-Log -Message "Comprehensive report generated: $htmlReportPath" -Level "INFO"
    Write-Progress -Activity "Report Generation" -Completed
    return @{ HtmlReport = $htmlReportPath; JsonReport = $jsonReportPath }
}
function Get-SystemInfo {
    $uptimeDays = [math]::Round((Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)).TotalDays
    return @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
        TotalMemoryGB = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        Processor = (Get-WmiObject Win32_Processor).Name
        UptimeDays = $uptimeDays
    }
}
# ==================== MAIN DETECTION LOGIC ====================
function Detect-AllThreats {
    $allDetections = @()
    Show-Progress -Activity "Threat Detection" -Status "Starting comprehensive scan" -PercentComplete 10
    # Basic threat detection
    $allDetections += Detect-Cryptominer
    Show-Progress -Activity "Threat Detection" -Status "Scanning for ransomware" -PercentComplete 20
    $allDetections += Detect-Ransomware
    Show-Progress -Activity "Threat Detection" -Status "Scanning for trojans" -PercentComplete 30
    $allDetections += Detect-Trojan
    Show-Progress -Activity "Threat Detection" -Status "Scanning for botnets" -PercentComplete 40
    $allDetections += Detect-Botnet
    Show-Progress -Activity "Threat Detection" -Status "Scanning for spyware" -PercentComplete 50
    $allDetections += Detect-Spyware
    # Enhanced detection modules
    Show-Progress -Activity "Threat Detection" -Status "Checking registry" -PercentComplete 60
    $allDetections += Detect-RegistryThreats
    Show-Progress -Activity "Threat Detection" -Status "Checking persistence" -PercentComplete 70
    $allDetections += Detect-AdvancedPersistence
    Show-Progress -Activity "Threat Detection" -Status "Analyzing behavior" -PercentComplete 80
    $allDetections += Detect-BehavioralAnomalies
    # Process analysis
    Show-Progress -Activity "Threat Detection" -Status "Analyzing processes" -PercentComplete 90
    $allDetections += Get-SuspiciousProcesses
    Write-Progress -Activity "Threat Detection" -Completed
    return $allDetections
}
# ==================== ALERT SYSTEM ====================
function Alert-Threat {
    param(
        [string]$ThreatType,
        [string]$Message,
        [object]$Details,
        [string]$Severity = "Medium"
    )
    $perfCounters["Alerts Triggered"]++
    $perfCounters["Threats Detected"][$ThreatType]++
    # Calculate threat score
    $threatScore = Calculate-ThreatScore -Detection @{Type = $ThreatType} -ProcessInfo $Details -FileAnalysis $null -MemoryAnalysis $null
    $fullMessage = "[$ThreatType - $Severity - Score: $($threatScore.Score)%] $Message"
    if ($Details) {
        $fullMessage += " Details: $(ConvertTo-Json $Details -Compress)"
    }
    Write-Log -Message $fullMessage -Level "ALERT" -ThreatType $ThreatType
    # Only show popups during active hours
    $currentHour = (Get-Date).Hour
    if ($currentHour -ge 8 -and $currentHour -le 22 -and $Severity -in @("High", "Critical")) {
        try {
            $result = [System.Windows.MessageBox]::Show(
                "$fullMessage`n`nTake action?",
                "Threat Detected: $ThreatType",
                'YesNo',
                'Warning'
            )
            if ($result -eq 'Yes' -and $Details.ProcessId) {
                Stop-Process -Id $Details.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Terminated process: $($Details.ProcessName) (PID: $($Details.ProcessId))" -Level "ALERT" -ThreatType $ThreatType
            }
        }
        catch {
            $ex = $_.Exception
            $msg = $ex.Message
            Write-Log -Message "Failed to show alert dialog: $msg" -Level "ERROR"
        }
    }
}
# ==================== MAIN EXECUTION ====================
try {
    Initialize-EventLog
    Initialize-HashDatabase
    Initialize-ThreatCache
    Initialize-Configuration
    Write-Log -Message "Enterprise Advanced Threat Detector service started" -Level "INFO"
    Write-EventLogEntry -Message "Threat Detector service started" -EntryType "Information"
    # Load threat intelligence
    Load-ThreatIntelligence
    # Initialize daily malicious DNS update
    Update-DailyMaliciousDNS
    $checkCount = 0
    while ($true) {
        $checkCount++
        Write-Log -Message "Starting comprehensive threat scan #$checkCount" -Level "INFO"
        # Detect all threat types
        $detections = Detect-AllThreats
        # Process detections with correlation
        $correlations = Correlate-Threats -Detections $detections
        foreach ($detection in $detections) {
            if ($detection) {
                # Calculate threat score
                $threatScore = Calculate-ThreatScore -Detection $detection -ProcessInfo $null -FileAnalysis $null -MemoryAnalysis $null
                Alert-Threat -ThreatType $detection.Type -Message "Threat detected: $($detection.ProcessName)" -Details $detection -Severity $detection.Severity
                # Take automatic action for critical threats
                if ($detection.Severity -eq "Critical" -and $detection.ProcessId) {
                    try {
                        Stop-Process -Id $detection.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "Auto-terminated critical threat: $($detection.ProcessName) (PID: $($detection.ProcessId))" -Level "ALERT" -ThreatType $detection.Type
                    }
                    catch {
                        $ex = $_.Exception
                        $msg = $ex.Message
                        Write-Log -Message "Failed to terminate process: $msg" -Level "ERROR"
                    }
                }
            }
        }
        # Perform threat hunting
        $hunts = Hunt-Threats
        foreach ($hunt in $hunts) {
            Write-Log -Message "Hunt detected: $($hunt.Type) - $($hunt.Risk) risk" -Level "WARNING" -ThreatType $hunt.Type
        }
        # Performance monitoring and adaptive sleep
        $sleepTime = Check-Performance
        Write-Log -Message "Scan #$checkCount completed. Detections: $($detections.Count). Hunting: $($hunts.Count). Sleeping for $sleepTime seconds." -Level "INFO"
        # Generate comprehensive report every 10 scans
        if ($checkCount % 10 -eq 0) {
            Generate-ComprehensiveReport
            Generate-Dashboard
            # Update threat intelligence cache
            Load-ThreatIntelligence
            # Update daily malicious DNS records
            Update-DailyMaliciousDNS
        }
        Start-Sleep -Seconds $sleepTime
    }
}
catch {
    $ex = $_.Exception
    $msg = $ex.Message
    $errorMsg = "Fatal error: $msg"
    Write-Log -Message $errorMsg -Level "ERROR"
    Write-EventLogEntry -Message $errorMsg -EntryType "Error"
    Start-Sleep -Seconds 60
}
