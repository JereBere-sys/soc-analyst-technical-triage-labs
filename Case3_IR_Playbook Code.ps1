# Case 3 - checking DESKTOP-5NLV63K for the C2 IPs found in the Case 2 pcap

# Phase 1
$C2_IPs = @(
    "172.64.155.76",
    "146.59.71.167",
    "38.182.168.246",
    "45.130.41.161",
    "172.67.162.153",
    "121.54.163.148"
)

Write-Host "Checking live connections against known C2 IPs..."

$activeConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$maliciousConnections = $activeConnections | Where-Object { $C2_IPs -contains $_.RemoteAddress }

if ($maliciousConnections) {
    Write-Host "Match found - active connection to a known C2 IP." -ForegroundColor Red

    $DetectionResults = foreach ($conn in $maliciousConnections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            RemoteIP    = $conn.RemoteAddress
            RemotePort  = $conn.RemotePort
            LocalPort   = $conn.LocalPort
            State       = $conn.State
            PID         = $conn.OwningProcess
            ProcessName = $proc.ProcessName
            ProcessPath = $proc.Path
        }
    }

    $DetectionResults | Format-Table -AutoSize

} else {
    Write-Host "No matches right now - clean baseline." -ForegroundColor Yellow
}

# Phase 2 - block the 6 C2 IPs outbound
 
$confirm = Read-Host "Type yes to add firewall block rules for the 6 C2 IPs"
 
if ($confirm -eq "yes") {
    foreach ($ip in $C2_IPs) {
        New-NetFirewallRule -DisplayName "Block-C2-$ip" -Direction Outbound -RemoteAddress $ip -Action Block | Out-Null
        Write-Host "Blocked $ip"
    }
} else {
    Write-Host "Skipped - no firewall rules added." -ForegroundColor Yellow
}
# Phase 3 - Investigate
 
Write-Host "`nChecking registry Run keys..."
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
 
if ($DetectionResults) {
    Write-Host "`nHashing flagged process..."
    foreach ($item in $DetectionResults) {
        if ($item.ProcessPath) {
            Get-FileHash -Path $item.ProcessPath -Algorithm SHA256
        }
    }
}
 
Write-Host "`nSnapshotting services and scheduled tasks..."
$ServiceSnapshot = Get-Service
$TaskSnapshot = Get-ScheduledTask
 
$ServiceSnapshot | Where-Object { $_.Status -eq "Running" } | Select-Object Name, Status -First 4
$TaskSnapshot | Select-Object TaskName, State -First 4

# Phase 4 - Preserve
 
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$folderName = "${hostname}_Triage_Data_$timestamp"
$folderPath = "$HOME\SOC-Triage\$folderName"
 
if (-not (Test-Path "$HOME\SOC-Triage")) {
    New-Item -Path "$HOME\SOC-Triage" -ItemType Directory | Out-Null
}
 
New-Item -Path $folderPath -ItemType Directory | Out-Null
 
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File "$folderPath\registry_run_hkcu.txt"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File "$folderPath\registry_run_hklm.txt"
$ServiceSnapshot | Where-Object { $_.Status -eq "Running" } | Out-File "$folderPath\running_services.txt"
$TaskSnapshot | Out-File "$folderPath\scheduled_tasks.txt"
 
if ($DetectionResults) {
    $DetectionResults | Out-File "$folderPath\detection_results.txt"
}
 
Compress-Archive -Path $folderPath -DestinationPath "$folderPath.zip"
 
Write-Host "`nEvidence saved to $folderPath.zip"

 
