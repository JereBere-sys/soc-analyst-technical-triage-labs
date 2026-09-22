# Case 3 - IR playbook for DESKTOP-5NLV63K (user: rvance)
# Following up on the FormBook/XLoader C2 activity found in Case 2's pcap.
# This script automates the first-response steps I'd normally do by hand.

# Phase 1 - Detect
# Checking if this machine is still talking to any of the 6 C2 IPs from the pcap.
$C2_IPs = @(
    "172.64.155.76",
    "146.59.71.167",
    "38.182.168.246",
    "45.130.41.161",
    "172.67.162.153",
    "121.54.163.148"
)

Write-Host "Checking live connections against the known C2 IPs..."

# Pull every current TCP connection on this machine (same idea as netstat)
$activeConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue

# Keep only the ones where the remote side is one of our 6 bad IPs
$maliciousConnections = $activeConnections | Where-Object {
    $C2_IPs -contains $_.RemoteAddress
}

if ($maliciousConnections) {
    Write-Host "Match found - this machine has an active connection to a known C2 IP." -ForegroundColor Red

    # For each hit, look up which process actually owns that connection
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
    Write-Host "No active connections to the known C2 IPs right now." -ForegroundColor Yellow
    Write-Host "That's expected on a clean machine - this just confirms the check itself works."
}
