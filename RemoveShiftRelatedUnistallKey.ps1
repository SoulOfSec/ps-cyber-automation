Write-Output "Starting Shift uninstall key cleanup (REAL RUN)..."

$TargetInnoKey = '{95fcf903-63b1-44bd-ab77-358a5bd30aae}_is1'
$RemovedKeys   = @()

# --- HKU sweep (per-user uninstall keys) ---
$HKUSids = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object {
    $_.PSChildName -match '^S-1-(5-21|12-1)-' -and $_.PSChildName -notmatch '_Classes$'
}
foreach ($hku in $HKUSids) {
    $sid  = $hku.PSChildName
    $keyPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\$TargetInnoKey"
    if (Test-Path $keyPath) {
        try {
            Remove-Item -Path $keyPath -Recurse -Force
            $RemovedKeys += $keyPath
            Write-Output "Removed uninstall key: $keyPath"
        } catch {
            Write-Output "Failed to remove uninstall key: $keyPath — $_"
        }
    }
}

# --- HKLM sweep (machine-wide, incl. WOW6432Node) ---
foreach ($root in @('HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node')) {
    $keyPath = Join-Path $root "Microsoft\Windows\CurrentVersion\Uninstall\$TargetInnoKey"
    if (Test-Path $keyPath) {
        try {
            Remove-Item -Path $keyPath -Recurse -Force
            $RemovedKeys += $keyPath
            Write-Output "Removed uninstall key: $keyPath"
        } catch {
            Write-Output "Failed to remove uninstall key: $keyPath — $_"
        }
    }
}

# --- XSIAM-friendly output ---
if ($RemovedKeys.Count -eq 0) {
    Write-Output "===SHIFT_UNINSTALLKEY_NONE=== No Shift uninstall keys found."
} else {
    Write-Output "===SHIFT_UNINSTALLKEY_REMOVED_START==="
    $RemovedKeys | ForEach-Object { Write-Output $_ }
    Write-Output "===SHIFT_UNINSTALLKEY_REMOVED_END==="
}

Write-Output "Completed Shift uninstall key cleanup."
