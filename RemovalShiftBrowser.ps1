Write-Output "Starting Shift Browser cleanup (REAL RUN)..."

# === Kill Running Shift Processes ===
$processNames = @("shift", "shiftupdate", "shiftbrowser")
foreach ($proc in $processNames) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force
            Write-Output "Killed process: $($_.Name) (PID: $($_.Id))"
        } catch {
            Write-Output "Failed to kill process: $($_.Name) ($($_.Id)) — $_"
        }
    }
}

# === Known Paths to Clean ===
$knownRelativePaths = @(
    "AppData\Local\Shift",
    "AppData\Local\Shift\chromium\shift.exe",
    "AppData\Roaming\Shift",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Shift",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Shift.lnk",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*Shift*",
    "Downloads\Shift*",
	"Desktop\Shift Browser.lnk"
)

$validProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($user in $validProfiles) {
    foreach ($relPath in $knownRelativePaths) {

        # Handle wildcards
        if ($relPath -match '[\*\?]') {
            $base = Join-Path $user.FullName (Split-Path $relPath -Parent)
            $leaf = Split-Path $relPath -Leaf
            if (Test-Path $base) {
                Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue -Recurse:$false |
                    ForEach-Object {
                        try {
                            Remove-Item -Path $_.FullName -Recurse -Force
                            Write-Output "Removed file/folder: $($_.FullName)"
                        } catch {
                            Write-Output "Failed to remove: $($_.FullName) — $_"
                        }
                    }
            }
            continue
        }

        # No wildcard
        $fullPath = Join-Path $user.FullName $relPath
        if (Test-Path $fullPath) {
            try {
                Remove-Item -Path $fullPath -Recurse -Force
                Write-Output "Removed file/folder: $fullPath"
            } catch {
                Write-Output "Failed to remove: $fullPath — $_"
            }
        }
    }

    # Remove shortcuts
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    Get-ChildItem -Path $startMenu -Recurse -Include "*shift*.lnk" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force
            Write-Output "Removed shortcut: $($_.FullName)"
        } catch {
            Write-Output "Failed to remove shortcut: $($_.FullName) — $_"
        }
    }
}

# === Remove Scheduled Tasks ===
$knownShiftTasks = @("ShiftLaunchTask", "ShiftBrowserTask", "ShiftUpdateTask")
$foundTasks = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"

foreach ($taskLine in $foundTasks) {
    if ($taskLine.Matches[0].Groups[1].Value -match "Shift") {
        $taskName = $taskLine.Matches[0].Groups[1].Value.Trim()
        foreach ($known in $knownShiftTasks) {
            if ($taskName -like "*$known*") {
                try {
                    schtasks /delete /tn "$taskName" /f
                    Write-Output "Removed scheduled task: $taskName"
                } catch {
                    Write-Output "Failed to remove task: $taskName — $_"
                }
            }
        }
    }
}

# === HKU Registry Cleanup ===
foreach ($userHive in Get-ChildItem "Registry::HKEY_USERS") {
    $sid = $userHive.PSChildName
    $base = "Registry::HKEY_USERS\$sid"

    $pathsToClean = @(
        "$base\Software\Microsoft\Windows\CurrentVersion\Run",
        "$base\Software\RegisteredApplications",
        "$base\Software\Shift",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
        "$base\Software\Classes\Applications\Shift.exe"
    )

    foreach ($path in $pathsToClean) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "*Shift*" -or "$($prop.Value)" -like "*Shift*") {
                    try {
                        Remove-ItemProperty -Path $path -Name $prop.Name -Force
                        Write-Output "Removed registry value: $path -> $($prop.Name)"
                    } catch {
                        Write-Output "Failed to remove registry value: $path -> $($prop.Name) — $_"
                    }
                }
            }

            if ($path -like "*\Shift" -or $path -like "*Shift*") {
                try {
                    Remove-Item -Path $path -Recurse -Force
                    Write-Output "Removed registry key: $path"
                } catch {
                    Write-Output "Failed to remove registry key: $path — $_"
                }
            }
        }
    }
}

# === HKLM Registry Cleanup ===
$hklmPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    "HKLM:\SOFTWARE\Microsoft\Tracing"
)

foreach ($path in $hklmPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -like "*Shift*") {
                try {
                    Remove-Item -Path $_.PsPath -Recurse -Force
                    Write-Output "Removed registry key: $($_.PsPath)"
                } catch {
                    Write-Output "Failed to remove registry key: $($_.PsPath) — $_"
                }
            }
        }
    }
}

# === Prefetch Files ===
$prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*SHIFT*.pf" -ErrorAction SilentlyContinue
foreach ($file in $prefetchFiles) {
    try {
        Remove-Item -Path $file.FullName -Force
        Write-Output "Removed prefetch file: $($file.FullName)"
    } catch {
        Write-Output "Failed to remove prefetch file: $($file.FullName) — $_"
    }
}

Write-Output "Shift Browser cleanup completed."
