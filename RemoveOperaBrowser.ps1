Write-Output "Starting Opera Browser cleanup (REAL RUN)..."

# ===== Kill Running Opera Processes =====
$processNames = @(
    "opera",
    "opera_autoupdate",
    "opera_crashreporter",
    "opera_browser_assistant",
    "browser_assistant",
    "launcher"
)

foreach ($proc in $processNames) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Write-Output "KILLED_PROCESS|$($_.ProcessName)|PID=$($_.Id)"
        } catch {
            Write-Output "ERROR_KILL|$($_.ProcessName)|$($_.Exception.Message)"
        }
    }
}

# ===== Remove Files & Directories =====
$systemPaths = @(
    "$env:ProgramFiles\Opera",
    "$env:ProgramFiles\Opera GX",
    "${env:ProgramFiles(x86)}\Opera",
    "${env:ProgramFiles(x86)}\Opera GX",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Opera"
)

foreach ($sys in $systemPaths) {
    if (Test-Path $sys) {
        try {
            Remove-Item -Path $sys -Recurse -Force -ErrorAction Stop
            Write-Output "DEL_DIR|$sys"
        } catch {
            Write-Output "ERROR_DEL|$sys|$($_.Exception.Message)"
        }
    }
}

# Per-user
$knownRelativePaths = @(
    "AppData\Local\Programs\Opera",
    "AppData\Local\Programs\Opera GX",
    "AppData\Roaming\Opera Software",
    "AppData\Local\Opera Software",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Opera",
    "Desktop\Opera.lnk",
    "Desktop\Opera GX.lnk"
)

$validProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($user in $validProfiles) {
    foreach ($rel in $knownRelativePaths) {
        $full = Join-Path $user.FullName $rel
        if (Test-Path $full) {
            try {
                Remove-Item -Path $full -Recurse -Force -ErrorAction Stop
                Write-Output "DEL_FILE_OR_DIR|$full"
            } catch {
                Write-Output "ERROR_DEL|$full|$($_.Exception.Message)"
            }
        }
    }

    # Shortcuts (*.lnk)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*opera*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                    Write-Output "DEL_SHORTCUT|$($_.FullName)"
                } catch {
                    Write-Output "ERROR_DEL|$($_.FullName)|$($_.Exception.Message)"
                }
            }
    }
}

# ===== Scheduled Task Cleanup =====
try {
    $tasks = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"
    foreach ($line in $tasks) {
        $tn = $line.Matches[0].Groups[1].Value.Trim()
        if ($tn -match "(?i)opera.*autoupdate" -or $tn -match "(?i)opera gx.*autoupdate" -or $tn -match "(?i)assistant.*opera") {
            try {
                schtasks /Delete /TN "$tn" /F | Out-Null
                Write-Output "DEL_TASK|$tn"
            } catch {
                Write-Output "ERROR_TASK|$tn|$($_.Exception.Message)"
            }
        }
    }
} catch {}

# ===== Registry Cleanup (HKU) =====
foreach ($userHive in Get-ChildItem "Registry::HKEY_USERS") {
    $sid = $userHive.PSChildName
    if ($sid -match "_Classes$") { continue }
    $base = "Registry::HKEY_USERS\$sid"

    $pathsToCheck = @(
        "$base\Software\Microsoft\Windows\CurrentVersion\Run",
        "$base\Software\Opera Software",
        "$base\Software\Classes\OperaStable",
        "$base\Software\Classes\Applications\opera.exe",
        "$base\Software\RegisteredApplications",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
    )

    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Output "DEL_REG_KEY|$path"
            } catch {
                Write-Output "ERROR_REG|$path|$($_.Exception.Message)"
            }
        }
    }

    $uninst = "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninst) {
        Get-ChildItem $uninst | ForEach-Object {
            try {
                $p = Get-ItemProperty $_.PsPath -ErrorAction Stop
                if ($p.DisplayName -match "(?i)^Opera( GX)?") {
                    Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop
                    Write-Output "DEL_REG_UNINSTALL|$($_.PsPath)"
                }
            } catch {}
        }
    }
}

# ===== Registry Cleanup (HKLM) =====
$hklmPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $hklmPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            try {
                $kv = Get-ItemProperty $_.PsPath -ErrorAction Stop
                if ($kv.DisplayName -match "(?i)^Opera( GX)?") {
                    Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop
                    Write-Output "DEL_REG_KEY|$($_.PsPath)"
                }
            } catch {}
        }
    }
}

# ===== Prefetch Cleanup =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*OPERA*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*LAUNCHER*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BROWSER_ASSISTANT*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
} catch {}

Write-Output "Opera Browser cleanup completed."
