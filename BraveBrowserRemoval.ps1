Write-Output "Starting Brave Browser cleanup (REAL RUN)..."

# ===== Kill Running Brave Processes =====
$processNames = @(
    "brave",
    "braveupdate",
    "brave_crashpad_handler",
    "crashpad_handler"
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

# ===== Remove Files & Directories (System-wide) =====
$systemPaths = @(
    "$env:ProgramFiles\BraveSoftware\Brave-Browser",
    "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application",
    "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser",
    "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Brave",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Brave Browser.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Brave*.lnk"
)

foreach ($sys in $systemPaths) {
    if ($sys -match '[\*\?]') {
        $base = Split-Path $sys -Parent
        $leaf = Split-Path $sys -Leaf
        if (Test-Path $base) {
            Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                    Write-Output "DEL_DIR|$($_.FullName)"
                } catch {
                    Write-Output "ERROR_DEL|$($_.FullName)|$($_.Exception.Message)"
                }
            }
        }
    } else {
        if (Test-Path $sys) {
            try {
                Remove-Item -Path $sys -Recurse -Force -ErrorAction Stop
                Write-Output "DEL_DIR|$sys"
            } catch {
                Write-Output "ERROR_DEL|$sys|$($_.Exception.Message)"
            }
        }
    }
}

# ===== Remove Files & Shortcuts (Per-user) =====
$knownRelativePaths = @(
    # Install/data roots
    "AppData\Local\Programs\BraveSoftware\Brave-Browser\Application",
    "AppData\Local\BraveSoftware\Brave-Browser",
    "AppData\Local\BraveSoftware\Brave-Browser\User Data",
    "AppData\Roaming\BraveSoftware",

    # Common shortcuts
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Brave",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Brave Browser.lnk",
    "Desktop\Brave.lnk",
    "Desktop\Brave Browser.lnk"
)

$validProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($user in $validProfiles) {
    foreach ($rel in $knownRelativePaths) {
        $full = Join-Path $user.FullName $rel
        if ($full -match '[\*\?]') {
            $base = Join-Path $user.FullName (Split-Path $rel -Parent)
            $leaf = Split-Path $rel -Leaf
            if (Test-Path $base) {
                Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                        Write-Output "DEL_FILE_OR_DIR|$($_.FullName)"
                    } catch {
                        Write-Output "ERROR_DEL|$($_.FullName)|$($_.Exception.Message)"
                    }
                }
            }
        } else {
            if (Test-Path $full) {
                try {
                    Remove-Item -Path $full -Recurse -Force -ErrorAction Stop
                    Write-Output "DEL_FILE_OR_DIR|$full"
                } catch {
                    Write-Output "ERROR_DEL|$full|$($_.Exception.Message)"
                }
            }
        }
    }

    # Deep search Start Menu for Brave shortcuts (*.lnk)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*brave*.lnk" -Force -ErrorAction SilentlyContinue |
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

# ===== Scheduled Task Cleanup (Brave Updater & related) =====
try {
    $tasks = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"
    foreach ($line in $tasks) {
        $tn = $line.Matches[0].Groups[1].Value.Trim()
        if ($tn -match "(?i)BraveSoftware.*Update" -or $tn -match "(?i)\bBrave.*Update\b" -or $tn -match "(?i)\bBrave.*AutoUpdate\b") {
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
        "$base\Software\BraveSoftware",
        "$base\Software\Classes\BraveHTML",
        "$base\Software\Classes\Applications\brave.exe",
        "$base\Software\RegisteredApplications",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
    )

    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            try {
                # If it's the Run key, prune only values that reference Brave*
                if ($path -match "\\Run$") {
                    try {
                        $props = Get-ItemProperty -Path $path -ErrorAction Stop
                        foreach ($prop in $props.PSObject.Properties) {
                            $val = "$($prop.Value)"
                            if ($prop.Name -match "(?i)brave|braveupdate|crashpad" -or $val -match "(?i)brave|braveupdate|crashpad") {
                                Remove-ItemProperty -Path $path -Name $prop.Name -Force -ErrorAction Stop
                                Write-Output "DEL_REG_VALUE|$path|$($prop.Name)=$val"
                            }
                        }
                    } catch {}
                } else {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Output "DEL_REG_KEY|$path"
                }
            } catch {
                Write-Output "ERROR_REG|$path|$($_.Exception.Message)"
            }
        }
    }

    # Per-user Uninstall keys
    $uninst = "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninst) {
        Get-ChildItem $uninst | ForEach-Object {
            try {
                $p = Get-ItemProperty $_.PsPath -ErrorAction Stop
                if ($p.DisplayName -match "(?i)^Brave( Browser)?( Beta| Nightly)?$") {
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
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\BraveSoftware",
    "HKLM:\SOFTWARE\WOW6432Node\BraveSoftware"
)

foreach ($path in $hklmPaths) {
    if (Test-Path $path) {
        if ($path -match "\\Uninstall$") {
            Get-ChildItem $path | ForEach-Object {
                try {
                    $kv = Get-ItemProperty $_.PsPath -ErrorAction Stop
                    if ($kv.DisplayName -match "(?i)^Brave( Browser)?( Beta| Nightly)?$") {
                        Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop
                        Write-Output "DEL_REG_KEY|$($_.PsPath)"
                    }
                } catch {}
            }
        } elseif ($path -match "\\Run$") {
            try {
                $props = Get-ItemProperty -Path $path -ErrorAction Stop
                foreach ($prop in $props.PSObject.Properties) {
                    $val = "$($prop.Value)"
                    if ($prop.Name -match "(?i)brave|braveupdate|crashpad" -or $val -match "(?i)brave|braveupdate|crashpad") {
                        try {
                            Remove-ItemProperty -Path $path -Name $prop.Name -Force -ErrorAction Stop
                            Write-Output "DEL_REG_VALUE|$path|$($prop.Name)=$val"
                        } catch {}
                    }
                }
            } catch {}
        } else {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Output "DEL_REG_KEY|$path"
            } catch {}
        }
    }
}

# ===== Prefetch Cleanup =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BRAVE*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BRAVEUPDATE*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*CRASHPAD*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Output "DEL_PREFETCH|$($_.FullName)"
            } catch {}
        }
} catch {}

Write-Output "Brave Browser cleanup completed."
