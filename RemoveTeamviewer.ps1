Write-Output "Starting TeamViewer cleanup scan (real-run)..."

# ===== Helpers =====
$Findings = New-Object System.Collections.Generic.List[pscustomobject]
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Path,
        [string]$Extra = ""
    )
    $Findings.Add([pscustomobject]@{ Type = $Type; Path = $Path; Extra = $Extra })
}

# ===== Identify Running TeamViewer Processes =====
# Common TeamViewer executables:
# TeamViewer.exe, TeamViewer_Service.exe, TeamViewer_Desktop.exe, TeamViewer_QuickSupport.exe, TeamViewer_Host.exe, TeamViewer_Desktop_Service.exe
$processNames = @(
    "teamviewer",
    "teamviewer_service",
    "teamviewer_desktop",
    "teamviewer_quicksupport",
    "teamviewer_host",
    "teamviewer_service64",
    "teamviewer_setup"
)

foreach ($proc in $processNames) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        $pPath = $null
        try { $pPath = $_.Path } catch {}

        $procPath = if ([string]::IsNullOrWhiteSpace($pPath)) { $_.Name } else { $pPath }
        Add-Finding -Type "PROCESS" -Path $procPath -Extra "PID=$($_.Id)"

        # REAL-RUN: kill it
        try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {}
    }
}

# ===== Define Known Paths =====
$knownRelativePaths = @(
    # Per-user / per-machine install locations
    "AppData\Local\Programs\TeamViewer",
    "AppData\Local\TeamViewer",
    "AppData\Roaming\TeamViewer",

    # Per-user data
    "AppData\Roaming\TeamViewer",
    "AppData\Local\TeamViewer",

    # Common shortcuts/links
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\TeamViewer*.lnk",
    "Desktop\TeamViewer*.lnk",
    "Downloads\TeamViewer*"
)

# System-wide locations
$systemPaths = @(
    "$env:ProgramFiles\TeamViewer",
    "$env:ProgramFiles\TeamViewer\TeamViewer.exe",
    "${env:ProgramFiles(x86)}\TeamViewer",
    "${env:ProgramFiles(x86)}\TeamViewer\TeamViewer.exe",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TeamViewer*.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TeamViewer"
)

foreach ($sys in $systemPaths) {
    if ($sys -match '[\*\?]') {
        $base = Split-Path $sys -Parent
        $leaf = Split-Path $sys -Leaf
        if (Test-Path $base) {
            Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Add-Finding -Type "FILE_OR_DIR" -Path $_.FullName
                    # REAL-RUN: remove
                    try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch {}
                }
        }
    } elseif (Test-Path $sys) {
        Add-Finding -Type "FILE_OR_DIR" -Path $sys
        # REAL-RUN: remove
        try { Remove-Item -LiteralPath $sys -Recurse -Force -ErrorAction Stop } catch {}
    }
}

# Per-user profiles to scan
$validProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public", "Default", "Default User", "All Users")
}

foreach ($user in $validProfiles) {
    foreach ($relPath in $knownRelativePaths) {
        if ($relPath -match '[\*\?]') {
            $base = Join-Path $user.FullName (Split-Path $relPath -Parent)
            $leaf = Split-Path $relPath -Leaf
            if (Test-Path $base) {
                Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        Add-Finding -Type "FILE_OR_DIR" -Path $_.FullName
                        # REAL-RUN: remove
                        try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch {}
                    }
            }
            continue
        }

        $fullPath = Join-Path $user.FullName $relPath
        if (Test-Path $fullPath) {
            Add-Finding -Type "FILE_OR_DIR" -Path $fullPath
            # REAL-RUN: remove
            try { Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop } catch {}
        }
    }

    # Shortcuts (deep search for *.lnk that contain TeamViewer)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*teamviewer*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                Add-Finding -Type "SHORTCUT" -Path $_.FullName
                # REAL-RUN: remove
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {}
            }
    }
}

# ===== Services =====
try {
    Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -Type "SERVICE" -Path $_.Name -Extra "Status=$($_.Status)"
        # REAL-RUN: stop + delete
        try { if ($_.Status -ne 'Stopped') { Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue } } catch {}
        try { sc.exe delete $_.Name | Out-Null } catch {}
    }
} catch {}

# ===== Scheduled Task Lookup (Updater / Host tasks) =====
# Typical task names may contain "TeamViewer"
$foundTasks = @()
try {
    $raw = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"
} catch {}

foreach ($taskLine in $foundTasks + $raw) {
    $tn = $taskLine.Matches[0].Groups[1].Value.Trim()
    if ($tn -match "(?i)teamviewer") {
        Add-Finding -Type "SCHEDULED_TASK" -Path $tn
        # REAL-RUN: delete
        try { schtasks /Delete /TN $tn /F | Out-Null } catch {}
    }
}

# ===== Registry Cleanup (HKU) =====
foreach ($userHive in Get-ChildItem "Registry::HKEY_USERS") {
    $sid = $userHive.PSChildName
    if ($sid -match "_Classes$") { continue }

    $base = "Registry::HKEY_USERS\$sid"
    $pathsToCheck = @(
        "$base\Software\Microsoft\Windows\CurrentVersion\Run",
        "$base\Software\TeamViewer",
        "$base\Software\Wow6432Node\TeamViewer",
        "$base\Software\Classes\TeamViewer",
        "$base\Software\Classes\Applications\TeamViewer.exe",
        "$base\Software\RegisteredApplications",
        "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $pathsToCheck) {
        if (-not (Test-Path $path)) { continue }

        # Values containing TeamViewer / teamviewer
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                $val = "$($prop.Value)"
                if ($prop.Name -match "(?i)teamviewer" -or $val -match "(?i)teamviewer") {
                    Add-Finding -Type "REG_VALUE_HKU" -Path $path -Extra "$($prop.Name)=$val"
                    # REAL-RUN: remove this value
                    try { Remove-ItemProperty -Path $path -Name $prop.Name -Force -ErrorAction Stop } catch {}
                }
            }
        } catch {}

        # Keys that are TeamViewer related
        if ($path -match "(?i)\\TeamViewer(\\|$)" -or $path -match "(?i)\\TeamViewer.exe(\\|$)") {
            Add-Finding -Type "REG_KEY_HKU" -Path $path
            # REAL-RUN: remove key
            try { Remove-Item -Path $path -Recurse -Force -ErrorAction Stop } catch {}
        }

        # Per-user uninstall subkeys that have TeamViewer in DisplayName
        if ($path -match "(?i)\\Uninstall$") {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    if (("$($p.DisplayName)") -match "(?i)^TeamViewer|TeamViewer Host|TeamViewer QuickSupport") {
                        Add-Finding -Type "REG_KEY_HKU" -Path $_.PSPath
                        # REAL-RUN: remove uninstall key
                        try { Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop } catch {}
                    }
                } catch {}
            }
        }
    }
}

# ===== HKLM Registry Scan =====
$hklmPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\TeamViewer",
    "HKLM:\SOFTWARE\WOW6432Node\TeamViewer",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    "HKLM:\SOFTWARE\Microsoft\Tracing"
)

foreach ($path in $hklmPaths) {
    if (-not (Test-Path $path)) { continue }

    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $kv = Get-ItemProperty -Path $_.PsPath -ErrorAction Stop

            # Uninstall entries with DisplayName = TeamViewer*
            if ($kv.PSObject.Properties.Match('DisplayName') -and "$($kv.DisplayName)" -match "(?i)TeamViewer|TeamViewer Host|TeamViewer QuickSupport") {
                Add-Finding -Type "REG_KEY_HKLM" -Path $_.PsPath
                # REAL-RUN: remove uninstall key
                try { Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop } catch {}
            }

            foreach ($p in $kv.PSObject.Properties) {
                $v = "$($p.Value)"
                if ($p.Name -match "(?i)teamviewer" -or $v -match "(?i)teamviewer") {
                    Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "$($p.Name)=$v"
                    # REAL-RUN: remove value
                    try { Remove-ItemProperty -Path $_.PsPath -Name $p.Name -Force -ErrorAction Stop } catch {}
                }
            }
        } catch {}
    }
}

# ===== Prefetch Check =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*TEAMVIEWER*.pf" -ErrorAction Stop |
        ForEach-Object {
            Add-Finding -Type "PREFETCH" -Path $_.FullName
            # REAL-RUN: delete
            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {}
        }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*TEAMVIEWERQS*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Finding -Type "PREFETCH" -Path $_.FullName
            # REAL-RUN: delete
            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {}
        }
} catch {}

# ===== File System: common logs and configs =====
$programDataPaths = @(
    "C:\ProgramData\TeamViewer",
    "C:\ProgramData\TeamViewer\Logs"
)
foreach ($pp in $programDataPaths) {
    if (Test-Path $pp) {
        Add-Finding -Type "FILE_OR_DIR" -Path $pp
        # REAL-RUN: remove
        try { Remove-Item -LiteralPath $pp -Recurse -Force -ErrorAction Stop } catch {}
    }
}

# ===== Output =====
if ($Findings.Count -eq 0) {
    Write-Output "No TeamViewer artifacts were found. Nothing removed."
    return
}

# Machine-readable block for XSIAM parsers
Write-Output "===TEAMVIEWER_FINDINGS_START==="
foreach ($f in $Findings) {
    $extra = if ([string]::IsNullOrWhiteSpace($f.Extra)) { "" } else { $f.Extra }
    Write-Output ("{0}|{1}|{2}" -f $f.Type, $f.Path, $extra)
}
Write-Output "===TEAMVIEWER_FINDINGS_END==="

# Human-friendly summary
$byType = $Findings | Group-Object Type | Sort-Object Name
Write-Output ("Found and processed {0} TeamViewer-related artifact(s) across {1} category(ies)." -f $Findings.Count, $byType.Count)
foreach ($g in $byType) {
    Write-Output (" - {0}: {1}" -f $g.Name, $g.Count)
}

Write-Output "✅ Real-run complete. Files, tasks, services, prefetch, and registry artifacts were removed where found."
