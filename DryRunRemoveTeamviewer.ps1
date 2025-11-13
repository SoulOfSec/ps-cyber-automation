Write-Output "Starting TeamViewer cleanup scan (dry-run)..."

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

        # Crash handlers/other helpers not typical for TeamViewer so accept any matching process name
        $procPath = if ([string]::IsNullOrWhiteSpace($pPath)) { $_.Name } else { $pPath }
        Add-Finding -Type "PROCESS" -Path $procPath -Extra "PID=$($_.Id)"
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
                ForEach-Object { Add-Finding -Type "FILE_OR_DIR" -Path $_.FullName }
        }
    } elseif (Test-Path $sys) {
        Add-Finding -Type "FILE_OR_DIR" -Path $sys
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
                    ForEach-Object { Add-Finding -Type "FILE_OR_DIR" -Path $_.FullName }
            }
            continue
        }

        $fullPath = Join-Path $user.FullName $relPath
        if (Test-Path $fullPath) { Add-Finding -Type "FILE_OR_DIR" -Path $fullPath }
    }

    # Shortcuts (deep search for *.lnk that contain TeamViewer)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*teamviewer*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Add-Finding -Type "SHORTCUT" -Path $_.FullName }
    }
}

# ===== Services =====
# Common service names: TeamViewer, TeamViewer_Service
try {
    Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -Type "SERVICE" -Path $_.Name -Extra "Status=$($_.Status)"
    }
} catch {}

# ===== Scheduled Task Lookup (Updater / Host tasks) =====
# Typical task names may contain "TeamViewer" or "TeamViewer" under Task Scheduler tree
$foundTasks = @()
try {
    $raw = schtasks /query /fo LIST /v 2>$null
    if ($raw) {
        $foundTasks = ($raw | Select-String -Pattern '^TaskName:\s+(.+)$' -AllMatches)
    }
} catch {}

foreach ($taskLine in $foundTasks) {
    $tn = $taskLine.Matches[0].Groups[1].Value.Trim()
    if ($tn -match "(?i)teamviewer") {
        Add-Finding -Type "SCHEDULED_TASK" -Path $tn
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
                }
            }
        } catch {}

        # Keys that are TeamViewer related
        if ($path -match "(?i)\\TeamViewer(\\|$)" -or $path -match "(?i)\\TeamViewer.exe(\\|$)") {
            Add-Finding -Type "REG_KEY_HKU" -Path $path
        }

        # Per-user uninstall subkeys that have TeamViewer in DisplayName
        if ($path -match "(?i)\\Uninstall$") {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    if (("$($p.DisplayName)") -match "(?i)^TeamViewer|TeamViewer Host|TeamViewer QuickSupport") {
                        Add-Finding -Type "REG_KEY_HKU" -Path $_.PSPath
                        if ($p.UninstallString) { Add-Finding -Type "REG_VALUE_HKU" -Path $_.PSPath -Extra "UninstallString=$($p.UninstallString)" }
                        if ($p.QuietUninstallString) { Add-Finding -Type "REG_VALUE_HKU" -Path $_.PSPath -Extra "QuietUninstallString=$($p.QuietUninstallString)" }
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
                if ($kv.UninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "UninstallString=$($kv.UninstallString)" }
                if ($kv.QuietUninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "QuietUninstallString=$($kv.QuietUninstallString)" }
            }

            foreach ($p in $kv.PSObject.Properties) {
                $v = "$($p.Value)"
                if ($p.Name -match "(?i)teamviewer" -or $v -match "(?i)teamviewer") {
                    Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "$($p.Name)=$v"
                }
            }
        } catch {}
    }
}

# ===== Prefetch Check =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*TEAMVIEWER*.pf" -ErrorAction Stop |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*TEAMVIEWERQS*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
} catch {}

# ===== File System: common logs and configs =====
# TeamViewer may place logs under ProgramData or AppData; search common ProgramData locations
$programDataPaths = @(
    "C:\ProgramData\TeamViewer",
    "C:\ProgramData\TeamViewer\Logs"
)
foreach ($pp in $programDataPaths) {
    if (Test-Path $pp) { Add-Finding -Type "FILE_OR_DIR" -Path $pp }
}

# ===== Output =====
if ($Findings.Count -eq 0) {
    Write-Output "No TeamViewer artifacts were found. Safe to skip removal."
    return
}

# Machine-readable block for XSIAM parsers
Write-Output "===TEAMVIEWER_FINDINGS_START==="
foreach ($f in $Findings) {
    $extra = if ([string]::IsNullOrWhiteSpace($f.Extra)) { "" } else { $f.Extra }
    Write-Output ("{0}|{1}|{2}" -f $f.Type, $f.Path, $extra)
}
Write-Output "===TEAMVIEWER_FINDINGS_END==="

# Optional JSON (compressed) if you want to capture as a playbook artifact
# $Findings | ConvertTo-Json -Compress | Write-Output

# Human-friendly summary
$byType = $Findings | Group-Object Type | Sort-Object Name
Write-Output ("Found {0} TeamViewer-related artifact(s) across {1} category(ies)." -f $Findings.Count, $byType.Count)
foreach ($g in $byType) {
    Write-Output (" - {0}: {1}" -f $g.Name, $g.Count)
}

Write-Output "⚠️ This was a dry-run. No files, services, scheduled tasks, or registry entries were modified or removed."
