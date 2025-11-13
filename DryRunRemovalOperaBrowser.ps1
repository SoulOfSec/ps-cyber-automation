Write-Output "Starting Opera Browser cleanup scan (dry-run)..."

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

# ===== Identify Running Opera Processes =====
# Opera executables: opera.exe, opera_autoupdate.exe, opera_crashreporter.exe,
# opera_browser_assistant.exe, browser_assistant.exe, launcher.exe (only count if path is Opera folder)
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
        $pPath = $null
        try { $pPath = $_.Path } catch {}

        $isOperaish = $true
        if ($_.Name -ieq "launcher") {
            $isOperaish = ($pPath -match '(?i)\\Opera( GX)?\\') -or ($pPath -match '(?i)\\Opera Software\\')
        }

        if ($isOperaish) {
            $procPath = if ([string]::IsNullOrWhiteSpace($pPath)) { $_.Name } else { $pPath }
            Add-Finding -Type "PROCESS" -Path $procPath -Extra "PID=$($_.Id)"
        }
    }
}

# ===== Define Known Paths =====
$knownRelativePaths = @(
    # Per-user installs
    "AppData\Local\Programs\Opera",
    "AppData\Local\Programs\Opera GX",
    # Per-user data
    "AppData\Roaming\Opera Software",
    "AppData\Local\Opera Software",
    # Common shortcuts/links
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Opera*",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Opera.lnk",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Opera GX*.lnk",
    "Desktop\Opera*.lnk",
    "Downloads\Opera*"
)

# System-wide locations
$systemPaths = @(
    "$env:ProgramFiles\Opera",
    "$env:ProgramFiles\Opera GX",
    "${env:ProgramFiles(x86)}\Opera",
    "${env:ProgramFiles(x86)}\Opera GX",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Opera*"
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

    # Shortcuts (deep search for *.lnk that contain Opera)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*opera*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Add-Finding -Type "SHORTCUT" -Path $_.FullName }
    }
}

# ===== Scheduled Task Lookup (Autoupdate / Assistant) =====
# Typical task names: "Opera scheduled Autoupdate", "Opera GX scheduled Autoupdate", sometimes assistant-related
$foundTasks = @()
try {
    $foundTasks = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"
} catch {}

foreach ($taskLine in $foundTasks) {
    $tn = $taskLine.Matches[0].Groups[1].Value.Trim()
    if ($tn -match "(?i)opera.*autoupdate" -or $tn -match "(?i)opera gx.*autoupdate" -or $tn -match "(?i)assistant.*opera") {
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
        "$base\Software\Opera Software",
        "$base\Software\Classes\OperaStable",
        "$base\Software\Classes\Applications\opera.exe",
        "$base\Software\RegisteredApplications",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
        "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $pathsToCheck) {
        if (-not (Test-Path $path)) { continue }

        # Values containing Opera / browser_assistant.exe
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                $val = "$($prop.Value)"
                if ($prop.Name -match "(?i)opera|browser_assistant" -or $val -match "(?i)opera|browser_assistant") {
                    Add-Finding -Type "REG_VALUE_HKU" -Path $path -Extra "$($prop.Name)=$val"
                }
            }
        } catch {}

        # Keys that are Opera related
        if ($path -match "(?i)\\Opera( Software)?(\\|$)" -or $path -match "(?i)\\Opera GX(\\|$)" -or $path -match "(?i)\\opera\.exe(\\|$)") {
            Add-Finding -Type "REG_KEY_HKU" -Path $path
        }

        # Per-user uninstall subkeys that have Opera in DisplayName
        if ($path -match "(?i)\\Uninstall$") {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    if (("$($p.DisplayName)") -match "(?i)^Opera( GX)?( Browser)?( Stable)?") {
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
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    "HKLM:\SOFTWARE\Microsoft\Tracing"
)

foreach ($path in $hklmPaths) {
    if (-not (Test-Path $path)) { continue }

    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $kv = Get-ItemProperty -Path $_.PsPath -ErrorAction Stop

            # Uninstall entries with DisplayName = Opera*
            if ($kv.PSObject.Properties.Match('DisplayName') -and "$($kv.DisplayName)" -match "(?i)^Opera( GX)?( Browser)?( Stable)?") {
                Add-Finding -Type "REG_KEY_HKLM" -Path $_.PsPath
                if ($kv.UninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "UninstallString=$($kv.UninstallString)" }
                if ($kv.QuietUninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "QuietUninstallString=$($kv.QuietUninstallString)" }
            }

            foreach ($p in $kv.PSObject.Properties) {
                $v = "$($p.Value)"
                if ($p.Name -match "(?i)opera|browser_assistant" -or $v -match "(?i)opera|browser_assistant") {
                    Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "$($p.Name)=$v"
                }
            }
        } catch {}
    }
}

# ===== Prefetch Check =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*OPERA*.pf" -ErrorAction Stop |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*LAUNCHER*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BROWSER_ASSISTANT*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
} catch {}

# ===== Output =====
if ($Findings.Count -eq 0) {
    Write-Output "No Opera artifacts were found. Safe to skip removal."
    return
}

# Machine-readable block for XSIAM parsers
Write-Output "===OPERA_FINDINGS_START==="
foreach ($f in $Findings) {
    $extra = if ([string]::IsNullOrWhiteSpace($f.Extra)) { "" } else { $f.Extra }
    Write-Output ("{0}|{1}|{2}" -f $f.Type, $f.Path, $extra)
}
Write-Output "===OPERA_FINDINGS_END==="

# Optional JSON (compressed) if you want to capture as a playbook artifact
# $Findings | ConvertTo-Json -Compress | Write-Output

# Human-friendly summary
$byType = $Findings | Group-Object Type | Sort-Object Name
Write-Output ("Found {0} Opera-related artifact(s) across {1} category(ies)." -f $Findings.Count, $byType.Count)
foreach ($g in $byType) {
    Write-Output (" - {0}: {1}" -f $g.Name, $g.Count)
}

Write-Output "⚠️ This was a dry-run. No files, tasks, or registry entries were removed."
