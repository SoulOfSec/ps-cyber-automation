Write-Output "Starting Brave Browser cleanup scan (dry-run)..."

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

# ===== Identify Running Brave Processes =====
# Common Brave executables:
# brave.exe, braveupdate.exe, brave_crashpad_handler.exe, crashpad_handler.exe
$processNames = @(
    "brave",
    "braveupdate",
    "brave_crashpad_handler",
    "crashpad_handler"
)

foreach ($proc in $processNames) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        $pPath = $null
        try { $pPath = $_.Path } catch {}

        # For Brave, any of the above processes count if path hints BraveSoftware or Brave
        $isBraveish = $true
        if ($_.Name -in @("crashpad_handler","brave_crashpad_handler")) {
            # Crashpad can be used by other Chromium apps; make sure it's Brave's
            $isBraveish = ($pPath -match '(?i)\\Brave(Software)?\\') -or ($pPath -match '(?i)\\Brave-Browser\\')
        }

        if ($isBraveish) {
            $procPath = if ([string]::IsNullOrWhiteSpace($pPath)) { $_.Name } else { $pPath }
            Add-Finding -Type "PROCESS" -Path $procPath -Extra "PID=$($_.Id)"
        }
    }
}

# ===== Define Known Paths =====
$knownRelativePaths = @(
    # Per-user installs (Brave installs typically per-machine, but include for completeness)
    "AppData\Local\Programs\BraveSoftware\Brave-Browser\Application",

    # Per-user data
    "AppData\Local\BraveSoftware\Brave-Browser",
    "AppData\Local\BraveSoftware\Brave-Browser\User Data",
    "AppData\Roaming\BraveSoftware", # rare, but some artifacts may land here

    # Common shortcuts/links
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Brave*.lnk",
    "Desktop\Brave*.lnk",
    "Downloads\Brave*"
)

# System-wide locations
$systemPaths = @(
    "$env:ProgramFiles\BraveSoftware\Brave-Browser",
    "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application",
    "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser",
    "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Brave*.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Brave Browser*.lnk"
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

    # Shortcuts (deep search for *.lnk that contain Brave)
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*brave*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Add-Finding -Type "SHORTCUT" -Path $_.FullName }
    }
}

# ===== Scheduled Task Lookup (Updater) =====
# Typical task names (machine/user): "BraveSoftwareUpdateTaskMachineCore", "BraveSoftwareUpdateTaskMachineUA",
# and per-user equivalents under \BraveSoftware\
$foundTasks = @()
try {
    $foundTasks = schtasks /query /fo LIST /v | Select-String "^TaskName:\s+(.+)$"
} catch {}

foreach ($taskLine in $foundTasks) {
    $tn = $taskLine.Matches[0].Groups[1].Value.Trim()
    if ($tn -match "(?i)bravesoftware.*update|brave.*update|brave.*autoupdate") {
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
        "$base\Software\BraveSoftware",
        "$base\Software\Classes\BraveHTML",
        "$base\Software\Classes\Applications\brave.exe",
        "$base\Software\RegisteredApplications",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
        "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $pathsToCheck) {
        if (-not (Test-Path $path)) { continue }

        # Values containing Brave / braveupdate
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                $val = "$($prop.Value)"
                if ($prop.Name -match "(?i)brave|braveupdate|crashpad" -or $val -match "(?i)brave|braveupdate|crashpad") {
                    Add-Finding -Type "REG_VALUE_HKU" -Path $path -Extra "$($prop.Name)=$val"
                }
            }
        } catch {}

        # Keys that are Brave related
        if ($path -match "(?i)\\Brave(Software)?(\\|$)" -or $path -match "(?i)\\Brave-Browser(\\|$)" -or $path -match "(?i)\\brave\.exe(\\|$)") {
            Add-Finding -Type "REG_KEY_HKU" -Path $path
        }

        # Per-user uninstall subkeys that have Brave in DisplayName
        if ($path -match "(?i)\\Uninstall$") {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    if (("$($p.DisplayName)") -match "(?i)^Brave( Browser)?( Beta| Nightly)?$") {
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

            # Uninstall entries with DisplayName = Brave*
            if ($kv.PSObject.Properties.Match('DisplayName') -and "$($kv.DisplayName)" -match "(?i)^Brave( Browser)?( Beta| Nightly)?$") {
                Add-Finding -Type "REG_KEY_HKLM" -Path $_.PsPath
                if ($kv.UninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "UninstallString=$($kv.UninstallString)" }
                if ($kv.QuietUninstallString) { Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "QuietUninstallString=$($kv.QuietUninstallString)" }
            }

            foreach ($p in $kv.PSObject.Properties) {
                $v = "$($p.Value)"
                if ($p.Name -match "(?i)brave|braveupdate|crashpad" -or $v -match "(?i)brave|braveupdate|crashpad") {
                    Add-Finding -Type "REG_VALUE_HKLM" -Path $_.PsPath -Extra "$($p.Name)=$v"
                }
            }
        } catch {}
    }
}

# ===== Prefetch Check =====
try {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BRAVE*.pf" -ErrorAction Stop |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*BRAVEUPDATE*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*CRASHPAD*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding -Type "PREFETCH" -Path $_.FullName }
} catch {}

# ===== Output =====
if ($Findings.Count -eq 0) {
    Write-Output "No Brave artifacts were found. Safe to skip removal."
    return
}

# Machine-readable block for XSIAM parsers
Write-Output "===BRAVE_FINDINGS_START==="
foreach ($f in $Findings) {
    $extra = if ([string]::IsNullOrWhiteSpace($f.Extra)) { "" } else { $f.Extra }
    Write-Output ("{0}|{1}|{2}" -f $f.Type, $f.Path, $extra)
}
Write-Output "===BRAVE_FINDINGS_END==="

# Optional JSON (compressed) if you want to capture as a playbook artifact
# $Findings | ConvertTo-Json -Compress | Write-Output

# Human-friendly summary
$byType = $Findings | Group-Object Type | Sort-Object Name
Write-Output ("Found {0} Brave-related artifact(s) across {1} category(ies)." -f $Findings.Count, $byType.Count)
foreach ($g in $byType) {
    Write-Output (" - {0}: {1}" -f $g.Name, $g.Count)
}

Write-Output "⚠️ This was a dry-run. No files, tasks, or registry entries were removed."
