# ==========================================
# OneLaunch Cleanup Scan (DRY-RUN)
# ==========================================
Write-Output "Starting OneLaunch cleanup scan (dry-run)..."

# ===== Config =====
$Delete     = $false                # keep FALSE for dry-run
$SidFilter  = $null                 # e.g. "S-1-5-21-636427573-95980257-707368703-76103" to target one hive

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

function Get-RegValues {
    param([Parameter(Mandatory)][string]$KeyPath, [string]$TypeTag = "REG_VALUE_HKU")
    try {
        $item = Get-Item -Path $KeyPath -ErrorAction Stop
        foreach ($n in $item.GetValueNames()) {
            $v = $item.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
            Add-Finding -Type $TypeTag -Path "$KeyPath\$n" -Extra "$v"
        }
        $def = $item.GetValue('', $null, 'DoNotExpandEnvironmentNames')
        if ($null -ne $def) {
            Add-Finding -Type $TypeTag -Path "$KeyPath\(Default)" -Extra "$def"
        }
    } catch {}
}

function Contains-OneLaunch { param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    return ($s -match '(?i)onelaunch')
}

# ===== Identify Running OneLaunch Processes =====
$processNames = @("OneLaunch","OneLaunch.exe","onelaunchtray","onelaunchtray.exe","chromium","chromium.exe")
foreach ($proc in $processNames) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {
        try { Add-Finding -Type "PROCESS" -Path $_.Name -Extra ("PID={0}" -f $_.Id) } catch {}
    }
}

# ===== Define Known Paths (per-user) =====
$knownRelativePaths = @(
    "AppData\Local\OneLaunch",
    "AppData\Roaming\OneLaunch",
    "AppData\Local\OneLaunch\*\chromium\chromium.exe",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch.lnk",
    "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*OneLaunch*",
    "Downloads\*OneLaunch*",
    "Downloads\*Onelaunch*",
    "AppData\Local\Temp\*OneLaunch*",
    "AppData\Local\Temp\Onelaunch Software.tmp"
)

$validProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @("Public","Default","Default User","All Users")
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

    # Shortcuts anywhere in Start Menu
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*onelaunch*.lnk","*one launch*.lnk" -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Add-Finding -Type "SHORTCUT" -Path $_.FullName }
    }
}

# ===== Scheduled Tasks =====
try {
    $taskDump = schtasks /query /fo LIST /v 2>$null
    if ($taskDump) {
        $taskNames = $taskDump | Select-String "^TaskName:\s+(.+)$" | ForEach-Object {
            $_.Matches[0].Groups[1].Value.Trim()
        } | Sort-Object -Unique

        foreach ($tn in $taskNames) {
            if ($tn -match '(?i)onelaunch') {
                Add-Finding -Type "SCHEDULED_TASK" -Path $tn
            }
        }
    }
} catch {}

# ===== Registry (HKU) =====
$hkuRoots = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object {
    $_.PSChildName -notmatch '_Classes$'
}
if ($SidFilter) { $hkuRoots = $hkuRoots | Where-Object { $_.PSChildName -eq $SidFilter } }

foreach ($userHive in $hkuRoots) {
    $sid = $userHive.PSChildName
    $base = "Registry::HKEY_USERS\$sid"

    $pathsToScan = @(
        "$base\Software\Microsoft\Windows\CurrentVersion\Run",
        "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "$base\Software\OneLaunch",
        "$base\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
        "$base\Software\Classes\Applications\OneLaunch.exe"
    )

    foreach ($path in $pathsToScan) {
        if (-not (Test-Path $path)) { continue }

        # Values referencing OneLaunch
        try {
            $item = Get-Item -Path $path -ErrorAction Stop
            foreach ($name in $item.GetValueNames()) {
                $val = $item.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
                if ($name -match '(?i)onelaunch' -or (Contains-OneLaunch "$val")) {
                    Add-Finding -Type "REG_VALUE_HKU" -Path "$path\$name" -Extra "$val"
                }
            }
            $def = $item.GetValue('', $null, 'DoNotExpandEnvironmentNames')
            if ($def -and (Contains-OneLaunch "$def")) {
                Add-Finding -Type "REG_VALUE_HKU" -Path "$path\(Default)" -Extra "$def"
            }
        } catch {}

        # Keys that themselves are OneLaunch-ish
        if ($path -match "\\OneLaunch(\\|$)" -or $path -match '(?i)OneLaunch') {
            Add-Finding -Type "REG_KEY_HKU" -Path $path
        }

        # Enumerate ALL subkeys under Uninstall; flag {GUID}_is1 and inspect values
        if ($path -like "*\Uninstall") {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                $sub = $_.PsPath
                try {
                    $kvItem = Get-Item -Path $sub -ErrorAction Stop

                    $isInno = $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}_is1$'
                    if ($isInno) {
                        Add-Finding -Type "REG_KEY_HKU" -Path $sub
                    }

                    foreach ($n in $kvItem.GetValueNames()) {
                        $v = $kvItem.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                        if ($isInno -or $n -match '(?i)onelaunch' -or (Contains-OneLaunch "$v")) {
                            Add-Finding -Type "REG_VALUE_HKU" -Path "$sub\$n" -Extra "$v"
                        }
                    }
                    $dv = $kvItem.GetValue('', $null, 'DoNotExpandEnvironmentNames')
                    if ($dv -and ($isInno -or (Contains-OneLaunch "$dv"))) {
                        Add-Finding -Type "REG_VALUE_HKU" -Path "$sub\(Default)" -Extra "$dv"
                    }
                } catch {}
            }
        }
    }

    # ---- RegisteredApplications (and follow pointer to Capability) ----
    $regApps = "$base\Software\RegisteredApplications"
    if (Test-Path $regApps) {
        try {
            $appsItem = Get-Item -Path $regApps -ErrorAction Stop
            $raVal = $appsItem.GetValue('OneLaunch', $null, 'DoNotExpandEnvironmentNames')
            if ($raVal) {
                Add-Finding -Type "REG_VALUE_HKU" -Path "$regApps\OneLaunch" -Extra "$raVal"
                $capKey = Join-Path $base $raVal
                if (Test-Path $capKey) {
                    Add-Finding -Type "REG_KEY_HKU" -Path $capKey
                    Get-RegValues -KeyPath $capKey
                }
            }
        } catch {}
    }

    # ---- Specific keys you called out ----
    $capDirect = "$base\Software\OneLaunch\Browser\Capability"
    if (Test-Path $capDirect) {
        Add-Finding -Type "REG_KEY_HKU" -Path $capDirect
        Get-RegValues -KeyPath $capDirect
    }

    $oneLaunchHtml = "$base\SOFTWARE\Classes\OneLaunchHTML"
    if (Test-Path $oneLaunchHtml) {
        Add-Finding -Type "REG_KEY_HKU" -Path $oneLaunchHtml
        Get-RegValues -KeyPath $oneLaunchHtml
    }

    # ---- Related protocol/file class checks (lightweight) ----
    foreach ($cls in @(
        "$base\Software\Classes\OneLaunchURL",
        "$base\Software\Classes\OneLaunchHTM",
        "$base\Software\Classes\Applications\OneLaunch.exe",
        "$base\Software\Classes\OneLaunchHTML\shell\open\command"
    )) {
        if (Test-Path $cls) {
            Add-Finding -Type "REG_KEY_HKU" -Path $cls
            Get-RegValues -KeyPath $cls
        }
    }

    # ---- UserChoice for URL handlers (look for OneLaunch trying to grab http/https) ----
    foreach ($proto in @("http","https")) {
        $uc = "$base\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$proto\UserChoice"
        if (Test-Path $uc) {
            $item = Get-Item -Path $uc -ErrorAction SilentlyContinue
            if ($item) {
                $progId = $item.GetValue("ProgId", $null, 'DoNotExpandEnvironmentNames')
                if ($progId -and (Contains-OneLaunch "$progId")) {
                    Add-Finding -Type "REG_VALUE_HKU" -Path "$uc\ProgId" -Extra "$progId"
                }
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

    # Include the key itself and its immediate children
    @($path) + (Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object { $_.PsPath }) | ForEach-Object {
        $keyPath = $_
        try {
            $kitem = Get-Item -Path $keyPath -ErrorAction Stop
            if ($kitem.PSChildName -match '(?i)onelaunch') {
                Add-Finding -Type "REG_KEY_HKLM" -Path $keyPath
            }

            # Flag {GUID}_is1 uninstall keys and list all values
            $isInno = $kitem.PSChildName -match '^\{[0-9A-Fa-f-]+\}_is1$'
            if ($isInno) {
                Add-Finding -Type "REG_KEY_HKLM" -Path $keyPath
            }

            foreach ($n in $kitem.GetValueNames()) {
                $v = $kitem.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                if ($isInno -or $n -match '(?i)onelaunch' -or (Contains-OneLaunch "$v")) {
                    Add-Finding -Type "REG_VALUE_HKLM" -Path "$keyPath\$n" -Extra "$v"
                }
            }
            $dv = $kitem.GetValue('', $null, 'DoNotExpandEnvironmentNames')
            if ($dv -and ($isInno -or (Contains-OneLaunch "$dv"))) {
                Add-Finding -Type "REG_VALUE_HKLM" -Path "$keyPath\(Default)" -Extra "$dv"
            }
        } catch {}
    }
}

# ===== Prefetch Check =====
foreach ($pattern in @("*ONELAUNCH*.pf","*CHROMIUM*.pf")) {
    try {
        Get-ChildItem "C:\Windows\Prefetch" -Filter $pattern -ErrorAction Stop | ForEach-Object {
            Add-Finding -Type "PREFETCH" -Path $_.FullName
        }
    } catch {}
}

# ===== Output =====
if ($Findings.Count -eq 0) {
    Write-Output "No OneLaunch artifacts were found. Safe to skip removal."
    return
}

Write-Output "===ONELAUNCH_FINDINGS_START==="
foreach ($f in $Findings) {
    $extra = if ([string]::IsNullOrWhiteSpace($f.Extra)) { "" } else { $f.Extra }
    Write-Output ("{0}|{1}|{2}" -f $f.Type, $f.Path, $extra)
}
Write-Output "===ONELAUNCH_FINDINGS_END==="

$byType = $Findings | Group-Object Type | Sort-Object Name
Write-Output ("Found {0} OneLaunch-related artifact(s) across {1} category(ies)." -f $Findings.Count, $byType.Count)
foreach ($g in $byType) {
    Write-Output (" - {0}: {1}" -f $g.Name, $g.Count)
}
Write-Output "⚠️ This was a dry-run. No files, tasks, or registry entries were removed."
# ==========================================
