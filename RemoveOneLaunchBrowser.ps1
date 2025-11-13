# OneLaunch REAL-RUN Remover (enhanced to match dry-run coverage)
# Run as Administrator

$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Starting OneLaunch cleanup (REAL RUN)..."

# ========= Helpers =========
$Removed = New-Object System.Collections.Generic.List[pscustomobject]
$Failed  = New-Object System.Collections.Generic.List[pscustomobject]

function Add-Result {
    param([string]$Type,[string]$Path,[string]$Action,[bool]$Success,[string]$Extra="")
    $obj = [pscustomobject]@{ Type=$Type; Path=$Path; Action=$Action; Extra=$Extra }
    if ($Success) { $Removed.Add($obj) } else { $Failed.Add($obj) }
}

function Remove-ItemSafely {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        try { Attrib -R -H -S -A -I -Q "$Path" *>$null } catch {}
        try {
            if (Test-Path -LiteralPath $Path -PathType Container) {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
            Add-Result -Type "FILE_OR_DIR" -Path $Path -Action "Delete" -Success $true
        } catch { Add-Result -Type "FILE_OR_DIR" -Path $Path -Action "Delete" -Success $false -Extra $_.Exception.Message }
    }
}

function Remove-RegKey {
    param([Parameter(Mandatory)][string]$KeyPath)
    try {
        if (Test-Path $KeyPath) {
            Remove-Item $KeyPath -Recurse -Force -ErrorAction Stop
            Add-Result -Type "REG_KEY" -Path $KeyPath -Action "Delete" -Success $true
        }
    } catch { Add-Result -Type "REG_KEY" -Path $KeyPath -Action "Delete" -Success $false -Extra $_.Exception.Message }
}

function Remove-RegValueExact {
    param([Parameter(Mandatory)][string]$KeyPath,[Parameter(Mandatory)][string]$Name)
    try {
        if (Test-Path $KeyPath) {
            Remove-ItemProperty -Path $KeyPath -Name $Name -Force -ErrorAction Stop
            Add-Result -Type "REG_VALUE" -Path "$KeyPath::$Name" -Action "Delete" -Success $true
        }
    } catch { Add-Result -Type "REG_VALUE" -Path "$KeyPath::$Name" -Action "Delete" -Success $false -Extra $_.Exception.Message }
}

function Remove-RegValueIfMatch {
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$NameLike,   # wildcard for value name
        [Parameter(Mandatory)][string]$ValueLike   # wildcard for value data
    )
    try {
        if (-not (Test-Path $KeyPath)) { return }
        $props = Get-ItemProperty -Path $KeyPath -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            $n = $p.Name
            $v = "$($p.Value)"
            if ($n -like $NameLike -or $v -like $ValueLike) {
                try {
                    Remove-ItemProperty -Path $KeyPath -Name $n -Force -ErrorAction Stop
                    Add-Result -Type "REG_VALUE" -Path "$KeyPath::$n" -Action "Delete" -Success $true -Extra $v
                } catch {
                    Add-Result -Type "REG_VALUE" -Path "$KeyPath::$n" -Action "Delete" -Success $false -Extra $_.Exception.Message
                }
            }
        }
    } catch {}
}

function Contains-OneLaunch {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    return ($s -match '(?i)onelaunch')
}

# ========= 1) Kill Processes =========
$procNames = @("OneLaunch","OneLaunch.exe","onelaunchtray","onelaunchtray.exe","chromium","chromium.exe")
foreach ($pn in $procNames) {
    Get-Process -Name $pn -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Add-Result -Type "PROCESS" -Path $_.Name -Action "Kill" -Success $true -Extra ("PID={0}" -f $_.Id)
        } catch {
            Add-Result -Type "PROCESS" -Path $_.Name -Action "Kill" -Success $false -Extra ("PID={0}; {1}" -f $_.Id, $_.Exception.Message)
        }
    }
}

# ========= 2) Files & Shortcuts (per-user) =========
$relPaths = @(
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

$validProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Public","Default","Default User","All Users")
}

foreach ($user in $validProfiles) {
    foreach ($rel in $relPaths) {
        $base = Join-Path $user.FullName (Split-Path $rel -Parent)
        $leaf = Split-Path $rel -Leaf
        if ($rel -match '[\*\?]') {
            if (Test-Path $base) {
                Get-ChildItem -Path $base -Filter $leaf -Force -ErrorAction SilentlyContinue -Recurse:$false |
                    ForEach-Object { Remove-ItemSafely -Path $_.FullName }
            }
        } else {
            $full = Join-Path $user.FullName $rel
            Remove-ItemSafely -Path $full
        }
    }

    # Remove shortcuts anywhere in Start Menu
    $startMenu = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
    if (Test-Path $startMenu) {
        Get-ChildItem -Path $startMenu -Recurse -Include "*onelaunch*.lnk","*one launch*.lnk" -Force |
            ForEach-Object { Remove-ItemSafely -Path $_.FullName }
    }
}

# ========= 3) Scheduled Tasks =========
$schtxt = schtasks /query /fo LIST /v 2>$null
if ($LASTEXITCODE -eq 0 -and $schtxt) {
    $schtxt | Select-String "^TaskName:\s+(.+)$" | ForEach-Object {
        $tn = $_.Matches[0].Groups[1].Value.Trim()
        if ($tn -like "*OneLaunch*" -or $tn -like "*One Launch*") {
            try { schtasks /delete /tn "$tn" /f *>$null; Add-Result -Type "SCHEDULED_TASK" -Path $tn -Action "Unregister" -Success $true }
            catch { Add-Result -Type "SCHEDULED_TASK" -Path $tn -Action "Unregister" -Success $false -Extra $_.Exception.Message }
        }
    }
}

# ========= 4) Registry Cleanup =========

# --- helper: remove HKU RegisteredApplications value and follow capability path ---
function Remove-RegisteredApplications-OneLaunch {
    param([string]$BaseHive)  # e.g., "Registry::HKEY_USERS\S-1-5-21-...\..."
    $regApps = "$BaseHive\Software\RegisteredApplications"
    if (Test-Path $regApps) {
        try {
            $item = Get-Item -Path $regApps -ErrorAction Stop
            $ptr  = $item.GetValue('OneLaunch', $null, 'DoNotExpandEnvironmentNames')
            if ($ptr) {
                Remove-RegValueExact -KeyPath $regApps -Name 'OneLaunch'
                # follow the relative pointer, e.g. SOFTWARE\OneLaunch\Browser\Capability
                $capKey = Join-Path $BaseHive $ptr
                if (Test-Path $capKey) { Remove-RegKey -KeyPath $capKey }
            }
        } catch {}
    }
}

# --- helper: clean UserChoice ProgId if it references OneLaunch ---
function Clean-UserChoice {
    param([string]$BaseHive,[string]$Proto)
    $uc = "$BaseHive\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Proto\UserChoice"
    if (Test-Path $uc) {
        try {
            $it = Get-Item -Path $uc -ErrorAction Stop
            $pid = $it.GetValue("ProgId",$null,'DoNotExpandEnvironmentNames')
            if ($pid -and (Contains-OneLaunch "$pid")) {
                Remove-RegKey -KeyPath $uc
            }
        } catch {}
    }
}

# 4a) HKU — all user hives
foreach ($h in Get-ChildItem "Registry::HKEY_USERS") {
    $sid = $h.PSChildName
    if ($sid -match "_Classes$") { continue }
    $base = "Registry::HKEY_USERS\$sid"

    # RegisteredApplications + Capability follower
    Remove-RegisteredApplications-OneLaunch -BaseHive $base

    # Per-user classes and direct OneLaunch keys
    foreach ($k in @(
        "$base\Software\OneLaunch",
        "$base\Software\OneLaunch\Browser",
        "$base\Software\OneLaunch\Browser\Capability",
        "$base\SOFTWARE\Classes\OneLaunchHTML",
        "$base\Software\Classes\OneLaunchURL",
        "$base\Software\Classes\OneLaunchHTM",
        "$base\Software\Classes\Applications\OneLaunch.exe"
    )) { Remove-RegKey -KeyPath $k }

    # Per-user Run autoruns
    $run = "$base\Software\Microsoft\Windows\CurrentVersion\Run"
    Remove-RegValueIfMatch -KeyPath $run -NameLike "*OneLaunch*" -ValueLike "*OneLaunch*"

    # Per-user Uninstall: delete {GUID}_is1 and anything referencing OneLaunch
    $uninst = "$base\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninst) {
        Get-ChildItem $uninst -ErrorAction SilentlyContinue | ForEach-Object {
            $subPath = $_.PsPath
            $name = $_.PSChildName
            $isInno = $name -match '^\{[0-9A-Fa-f-]+\}_is1$'
            $shouldRemove = $false
            try {
                $itm = Get-Item -Path $subPath -ErrorAction Stop
                foreach ($n in $itm.GetValueNames()) {
                    $v = $itm.GetValue($n,$null,'DoNotExpandEnvironmentNames')
                    if ($isInno -or $n -like "*OneLaunch*" -or (Contains-OneLaunch "$v")) { $shouldRemove = $true; break }
                }
                # also check (Default)
                if (-not $shouldRemove) {
                    $dv = $itm.GetValue('', $null, 'DoNotExpandEnvironmentNames')
                    if ($dv -and (Contains-OneLaunch "$dv")) { $shouldRemove = $true }
                }
            } catch {}
            if ($shouldRemove) { Remove-RegKey -KeyPath $subPath }
        }
    }

    # Clean http/https hijack if set to OneLaunch
    Clean-UserChoice -BaseHive $base -Proto "http"
    Clean-UserChoice -BaseHive $base -Proto "https"
}

# 4b) HKLM — machine-wide
# HKLM Run
$lmRun = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-RegValueIfMatch -KeyPath $lmRun -NameLike "*OneLaunch*" -ValueLike "*OneLaunch*"

# HKLM Uninstall (native + WOW6432) — remove {GUID}_is1 and keys that reference OneLaunch
foreach ($parent in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)) {
    if (-not (Test-Path $parent)) { continue }
    Get-ChildItem $parent -ErrorAction SilentlyContinue | ForEach-Object {
        $kp = $_.PsPath
        $name = $_.PSChildName
        $isInno = $name -match '^\{[0-9A-Fa-f-]+\}_is1$'
        $shouldRemove = $false
        try {
            $kv = Get-Item -Path $kp -ErrorAction Stop
            foreach ($n in $kv.GetValueNames()) {
                $v = $kv.GetValue($n,$null,'DoNotExpandEnvironmentNames')
                if ($isInno -or $n -like "*OneLaunch*" -or (Contains-OneLaunch "$v")) { $shouldRemove = $true; break }
            }
            if (-not $shouldRemove) {
                $dv = $kv.GetValue('', $null, 'DoNotExpandEnvironmentNames')
                if ($dv -and (Contains-OneLaunch "$dv")) { $shouldRemove = $true }
            }
        } catch {}
        if ($shouldRemove) { Remove-RegKey -KeyPath $kp }
    }
}

# Optional: prune TaskCache branches that look OneLaunch-y
$taskTree = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
if (Test-Path $taskTree) {
    Get-ChildItem $taskTree -Recurse -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '(?i)onelaunch'
    } | ForEach-Object { Remove-RegKey -KeyPath $_.PsPath }
}

# ========= 5) Prefetch =========
foreach ($pf in @("*ONELAUNCH*.pf","*CHROMIUM*.pf")) {
    try {
        Get-ChildItem "C:\Windows\Prefetch" -Filter $pf | ForEach-Object {
            Remove-ItemSafely -Path $_.FullName
        }
    } catch {}
}

# ========= Output =========
Write-Output "===ONELAUNCH_REMOVAL_RESULTS_START==="
foreach ($r in $Removed) { Write-Output ("OK|{0}|{1}|{2}" -f $r.Type, $r.Path, $r.Action) }
foreach ($f in $Failed)  { Write-Output ("ERR|{0}|{1}|{2}|{3}" -f $f.Type, $f.Path, $f.Action, $f.Extra) }
Write-Output "===ONELAUNCH_REMOVAL_RESULTS_END==="

# Human summary
$ok  = $Removed.Count
$err = $Failed.Count
Write-Output ("Completed OneLaunch removal. Successes: {0}, Failures: {1}" -f $ok,$err)
if ($err -gt 0) {
    Write-Output "Some items could not be removed (permissions/locks). Re-run after reboot or in Safe Mode, or share the ERR lines."
}
