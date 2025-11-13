# Run with Administrator Privileges
Write-Output "Starting Extension Removal Process..."

# List of unique browser extension IDs
$extensionIds = @(
    "kpiecbcckbofpmkkkdibbllpinceiihk",
	"ffbkglfijbcbgblgflchnbphjdllaogb",
	"gfbbhkcipmfiidllnalpchabihdgklnl",
    "Hnmpcagpplmpfojmgmnngilcnanddlhb",
    "dimaiidfpngchbbfimkikgnicmibignd",
    "jedieiamjmoflcknjdjhpieklepfglin",
    "majdfhpaihoncoakbjgbdhglocklcgno",
    "fphgeikpdcdcheaochkhldmnfblfogla",
    "cdbkakmeogejmlpgioplhjkaablahbmj",
    "gjknjjomckknofjidppipffbpoekiipm",
    "jdgilggpfmjpbodmhndmhojklgfdlhob",
    "fjoaledfpmneenckfbpdfhkmimnjocfa",
    "panammoooggmlehahpcjckcncfeffcoi",
    "bibjcjfmgapbfoljiojpipaooddpkpai",
    "bihmplhobchoageeokmgbdihknkjbknd",
    "fgddmllnllkalaagkghckoinaemmogpe",
    "blgcbajigpdfohpgcmbbfnphcgifjopc",
    "gkojfkhlekighikafcpjkiklfbnlmeio"
)

# Output the list of extensions
Write-Output "Checking the following extensions:"
$extensionIds | ForEach-Object { Write-Output " $($_)" }

# Track whether any extensions were removed
$removedExtensions = @()

# Function to check and remove extensions
function Remove-Extension {
    param (
        [string]$extensionId
    )

    $extensionRemoved = $false

    # Get all user profiles
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userProfile in $userProfiles) {
        # Chrome Path (Check Default and other profiles)
        $chromeProfilePath = "$($userProfile.FullName)\AppData\Local\Google\Chrome\User Data"
        if (Test-Path -Path $chromeProfilePath) {
            # Check the Default profile
            $chromeDefaultPath = "$chromeProfilePath\Default\Extensions\$extensionId"
            Write-Output "Checking Chrome Default path: $chromeDefaultPath"
            if (Test-Path -Path $chromeDefaultPath) {
                Write-Output "Chrome extension found at: $chromeDefaultPath. Removing..."
                Remove-Item -Recurse -Force $chromeDefaultPath
                $extensionRemoved = $true
            } else {
                Write-Output "Chrome extension not found at: $chromeDefaultPath"
            }

            # Check other profiles (Profile 1, Profile 2, etc.)
            $profileDirs = Get-ChildItem -Path $chromeProfilePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Profile*" }
            foreach ($profile in $profileDirs) {
                $profilePath = "$chromeProfilePath\$($profile.Name)\Extensions\$extensionId"
                Write-Output "Checking Chrome path for $($profile.Name): $profilePath"
                if (Test-Path -Path $profilePath) {
                    Write-Output "Chrome extension found at: $profilePath. Removing..."
                    Remove-Item -Recurse -Force $profilePath
                    $extensionRemoved = $true
                } else {
                    Write-Output "Chrome extension not found at: $profilePath"
                }
            }
        }

        # Edge Path (Check Default and other profiles)
        $edgeProfilePath = "$($userProfile.FullName)\AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path -Path $edgeProfilePath) {
            # Check the Default profile
            $edgeDefaultPath = "$edgeProfilePath\Default\Extensions\$extensionId"
            Write-Output "Checking Edge Default path: $edgeDefaultPath"
            if (Test-Path -Path $edgeDefaultPath) {
                Write-Output "Edge extension found at: $edgeDefaultPath. Removing..."
                Remove-Item -Recurse -Force $edgeDefaultPath
                $extensionRemoved = $true
            } else {
                Write-Output "Edge extension not found at: $edgeDefaultPath"
            }

            # Check other profiles (Profile 1, Profile 2, etc.)
            $profileDirs = Get-ChildItem -Path $edgeProfilePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Profile*" }
            foreach ($profile in $profileDirs) {
                $profilePath = "$edgeProfilePath\$($profile.Name)\Extensions\$extensionId"
                Write-Output "Checking Edge path for $($profile.Name): $profilePath"
                if (Test-Path -Path $profilePath) {
                    Write-Output "Edge extension found at: $profilePath. Removing..."
                    Remove-Item -Recurse -Force $profilePath
                    $extensionRemoved = $true
                } else {
                    Write-Output "Edge extension not found at: $profilePath"
                }
            }
        }
    }

    if ($extensionRemoved) {
        $removedExtensions += $extensionId
    }
}

# Remove extensions if they exist
$extensionIds | ForEach-Object { Remove-Extension $_ }

# Output if any extensions were removed
if ($removedExtensions.Count -gt 0) {
    Write-Output "The following extensions were removed:"
    $removedExtensions | ForEach-Object { Write-Output "Removed: $($_)" }
} else {
    Write-Output "No extensions were removed."
}

# Indicate that the script has completed
Write-Output "Extension removal process complete."
