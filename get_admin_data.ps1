# get_admin_data.ps1 (Versi Fix: LastLogin per Mesin)
$ErrorActionPreference = 'SilentlyContinue'

$domainUser = "elife\sys-it-dc"
$domainPass = '2212ChillaBocil'
$dcIP = "192.168.10.16"

$rawOutput = net localgroup administrators

$startProcessing = $false
foreach ($line in $rawOutput) {
    $cleanLine = $line.Trim()
    if (-not $cleanLine) { continue }
    if ($cleanLine -match "^----") { $startProcessing = $true; continue }
    if ($cleanLine -match "The command completed") { $startProcessing = $false; continue }

    if ($startProcessing) {
        $fullName = $cleanLine
        $status = "Unknown"; $created = "N/A"; $last_login = "N/A"
        $shortName = if ($fullName -match '\\') { $fullName.Split('\')[-1] } else { $fullName }

        if ($fullName -notmatch "ELIFE") {
            # USER LOKAL (Tetap pake logika asli loe)
            $usr = Get-LocalUser -Name $shortName
            if ($usr) {
                $status = if ($usr.Enabled) { "Enabled" } else { "Disabled" }
                $created = if ($usr.PasswordLastSet) { Get-Date($usr.PasswordLastSet) -Format "yyyy-MM-dd HH:mm:ss" } else { "N/A" }
                $last_login = if ($usr.LastLogon) { Get-Date($usr.LastLogon) -Format "yyyy-MM-dd HH:mm:ss" } else { "Belum_Pernah" }
            }
        } else {
            # USER DOMAIN
            try {
                $path = "GC://$dcIP"
                $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $domainUser, $domainPass)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
                $searcher.Filter = "(sAMAccountName=$shortName)"
                $res = $searcher.FindOne()

                if ($res) {
                    $status = "Domain/External"
                    # Created tetap dari AD (karena ini data pusat)
                    if ($res.Properties.whencreated) {
                        $created = Get-Date($res.Properties.whencreated[0]) -Format "yyyy-MM-dd HH:mm:ss"
                    }

                    # --- REVISI: LAST LOGIN DARI LOCAL PROFILE (Agar beda tiap PC) ---
                    $userProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*\$shortName" }
                    if ($userProfile.LastUseTime) {
                        $last_login = Get-Date($userProfile.LastUseTime) -Format "yyyy-MM-dd HH:mm:ss"
                    } else {
                        $last_login = "Belum_Pernah_di_PC_Ini"
                    }
                }
            } catch {
                $status = "AD_Bind_Error"
            }
        }
        # Output sesuai format asli loe
        Write-Output "$fullName,Administrators,$status,$created,$last_login"
    }
}