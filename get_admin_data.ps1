# get_admin_data.ps1 (Versi Format Tanggal Seragam)
$ErrorActionPreference = 'SilentlyContinue'

$domainUser = "elife\sys-it-dc"
$domainPass = '2212ChillaBocil'
$dcIP = "192.168.10.16"

# Format string yang lo mau
$fmt = "dddd, dd-MM-yyyy, HH:mm:ss"

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
            # USER LOKAL
            $usr = Get-LocalUser -Name $shortName
            if ($usr) {
                $status = if ($usr.Enabled) { "Enabled" } else { "Disabled" }
                $created = if ($usr.PasswordLastSet) { (Get-Date $usr.PasswordLastSet).ToString($fmt) } else { "N/A" }
                $last_login = if ($usr.LastLogon) { (Get-Date $usr.LastLogon).ToString($fmt) } else { "Belum_Pernah" }
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
                    if ($res.Properties.whencreated) {
                        $created = (Get-Date $res.Properties.whencreated[0]).ToString($fmt)
                    }

                    # Pakai Win32_UserProfile biar beda tiap PC (Logic tetep sama)
                    $userProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*\$shortName" }
                    if ($userProfile.LastUseTime) {
                        $last_login = (Get-Date $userProfile.LastUseTime).ToString($fmt)
                    } else {
                        $last_login = "Belum_Pernah_di_PC_Ini"
                    }
                }
            } catch {
                $status = "AD_Bind_Error"
            }
        }
        # Output sesuai format CSV lo
        Write-Output "$fullName|Administrators|$status|$created|$last_login"
    }
}