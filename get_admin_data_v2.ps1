# get_admin_data.ps1 (Versi Fix LastLogin AD)
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
            # USER LOKAL
            $usr = Get-LocalUser -Name $shortName
            if ($usr) {
                $status = if ($usr.Enabled) { "Enabled" } else { "Disabled" }
                $created = if ($usr.PasswordLastSet) { Get-Date($usr.PasswordLastSet) -Format "yyyy-MM-dd HH:mm:ss" } else { "N/A" }
                $last_login = if ($usr.LastLogon) { Get-Date($usr.LastLogon) -Format "yyyy-MM-dd HH:mm:ss" } else { "Belum_Pernah" }
            }
        } else {
            # USER DOMAIN (Pake Jalur GC)
            try {
                $path = "GC://$dcIP"
                $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $domainUser, $domainPass)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
                $searcher.Filter = "(sAMAccountName=$shortName)"
                $res = $searcher.FindOne()
                if ($res) {
                    $status = "Domain/External"
                    if ($res.Properties.whencreated) {
                        $created = Get-Date($res.Properties.whencreated[0]) -Format "yyyy-MM-dd HH:mm:ss"
                    }

                    # LOGIKA FIX LAST LOGIN AD
                    # Kita cek lastLogonTimestamp (direplikasi) dulu, kalo kosong baru cek lastLogon (lokal DC)
                    $ts = $res.Properties.lastlogontimestamp[0]
                    if (-not $ts) { $ts = $res.Properties.lastlogon[0] }

                    if ($ts) {
                        $last_login = [DateTime]::FromFileTime($ts).ToString("yyyy-MM-dd HH:mm:ss")
                    } else {
                        $last_login = "Belum_Pernah"
                    }
                }
            } catch { $status = "AD_Bind_Error" }
        }
        Write-Output "$fullName,Administrators,$status,$created,$last_login"
    }
}