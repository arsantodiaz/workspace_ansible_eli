$ErrorActionPreference = 'SilentlyContinue'

# Kredensial Domain
$domainUser = "elife\sys-it-dc"
$domainPass = '2212ChillaBocil'
$dcIP = "192.168.10.16"

# Ambil output net localgroup
$rawOutput = net localgroup administrators

# Filter baris sampah: kita cuma ambil baris diantara 'Members' dan 'The command completed'
$startProcessing = $false
foreach ($line in $rawOutput) {
    $cleanLine = $line.Trim()

    # Abaikan baris kosong
    if (-not $cleanLine) { continue }

    # Mulai proses setelah ketemu baris pembatas '----'
    if ($cleanLine -match "^----") { $startProcessing = $true; continue }

    # Berhenti kalau ketemu tulisan sukses
    if ($cleanLine -match "The command completed") { $startProcessing = $false; continue }

    if ($startProcessing) {
        $fullName = $cleanLine
        $status = "Unknown"; $created = "N/A"; $last_login = "N/A"
        $shortName = if ($fullName -match '\\') { $fullName.Split('\')[-1] } else { $fullName }

        if ($fullName -notmatch "ELIFE") {
            # JALUR USER LOKAL
            $usr = Get-LocalUser -Name $shortName
            if ($usr) {
                $status = if ($usr.Enabled) { "Enabled" } else { "Disabled" }
                $created = if ($usr.PasswordLastSet) { Get-Date($usr.PasswordLastSet) -Format "yyyy-MM-dd HH:mm:ss" } else { "N/A" }
                $last_login = if ($usr.LastLogon) { Get-Date($usr.LastLogon) -Format "yyyy-MM-dd HH:mm:ss" } else { "Belum_Pernah" }
            }
        } else {
            # JALUR DOMAIN (GC Port 3268)
            try {
                $path = "GC://$dcIP"
                $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $domainUser, $domainPass)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
                $searcher.Filter = "(sAMAccountName=$shortName)"
                $res = $searcher.FindOne()
                if ($res) {
                    $status = "Domain/External"
                    if ($res.Properties.whencreated) { $created = Get-Date($res.Properties.whencreated[0]) -Format "yyyy-MM-dd HH:mm:ss" }
                    if ($res.Properties.lastlogon -and $res.Properties.lastlogon.Count -gt 0) {
                        $last_login = [DateTime]::FromFileTime($res.Properties.lastlogon[0]).ToString("yyyy-MM-dd HH:mm:ss")
                    } else { $last_login = "Belum_Pernah" }
                }
            } catch { $status = "AD_Bind_Error" }
        }

        # Output bersih ke CSV
        Write-Output "$fullName,Administrators,$status,$created,$last_login"
    }
}