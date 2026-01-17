# ==============================================================================
# SCRIPT AUDIT FULL - FINAL FIX (NO PIPE ERROR)
# ==============================================================================

# 0. PRE-REQ CHECK
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning "HARAP JALANKAN SEBAGAI ADMINISTRATOR!"
    Break
}

$sysInfo = Get-CimInstance Win32_ComputerSystem
$isDC = ($sysInfo.DomainRole -ge 4) 

Clear-Host
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "       AUDIT EXECUTION: REQUEST ITEMS 1 TO 23            " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

if ($isDC) { Write-Host "[SYSTEM] TIPE: DOMAIN CONTROLLER (AD)" -ForegroundColor Green } 
else { Write-Host "[SYSTEM] TIPE: MEMBER SERVER / WORKSTATION" -ForegroundColor Yellow }
Write-Host ""

# ==============================================================================

# ITEM 1: Guest User Status
Write-Host "[ITEM 1] Report of Guest User Status" -ForegroundColor Cyan
try {
    if ($isDC) { Get-ADUser -Identity "Guest" -Properties Enabled | Select Name, Enabled, DistinguishedName | Format-List }
    else { Get-LocalUser -Name "Guest" | Select Name, Enabled, Description | Format-List }
} catch { Write-Warning "User Guest tidak ditemukan." }
Write-Host "---------------------------------------------------------"

# ITEM 2: Security Options
Write-Host "[ITEM 2] Security Options" -ForegroundColor Cyan
try {
    $reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "autodisconnect" -ErrorAction SilentlyContinue
    if ($reg) { Write-Host "Idle Time Setting (Minutes): $($reg.autodisconnect)" } 
    else { Write-Host "Registry Key 'autodisconnect' not found." -ForegroundColor Gray }
} catch { Write-Warning "Gagal membaca Registry." }
Write-Host "---------------------------------------------------------"

# ITEM 3: Password Policy
Write-Host "[ITEM 3] Password Policy" -ForegroundColor Cyan
if ($isDC) {
    Write-Host "(Domain Policy)"
    Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, MaxPasswordAge, LockoutThreshold, LockoutDuration
} else {
    Write-Host "(Local Policy)"
    net accounts
}
Write-Host "---------------------------------------------------------"

# ITEM 4: User Property
Write-Host "[ITEM 4] User Property (Sample)" -ForegroundColor Cyan
try {
    if ($isDC) { Get-ADUser "Administrator" -Properties * | Select Name, Created, PasswordLastSet, LastLogonDate | Format-List }
    else { Get-LocalUser "Administrator" | Select * | Format-List }
} catch {}
Write-Host "---------------------------------------------------------"

# ITEM 5: Group List Members (Revised Logic)
Write-Host "[ITEM 5] Report of Group List Members (With Status)" -ForegroundColor Cyan

# Fungsi Helper Status
function Get-MemberStatus {
    param ($Member)
    $stat = "Unknown/Group"
    if ($Member.ObjectClass -eq "User") {
        try {
            if ($Member.PrincipalSource -eq "Local") {
                $cleanName = $Member.Name.Split('\')[-1]
                $u = Get-LocalUser -Name $cleanName -ErrorAction Stop
                if ($u.Enabled) { $stat = "ENABLED" } else { $stat = "DISABLED" }
            } 
            elseif ($Member.PrincipalSource -eq "ActiveDirectory") {
                if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                    $u = Get-ADUser -Identity $Member.SID -Properties Enabled -ErrorAction Stop
                    if ($u.Enabled) { $stat = "ENABLED" } else { $stat = "DISABLED" }
                } else { $stat = "Domain User (Need RSAT)" }
            }
        } catch { $stat = "Error Reading" }
    }
    return $stat
}

if ($isDC) {
    # DOMAIN CONTROLLER
    $groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Remote Desktop Users")
    foreach ($g in $groups) {
        Write-Host "Checking AD Group: $g" -ForegroundColor Yellow
        try { 
            $mems = Get-ADGroupMember $g -Recursive 
            if ($mems) {
                # Fix: Simpan ke variabel $output dulu
                $output = foreach ($m in $mems) {
                    try {
                        $u = Get-ADUser $m.DistinguishedName -Properties Enabled -ErrorAction SilentlyContinue
                        if ($u.Enabled) { $st = "ENABLED" } else { $st = "DISABLED" }
                    } catch { $st = "Group/Unknown" }
                    
                    [PSCustomObject]@{
                        Name = $m.Name
                        Type = $m.objectClass
                        Status = $st
                    }
                }
                $output | Format-Table -AutoSize
            } else { Write-Host "  (Empty)" -ForegroundColor Gray }
        } catch { Write-Host "  (Group Not Found)" -ForegroundColor Gray }
    }
} else {
    # MEMBER SERVER / LOCAL
    $groups = @("Administrators", "Backup Operators", "Network Configuration Operators", "Remote Desktop Users", "Power Users", "Users")
    foreach ($g in $groups) {
        Write-Host "Checking Local Group: $g" -ForegroundColor Yellow
        try { 
            $members = Get-LocalGroupMember -Group $g -ErrorAction Stop
            
            # Fix: Simpan ke variabel $output dulu
            $output = foreach ($m in $members) {
                [PSCustomObject]@{
                    Name   = $m.Name
                    Source = $m.PrincipalSource
                    Status = Get-MemberStatus -Member $m
                }
            }
            
            if ($output) { $output | Format-Table -AutoSize } 
            else { Write-Host "  (Empty)" -ForegroundColor Gray }

        } catch { Write-Host "  (Group Not Found)" -ForegroundColor Gray }
        Write-Host ""
    }
}
Write-Host "---------------------------------------------------------"

# ITEM 6: Registry Permissions
Write-Host "[ITEM 6] Registry Access Permissions (Winreg)" -ForegroundColor Cyan
try {
    $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg" -ErrorAction SilentlyContinue
    if ($acl) { $acl.Access | Select IdentityReference, AccessControlType, RegistryRights | Format-Table -AutoSize }
    else { Write-Warning "Key Winreg tidak ditemukan." }
} catch { Write-Warning "Gagal akses Registry ACL." }
Write-Host "---------------------------------------------------------"

# ITEM 7: AD Trust
Write-Host "[ITEM 7] AD Trust Relationships" -ForegroundColor Cyan
if ($isDC) {
    try { Get-ADTrust -Filter * | Select Name, TrustType, Direction | Format-Table -AutoSize } catch { Write-Warning "Error checking Trust." }
} else { Write-Host "N/A (Not a Domain Controller)" -ForegroundColor DarkGray }
Write-Host "---------------------------------------------------------"

# ITEM 8: File System Access
Write-Host "[ITEM 8] File System Update Access" -ForegroundColor Cyan
Write-Host "MANUAL CHECK REQUIRED: Right click target folder -> Properties -> Security." -ForegroundColor Red
Write-Host "---------------------------------------------------------"

# ITEM 9: FTP Accounts
Write-Host "[ITEM 9] FTP Accounts and Permissions" -ForegroundColor Cyan
if (Get-Module -ListAvailable WebAdministration) {
    try {
        Import-Module WebAdministration
        Get-WebSite | Where-Object { $_.Bindings.Collection.Protocol -contains "ftp" } | Format-Table Name, State, PhysicalPath
    } catch { Write-Host "Error querying IIS FTP." }
} else {
    Write-Host "IIS Module not installed / No FTP." -ForegroundColor DarkGray
}
Write-Host "---------------------------------------------------------"

# ITEM 10: Domain Structure
Write-Host "[ITEM 10] Domain Structure Service" -ForegroundColor Cyan
try {
    $service = Get-Service "NTDS" -ErrorAction SilentlyContinue
    if ($service) { Write-Host "Service 'Active Directory Domain Services' (NTDS): $($service.Status)" -ForegroundColor Green }
    else { Write-Host "Service NTDS NOT FOUND (Normal for Member Server)." -ForegroundColor Yellow }
    Write-Host "Computer Name: $env:COMPUTERNAME"
} catch {}
Write-Host "---------------------------------------------------------"

# ITEM 11: File System Report
Write-Host "[ITEM 11] File System Report (Drives)" -ForegroundColor Cyan
Get-Volume | Select DriveLetter, FileSystemLabel, FileSystem, DriveType, SizeRemaining, Size | Format-Table -AutoSize
Write-Host "---------------------------------------------------------"

# ITEM 12: App Directory Access
Write-Host "[ITEM 12] Application Directory Access (Program Files)" -ForegroundColor Cyan
try {
    (Get-Acl "C:\Program Files").Access | Select IdentityReference, FileSystemRights, AccessControlType | Format-Table -AutoSize
} catch { Write-Warning "Access Denied." }
Write-Host "---------------------------------------------------------"

# ITEM 13: AD Trust Re-Check
Write-Host "[ITEM 13] AD Trust (Re-Check)" -ForegroundColor Cyan
if ($isDC) { Get-ADTrust -Filter * | Select Name, TrustType | Format-Table } else { Write-Host "N/A" -ForegroundColor DarkGray }
Write-Host "---------------------------------------------------------"

# ITEM 14: Fine Grained Password
Write-Host "[ITEM 14] Fine Grained Password Policies" -ForegroundColor Cyan
if ($isDC) {
    try { Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name, ComplexityEnabled, MinPasswordLength } catch { Write-Host "No Fine Grained Policies." }
    Write-Host "Default Domain Policy:"
    Get-ADDefaultDomainPasswordPolicy | Select MinPasswordLength, MaxPasswordAge | Format-Table
} else {
    Write-Host "Local Policy:"
    net accounts
}
Write-Host "---------------------------------------------------------"

# ITEM 15: Privileged Accounts
Write-Host "[ITEM 15] List of Privileged Accounts" -ForegroundColor Cyan
if ($isDC) {
    $pGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    foreach ($g in $pGroups) {
        Write-Host "AD Group: $g" -ForegroundColor Yellow
        try { Get-ADGroupMember $g | Select Name, DistinguishedName | Format-Table -HideTableHeaders } catch {}
    }
} else {
    $pGroups = @("Administrators", "Backup Operators", "Power Users")
    foreach ($g in $pGroups) {
        Write-Host "Local Group: $g" -ForegroundColor Yellow
        try { Get-LocalGroupMember $g | Select Name, PrincipalSource | Format-Table -HideTableHeaders } catch {}
    }
}
Write-Host "---------------------------------------------------------"

# ITEM 16: User Rights RSOP
Write-Host "[ITEM 16] User Rights Assignment" -ForegroundColor Cyan
try {
    $rsop = Get-WmiObject -Namespace root\rsop\computer -Query "SELECT UserRight, AccountList FROM RSOP_UserPrivilegeRight" -ErrorAction SilentlyContinue
    if ($rsop) { $rsop | Select UserRight, AccountList | Format-Table -AutoSize }
    else { Write-Warning "RSOP Data Empty (Please check via 'secpol.msc')." }
} catch { Write-Warning "Failed to query WMI RSOP." }
Write-Host "---------------------------------------------------------"

# ITEM 17: Default Accounts
Write-Host "[ITEM 17] Default Accounts Status" -ForegroundColor Cyan
$defUsers = @("Administrator", "Guest", "HelpAssistant")
foreach ($u in $defUsers) {
    try {
        if ($isDC) { Get-ADUser $u -Properties Enabled -ErrorAction SilentlyContinue | Select Name, Enabled | Format-Table -HideTableHeaders }
        else { Get-LocalUser $u -ErrorAction SilentlyContinue | Select Name, Enabled | Format-Table -HideTableHeaders }
    } catch {}
}
Write-Host "---------------------------------------------------------"

# ITEM 18: Remote Desktop Access
Write-Host "[ITEM 18] Remote Desktop Access Users" -ForegroundColor Cyan
try {
    if ($isDC) { Get-ADGroupMember "Remote Desktop Users" -Recursive | Select Name | Format-Table -HideTableHeaders }
    else { Get-LocalGroupMember "Remote Desktop Users" | Select Name | Format-Table -HideTableHeaders }
} catch { Write-Warning "Group 'Remote Desktop Users' empty/not found." }
Write-Host "---------------------------------------------------------"

# ITEM 19: Audit Log Config
Write-Host "[ITEM 19] Audit Log Configuration (Export)" -ForegroundColor Cyan
$auditFileName = "$env:COMPUTERNAME" + "_AuditPolicy.txt"
$auditFilePath = Join-Path -Path $PWD -ChildPath $auditFileName
try {
    auditpol /get /category:* > $auditFilePath
    if (Test-Path $auditFilePath) { Write-Host "[SUCCESS] Saved to: $auditFilePath" -ForegroundColor Green }
} catch { Write-Warning "Gagal auditpol." }
Write-Host "---------------------------------------------------------"

# ITEM 20: Security Events
Write-Host "[ITEM 20] Security Events (Trust Changes)" -ForegroundColor Cyan
try {
    $events = Get-EventLog -LogName Security -Newest 1000 -InstanceId 4706, 4707, 4716 -ErrorAction SilentlyContinue
    if ($events) { $events | Select TimeGenerated, EventID, Message | Format-Table }
    else { Write-Host "No Trust Change events in last 1000 logs." -ForegroundColor Green }
} catch { Write-Warning "Log access denied." }
Write-Host "---------------------------------------------------------"

# ITEM 21: Hotfixes
Write-Host "[ITEM 21] List of Hot Fixes" -ForegroundColor Cyan
Get-HotFix | Sort InstalledOn -Descending | Select -First 10 HotFixID, Description, InstalledOn | Format-Table -AutoSize
Write-Host "---------------------------------------------------------"

# ITEM 22: Detailed Privileged Access (Revised Logic)
Write-Host "[ITEM 22] Detailed Privileged Access List (With Status)" -ForegroundColor Cyan

# Re-define Helper
function Get-MemberStatus2 {
    param ($Member)
    $stat = "Unknown/Group"
    if ($Member.ObjectClass -eq "User") {
        try {
            if ($Member.PrincipalSource -eq "Local") {
                $cleanName = $Member.Name.Split('\')[-1]
                $u = Get-LocalUser -Name $cleanName -ErrorAction Stop
                if ($u.Enabled) { $stat = "ENABLED (RISK)" } else { $stat = "DISABLED (SAFE)" }
            } 
            elseif ($Member.PrincipalSource -eq "ActiveDirectory") {
                if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                    $u = Get-ADUser -Identity $Member.SID -Properties Enabled -ErrorAction Stop
                    if ($u.Enabled) { $stat = "ENABLED (RISK)" } else { $stat = "DISABLED (SAFE)" }
                } else { $stat = "Domain User (No RSAT)" }
            }
        } catch { $stat = "Error" }
    }
    return $stat
}

if ($isDC) {
    $groupsToCheck = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Server Operators", "Backup Operators")
} else {
    $groupsToCheck = @("Administrators", "Network Configuration Operators", "Remote Desktop Users", "Server Operators", "Backup Operators")
}

foreach ($grp in $groupsToCheck) {
    Write-Host "Checking: $grp" -ForegroundColor Yellow
    try {
        if ($isDC) {
            # AD Logic
            $mems = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop
            
            # Fix: Simpan ke variabel $output dulu
            $output = foreach ($m in $mems) {
                 try {
                    $u = Get-ADUser $m.DistinguishedName -Properties Enabled -ErrorAction SilentlyContinue
                    if ($u.Enabled) { $st = "ENABLED" } else { $st = "DISABLED" }
                } catch { $st = "N/A" }
                [PSCustomObject]@{ Name=$m.Name; Class=$m.objectClass; Status=$st }
            }
            $output | Format-Table -AutoSize

        } else {
            # Local Logic
            $mems = Get-LocalGroupMember -Group $grp -ErrorAction Stop
            
            # Fix: Simpan ke variabel $output dulu
            $output = foreach ($m in $mems) {
                [PSCustomObject]@{
                    Name   = $m.Name
                    Source = $m.PrincipalSource
                    Status = Get-MemberStatus2 -Member $m
                }
            }
            if ($output) { $output | Format-Table -AutoSize }
        }
    } catch {
        Write-Warning "  Grup '$grp' tidak ditemukan / Kosong."
    }
    Write-Host ""
}
Write-Host "---------------------------------------------------------"

# ITEM 23: User Rights
Write-Host "[ITEM 23] User Rights (Specific)" -ForegroundColor Cyan
$targetRights = @("SeInteractiveLogonRight", "SeNetworkLogonRight", "SeRemoteInteractiveLogonRight", "SeRemoteShutdownPrivilege", "SeBatchLogonRight", "SeTcbPrivilege", "SeServiceLogonRight", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeTakeOwnershipPrivilege")

try {
    $rights = Get-WmiObject -Namespace root\rsop\computer -Query "SELECT UserRight, AccountList FROM RSOP_UserPrivilegeRight" -ErrorAction SilentlyContinue
    if ($rights) { 
        $rights | Where-Object { $targetRights -contains $_.UserRight } | Select UserRight, AccountList | Format-Table -AutoSize 
    } else {
        Write-Warning "RSOP Data Empty."
    }
} catch {}
Write-Host "---------------------------------------------------------"

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "                FULL AUDIT COMPLETED                     " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green