#Requires -Version 3.0
<#
.SYNOPSIS
    Windows Local Privilege Escalation Scanner
.DESCRIPTION
    Guvenlik denetimi icin yerel admin yukseltme yollarini tarar.
    Yalnizca yetkilendirilmis guvenlik testleri icin kullanilmalidir.
.AUTHOR
    Security Audit Tool
#>

param(
    [switch]$ExportHTML,
    [string]$OutputPath = ".\PrivEscReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$Banner = @"
====================================================
  Windows Local Privilege Escalation Scanner
  Guvenlik Denetim Araci
====================================================
"@

$Results = @()

function Write-Finding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Risk,
        [string]$Details
    )

    $color = switch ($Risk) {
        "KRITIK"  { "Red" }
        "YUKSEK"  { "Yellow" }
        "ORTA"    { "Cyan" }
        "DUSUK"   { "Green" }
        default   { "White" }
    }

    Write-Host "`n[$Risk] " -ForegroundColor $color -NoNewline
    Write-Host "$Category - $Finding" -ForegroundColor White
    Write-Host "  Detay: $Details" -ForegroundColor Gray

    $script:Results += [PSCustomObject]@{
        Kategori = $Category
        Bulgu = $Finding
        Risk = $Risk
        Detay = $Details
    }
}

function Test-UnquotedServicePaths {
    Write-Host "`n[*] Tirnaksiz Servis Yollari Kontrol Ediliyor..." -ForegroundColor Cyan

    $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -notlike '"*' -and $_.PathName -like '* *' -and $_.PathName -notlike 'C:\Windows\*' }

    foreach ($svc in $services) {
        $path = $svc.PathName
        Write-Finding -Category "Unquoted Service Path" `
                      -Finding $svc.Name `
                      -Risk "YUKSEK" `
                      -Details "Yol: $path"
    }

    if (-not $services) {
        Write-Host "  [OK] Tirnaksiz servis yolu bulunamadi." -ForegroundColor Green
    }
}

function Test-WeakServicePermissions {
    Write-Host "`n[*] Zayif Servis Izinleri Kontrol Ediliyor..." -ForegroundColor Cyan

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue

    foreach ($svc in $services) {
        if ($svc.PathName) {
            $exePath = $svc.PathName -replace '^"([^"]+)".*', '$1' -replace '^([^\s]+).*', '$1'

            if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                if ($acl) {
                    $writeAccess = $acl.Access | Where-Object {
                        ($_.FileSystemRights -match 'Write|FullControl|Modify') -and
                        ($_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users')
                    }

                    if ($writeAccess) {
                        Write-Finding -Category "Yazilabilir Servis Binary" `
                                      -Finding $svc.Name `
                                      -Risk "KRITIK" `
                                      -Details "Yol: $exePath - Kullanicilar yazabilir"
                    }
                }
            }
        }
    }
}

function Test-AlwaysInstallElevated {
    Write-Host "`n[*] AlwaysInstallElevated Kontrol Ediliyor..." -ForegroundColor Cyan

    $hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

    if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
        Write-Finding -Category "AlwaysInstallElevated" `
                      -Finding "Her iki kayit defteri anahtari da aktif" `
                      -Risk "KRITIK" `
                      -Details "MSI paketleri SYSTEM olarak calistirilabilir"
    } else {
        Write-Host "  [OK] AlwaysInstallElevated aktif degil." -ForegroundColor Green
    }
}

function Test-WritablePATH {
    Write-Host "`n[*] Yazilabilir PATH Dizinleri Kontrol Ediliyor..." -ForegroundColor Cyan

    $pathDirs = $env:PATH -split ';'

    foreach ($dir in $pathDirs) {
        if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
            try {
                $testFile = Join-Path $dir "test_write_$([guid]::NewGuid()).tmp"
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue

                Write-Finding -Category "Yazilabilir PATH Dizini" `
                              -Finding $dir `
                              -Risk "YUKSEK" `
                              -Details "DLL Hijacking icin kullanilabilir"
            } catch {
                # Yazma izni yok, guvenli
            }
        }
    }
}

function Test-StoredCredentials {
    Write-Host "`n[*] Kayitli Kimlik Bilgileri Kontrol Ediliyor..." -ForegroundColor Cyan

    $creds = cmdkey /list 2>$null
    if ($creds -match "Target:") {
        Write-Finding -Category "Kayitli Kimlik Bilgileri" `
                      -Finding "Windows Credential Manager" `
                      -Risk "ORTA" `
                      -Details "Kayitli kimlik bilgileri mevcut"
    }

    # Unattend.xml kontrol
    $unattendPaths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\unattended.xml",
        "C:\Windows\System32\Sysprep\unattend.xml",
        "C:\Windows\System32\Sysprep\Panther\unattend.xml"
    )

    foreach ($path in $unattendPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Unattend.xml Bulundu" `
                          -Finding $path `
                          -Risk "YUKSEK" `
                          -Details "Sifre iceriyor olabilir"
        }
    }
}

function Test-ScheduledTasks {
    Write-Host "`n[*] Zamanlanmis Gorevler Kontrol Ediliyor..." -ForegroundColor Cyan

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Principal.RunLevel -eq 'Highest' -and $_.State -eq 'Ready' }

    foreach ($task in $tasks) {
        $actions = $task.Actions | Where-Object { $_.Execute }
        foreach ($action in $actions) {
            $exePath = $action.Execute
            if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                if ($acl) {
                    $writeAccess = $acl.Access | Where-Object {
                        ($_.FileSystemRights -match 'Write|FullControl|Modify') -and
                        ($_.IdentityReference -match 'Everyone|Users|Authenticated Users')
                    }

                    if ($writeAccess) {
                        Write-Finding -Category "Yazilabilir Zamanli Gorev" `
                                      -Finding $task.TaskName `
                                      -Risk "KRITIK" `
                                      -Details "Yol: $exePath - Yuksek ayricalikla calisiyor"
                    }
                }
            }
        }
    }
}

function Test-TokenPrivileges {
    Write-Host "`n[*] Token Ayricaliklari Kontrol Ediliyor..." -ForegroundColor Cyan

    $privs = whoami /priv 2>$null

    $dangerousPrivs = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege"
    )

    foreach ($priv in $dangerousPrivs) {
        if ($privs -match $priv) {
            Write-Finding -Category "Tehlikeli Token Ayricaligi" `
                          -Finding $priv `
                          -Risk "KRITIK" `
                          -Details "Potato saldirisi veya diger yontemlerle kullanilabilir"
        }
    }
}

function Test-AutoRuns {
    Write-Host "`n[*] AutoRun Konumlari Kontrol Ediliyor..." -ForegroundColor Cyan

    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($regPath in $autorunPaths) {
        if (Test-Path $regPath) {
            $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $exePath = $_.Value -replace '^"([^"]+)".*', '$1' -replace '^([^\s]+).*', '$1'
                if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                    $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                    if ($acl) {
                        $writeAccess = $acl.Access | Where-Object {
                            ($_.FileSystemRights -match 'Write|FullControl|Modify') -and
                            ($_.IdentityReference -match 'Everyone|Users|Authenticated Users')
                        }

                        if ($writeAccess) {
                            Write-Finding -Category "Yazilabilir AutoRun" `
                                          -Finding $_.Name `
                                          -Risk "YUKSEK" `
                                          -Details "Yol: $exePath"
                        }
                    }
                }
            }
        }
    }
}

function Test-UACSettings {
    Write-Host "`n[*] UAC Ayarlari Kontrol Ediliyor..." -ForegroundColor Cyan

    $uacKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue

    if ($uacKey.EnableLUA -eq 0) {
        Write-Finding -Category "UAC Devre Disi" `
                      -Finding "EnableLUA = 0" `
                      -Risk "KRITIK" `
                      -Details "UAC tamamen devre disi"
    }

    if ($uacKey.ConsentPromptBehaviorAdmin -eq 0) {
        Write-Finding -Category "UAC Zayif Yapilandirma" `
                      -Finding "ConsentPromptBehaviorAdmin = 0" `
                      -Risk "YUKSEK" `
                      -Details "Admin onaysiz yukseltme yapabilir"
    }
}

function Test-WSL {
    Write-Host "`n[*] WSL Kontrol Ediliyor..." -ForegroundColor Cyan

    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        Write-Finding -Category "WSL Yuklu" `
                      -Finding "Windows Subsystem for Linux" `
                      -Risk "ORTA" `
                      -Details "WSL uzerinden pivot yapilabilir"
    }
}

function Test-InstalledSoftware {
    Write-Host "`n[*] Savunmasiz Yazilimlar Kontrol Ediliyor..." -ForegroundColor Cyan

    $software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion

    $vulnerablePatterns = @(
        @{Name="FileZilla"; Pattern="FileZilla"},
        @{Name="WinSCP"; Pattern="WinSCP"},
        @{Name="PuTTY"; Pattern="PuTTY"},
        @{Name="TeamViewer"; Pattern="TeamViewer"},
        @{Name="VNC"; Pattern="VNC"}
    )

    foreach ($vuln in $vulnerablePatterns) {
        $found = $software | Where-Object { $_.DisplayName -match $vuln.Pattern }
        if ($found) {
            Write-Finding -Category "Potansiyel Hedef Yazilim" `
                          -Finding $found.DisplayName `
                          -Risk "DUSUK" `
                          -Details "Versiyon: $($found.DisplayVersion) - Kayitli kimlik bilgileri olabilir"
        }
    }
}

function Test-AutoLogon {
    Write-Host "`n[*] AutoLogon Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue

    if ($winlogon.DefaultPassword) {
        Write-Finding -Category "AutoLogon Credentials" `
                      -Finding "DefaultPassword Mevcut" `
                      -Risk "KRITIK" `
                      -Details "Kullanici: $($winlogon.DefaultUserName) Domain: $($winlogon.DefaultDomainName) Sifre: $($winlogon.DefaultPassword)"
    }

    if ($winlogon.AutoAdminLogon -eq "1") {
        Write-Finding -Category "AutoLogon Aktif" `
                      -Finding "AutoAdminLogon = 1" `
                      -Risk "YUKSEK" `
                      -Details "Kullanici: $($winlogon.DefaultUserName)"
    }

    # LSA Secrets'ta sakli olabilir
    $lsaPath = "HKLM:\SECURITY\Policy\Secrets\DefaultPassword"
    if (Test-Path $lsaPath -ErrorAction SilentlyContinue) {
        Write-Finding -Category "LSA Secret AutoLogon" `
                      -Finding "DefaultPassword LSA Secret" `
                      -Risk "YUKSEK" `
                      -Details "LSA Secrets'ta sifre sakli olabilir"
    }
}

function Test-PowerShellHistory {
    Write-Host "`n[*] PowerShell History Kontrol Ediliyor..." -ForegroundColor Cyan

    $historyPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )

    # Tum kullanicilar icin kontrol
    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($user in $userFolders) {
        $historyPaths += "$($user.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }

    foreach ($path in $historyPaths | Select-Object -Unique) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $content = Get-Content $path -ErrorAction SilentlyContinue | Select-Object -Last 50
            $sensitivePatterns = $content | Where-Object { $_ -match '(password|credential|secret|key|token|apikey|pwd|pass)' }

            if ($sensitivePatterns) {
                Write-Finding -Category "PowerShell History" `
                              -Finding $path `
                              -Risk "YUKSEK" `
                              -Details "Hassas veri iceriyor olabilir: $($sensitivePatterns | Select-Object -First 3)"
            } else {
                Write-Finding -Category "PowerShell History" `
                              -Finding $path `
                              -Risk "ORTA" `
                              -Details "History dosyasi mevcut, incelenmeli"
            }
        }
    }
}

function Test-PuttySSH {
    Write-Host "`n[*] Putty Sessions ve SSH Keys Kontrol Ediliyor..." -ForegroundColor Cyan

    # Putty Sessions
    $puttySessions = Get-ChildItem "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
    foreach ($session in $puttySessions) {
        $sessionData = Get-ItemProperty $session.PSPath -ErrorAction SilentlyContinue
        Write-Finding -Category "Putty Session" `
                      -Finding $session.PSChildName `
                      -Risk "ORTA" `
                      -Details "Host: $($sessionData.HostName) User: $($sessionData.UserName)"
    }

    # Putty SSH Host Keys
    $puttyKeys = Get-ItemProperty "HKCU:\SOFTWARE\SimonTatham\PuTTY\SshHostKeys" -ErrorAction SilentlyContinue
    if ($puttyKeys) {
        Write-Finding -Category "Putty SSH Host Keys" `
                      -Finding "Kayitli Host Keys Mevcut" `
                      -Risk "DUSUK" `
                      -Details "Baglanti gecmisi mevcut"
    }

    # SSH Private Keys
    $sshPaths = @(
        "$env:USERPROFILE\.ssh\id_rsa",
        "$env:USERPROFILE\.ssh\id_dsa",
        "$env:USERPROFILE\.ssh\id_ecdsa",
        "$env:USERPROFILE\.ssh\id_ed25519"
    )

    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($user in $userFolders) {
        $sshPaths += "$($user.FullName)\.ssh\id_rsa"
        $sshPaths += "$($user.FullName)\.ssh\id_dsa"
        $sshPaths += "$($user.FullName)\.ssh\id_ecdsa"
        $sshPaths += "$($user.FullName)\.ssh\id_ed25519"
    }

    foreach ($path in $sshPaths | Select-Object -Unique) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Finding -Category "SSH Private Key" `
                          -Finding $path `
                          -Risk "KRITIK" `
                          -Details "Private key dosyasi bulundu"
        }
    }
}

function Test-WinSCP {
    Write-Host "`n[*] WinSCP Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    # Registry'den
    $winscpSessions = Get-ChildItem "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue
    foreach ($session in $winscpSessions) {
        $sessionData = Get-ItemProperty $session.PSPath -ErrorAction SilentlyContinue
        if ($sessionData.HostName) {
            Write-Finding -Category "WinSCP Session" `
                          -Finding $session.PSChildName `
                          -Risk "YUKSEK" `
                          -Details "Host: $($sessionData.HostName) User: $($sessionData.UserName) Password: $($sessionData.Password)"
        }
    }

    # WinSCP.ini dosyasi
    $winscpIni = @(
        "$env:APPDATA\WinSCP.ini",
        "C:\Program Files\WinSCP\WinSCP.ini",
        "C:\Program Files (x86)\WinSCP\WinSCP.ini"
    )

    foreach ($path in $winscpIni) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Finding -Category "WinSCP Config" `
                          -Finding $path `
                          -Risk "YUKSEK" `
                          -Details "WinSCP yapilandirma dosyasi - sifreler iceriyor olabilir"
        }
    }
}

function Test-BrowserCredentials {
    Write-Host "`n[*] Browser Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($user in $userFolders) {
        # Chrome
        $chromePath = "$($user.FullName)\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        if (Test-Path $chromePath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Chrome Credentials" `
                          -Finding $chromePath `
                          -Risk "YUKSEK" `
                          -Details "Chrome kayitli sifreler mevcut (DPAPI ile sifrelenmis)"
        }

        # Chrome Cookies
        $chromeCookies = "$($user.FullName)\AppData\Local\Google\Chrome\User Data\Default\Cookies"
        if (Test-Path $chromeCookies -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Chrome Cookies" `
                          -Finding $chromeCookies `
                          -Risk "ORTA" `
                          -Details "Chrome cookies - session hijacking icin kullanilabilir"
        }

        # Edge
        $edgePath = "$($user.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
        if (Test-Path $edgePath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Edge Credentials" `
                          -Finding $edgePath `
                          -Risk "YUKSEK" `
                          -Details "Edge kayitli sifreler mevcut (DPAPI ile sifrelenmis)"
        }

        # Firefox
        $firefoxProfiles = "$($user.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfiles -ErrorAction SilentlyContinue) {
            $profiles = Get-ChildItem $firefoxProfiles -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $loginsJson = "$($profile.FullName)\logins.json"
                $keyDb = "$($profile.FullName)\key4.db"
                if ((Test-Path $loginsJson) -or (Test-Path $keyDb)) {
                    Write-Finding -Category "Firefox Credentials" `
                                  -Finding $profile.FullName `
                                  -Risk "YUKSEK" `
                                  -Details "Firefox kayitli sifreler mevcut"
                }
            }
        }
    }
}

function Test-WifiPasswords {
    Write-Host "`n[*] Wifi Passwords Kontrol Ediliyor..." -ForegroundColor Cyan

    $profiles = netsh wlan show profiles 2>$null
    if ($profiles -match "All User Profile") {
        $profileNames = $profiles | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

        foreach ($name in $profileNames) {
            $detail = netsh wlan show profile name="$name" key=clear 2>$null
            $keyContent = $detail | Select-String "Key Content\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

            if ($keyContent) {
                Write-Finding -Category "Wifi Password" `
                              -Finding $name `
                              -Risk "ORTA" `
                              -Details "Sifre: $keyContent"
            }
        }
    }
}

function Test-VNCPasswords {
    Write-Host "`n[*] VNC Passwords Kontrol Ediliyor..." -ForegroundColor Cyan

    $vncPaths = @(
        "HKCU:\SOFTWARE\RealVNC\WinVNC4",
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKCU:\SOFTWARE\TightVNC\Server",
        "HKLM:\SOFTWARE\TightVNC\Server",
        "HKCU:\SOFTWARE\ORL\WinVNC3\Default",
        "HKLM:\SOFTWARE\ORL\WinVNC3\Default",
        "HKCU:\SOFTWARE\ORL\WinVNC\Default",
        "HKLM:\SOFTWARE\ORL\WinVNC\Default"
    )

    foreach ($path in $vncPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $vncData = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if ($vncData.Password -or $vncData.PasswordViewOnly) {
                Write-Finding -Category "VNC Password" `
                              -Finding $path `
                              -Risk "YUKSEK" `
                              -Details "Sifrelenmis VNC sifresi mevcut (kolayca cozulebilir)"
            }
        }
    }

    # UltraVNC
    $ultraVncIni = @(
        "C:\Program Files\UltraVNC\ultravnc.ini",
        "C:\Program Files (x86)\UltraVNC\ultravnc.ini"
    )

    foreach ($path in $ultraVncIni) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Finding -Category "UltraVNC Config" `
                          -Finding $path `
                          -Risk "YUKSEK" `
                          -Details "UltraVNC yapilandirma dosyasi"
        }
    }
}

function Test-MRemoteNG {
    Write-Host "`n[*] MRemoteNG Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($user in $userFolders) {
        $confPath = "$($user.FullName)\AppData\Roaming\mRemoteNG\confCons.xml"
        if (Test-Path $confPath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "mRemoteNG Config" `
                          -Finding $confPath `
                          -Risk "KRITIK" `
                          -Details "mRemoteNG baglanti dosyasi - sifreler AES ile sifrelenmis (varsayilan key ile cozulebilir)"
        }
    }
}

function Test-RDPCredentials {
    Write-Host "`n[*] RDP Saved Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    # RDP dosyalari
    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($user in $userFolders) {
        # Documents ve Desktop'ta .rdp dosyalari
        $rdpFiles = Get-ChildItem "$($user.FullName)\Documents\*.rdp" -ErrorAction SilentlyContinue
        $rdpFiles += Get-ChildItem "$($user.FullName)\Desktop\*.rdp" -ErrorAction SilentlyContinue

        foreach ($rdp in $rdpFiles) {
            $content = Get-Content $rdp.FullName -ErrorAction SilentlyContinue
            if ($content -match "password 51:") {
                Write-Finding -Category "RDP File with Password" `
                              -Finding $rdp.FullName `
                              -Risk "YUKSEK" `
                              -Details "RDP dosyasinda sifrelenmis sifre mevcut"
            } else {
                Write-Finding -Category "RDP File" `
                              -Finding $rdp.FullName `
                              -Risk "DUSUK" `
                              -Details "RDP baglanti dosyasi"
            }
        }
    }

    # Credential Manager RDP entries
    $rdpCreds = cmdkey /list 2>$null | Select-String "TERMSRV"
    if ($rdpCreds) {
        Write-Finding -Category "RDP Cached Credentials" `
                      -Finding "Credential Manager" `
                      -Risk "ORTA" `
                      -Details "Kayitli RDP kimlikleri: $($rdpCreds -join ', ')"
    }
}

function Test-GPPPasswords {
    Write-Host "`n[*] GPP Passwords Kontrol Ediliyor..." -ForegroundColor Cyan

    # Domain'e bagli mi kontrol et
    if ($env:USERDOMAIN -eq $env:COMPUTERNAME) {
        Write-Host "  [SKIP] Domain'e bagli degil, GPP kontrolu atlanıyor." -ForegroundColor Gray
        return
    }

    # SYSVOL yolunu olustur
    $domainDNS = $env:USERDNSDOMAIN
    if (-not $domainDNS) {
        Write-Host "  [SKIP] Domain DNS bulunamadi." -ForegroundColor Gray
        return
    }

    $sysvolPath = "\\$domainDNS\SYSVOL\$domainDNS\Policies"

    # Hizli baglanti testi (2 saniye timeout)
    Write-Host "  SYSVOL erisim testi: $sysvolPath" -ForegroundColor Gray
    $testJob = Start-Job -ScriptBlock { param($p) Test-Path $p } -ArgumentList $sysvolPath
    $completed = Wait-Job $testJob -Timeout 3

    if (-not $completed) {
        Stop-Job $testJob
        Remove-Job $testJob -Force
        Write-Host "  [TIMEOUT] SYSVOL erisilemedi (3s timeout)." -ForegroundColor Yellow
        return
    }

    $accessible = Receive-Job $testJob
    Remove-Job $testJob -Force

    if (-not $accessible) {
        Write-Host "  [SKIP] SYSVOL erisilemedi." -ForegroundColor Gray
        return
    }

    # Sadece Policies klasorunde ara (daha hizli)
    $gppFiles = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")

    # Depth 4 ile sinirla (cok derin aramadan kacin)
    $xmlFiles = Get-ChildItem $sysvolPath -Recurse -Depth 4 -Include $gppFiles -ErrorAction SilentlyContinue | Select-Object -First 50

    foreach ($file in $xmlFiles) {
        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue -First 100
        if ($content -match "cpassword=") {
            Write-Finding -Category "GPP Password" `
                          -Finding $file.FullName `
                          -Risk "KRITIK" `
                          -Details "cpassword alani mevcut - AES key bilinen, kolayca cozulebilir"
        }
    }
}

function Test-McAfeeSiteList {
    Write-Host "`n[*] McAfee SiteList.xml Kontrol Ediliyor..." -ForegroundColor Cyan

    $mcafeePaths = @(
        "C:\ProgramData\McAfee\Common Framework\SiteList.xml",
        "C:\Program Files\McAfee\Common Framework\SiteList.xml",
        "C:\Program Files (x86)\McAfee\Common Framework\SiteList.xml"
    )

    foreach ($path in $mcafeePaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            Write-Finding -Category "McAfee SiteList" `
                          -Finding $path `
                          -Risk "YUKSEK" `
                          -Details "McAfee yapilandirmasi - sifrelenmis sifreler iceriyor olabilir"
        }
    }
}

function Test-CloudCredentials {
    Write-Host "`n[*] Cloud Credentials Kontrol Ediliyor..." -ForegroundColor Cyan

    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($user in $userFolders) {
        # AWS
        $awsPath = "$($user.FullName)\.aws\credentials"
        if (Test-Path $awsPath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "AWS Credentials" `
                          -Finding $awsPath `
                          -Risk "KRITIK" `
                          -Details "AWS access key ve secret key iceriyor olabilir"
        }

        $awsConfig = "$($user.FullName)\.aws\config"
        if (Test-Path $awsConfig -ErrorAction SilentlyContinue) {
            Write-Finding -Category "AWS Config" `
                          -Finding $awsConfig `
                          -Risk "ORTA" `
                          -Details "AWS yapilandirmasi"
        }

        # Azure
        $azurePath = "$($user.FullName)\.azure\accessTokens.json"
        if (Test-Path $azurePath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Azure Tokens" `
                          -Finding $azurePath `
                          -Risk "KRITIK" `
                          -Details "Azure access token'lari"
        }

        $azureProfile = "$($user.FullName)\.azure\azureProfile.json"
        if (Test-Path $azureProfile -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Azure Profile" `
                          -Finding $azureProfile `
                          -Risk "ORTA" `
                          -Details "Azure profil bilgileri"
        }

        # GCP
        $gcpPath = "$($user.FullName)\.config\gcloud\credentials.db"
        if (Test-Path $gcpPath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "GCP Credentials" `
                          -Finding $gcpPath `
                          -Risk "KRITIK" `
                          -Details "Google Cloud credentials"
        }

        $gcpAccessTokens = "$($user.FullName)\.config\gcloud\access_tokens.db"
        if (Test-Path $gcpAccessTokens -ErrorAction SilentlyContinue) {
            Write-Finding -Category "GCP Access Tokens" `
                          -Finding $gcpAccessTokens `
                          -Risk "KRITIK" `
                          -Details "Google Cloud access token'lari"
        }

        # Kubernetes
        $kubePath = "$($user.FullName)\.kube\config"
        if (Test-Path $kubePath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Kubernetes Config" `
                          -Finding $kubePath `
                          -Risk "YUKSEK" `
                          -Details "Kubernetes cluster credentials"
        }

        # Docker
        $dockerConfig = "$($user.FullName)\.docker\config.json"
        if (Test-Path $dockerConfig -ErrorAction SilentlyContinue) {
            $content = Get-Content $dockerConfig -ErrorAction SilentlyContinue
            if ($content -match '"auth"') {
                Write-Finding -Category "Docker Registry Auth" `
                              -Finding $dockerConfig `
                              -Risk "YUKSEK" `
                              -Details "Docker registry credentials (base64 encoded)"
            }
        }
    }
}

function Test-IISWebConfig {
    Write-Host "`n[*] IIS web.config Kontrol Ediliyor..." -ForegroundColor Cyan

    $inetpubPath = "C:\inetpub\wwwroot"

    if (Test-Path $inetpubPath -ErrorAction SilentlyContinue) {
        $webConfigs = Get-ChildItem $inetpubPath -Recurse -Include "web.config","applicationHost.config" -ErrorAction SilentlyContinue

        foreach ($config in $webConfigs) {
            $content = Get-Content $config.FullName -ErrorAction SilentlyContinue
            if ($content -match "(connectionString|password|pwd|credentials)") {
                Write-Finding -Category "IIS Web.config" `
                              -Finding $config.FullName `
                              -Risk "KRITIK" `
                              -Details "Connection string veya credentials iceriyor olabilir"
            }
        }
    }

    # Machine-wide config
    $machineConfig = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config"
    if (Test-Path $machineConfig -ErrorAction SilentlyContinue) {
        Write-Finding -Category "Machine Web.config" `
                      -Finding $machineConfig `
                      -Risk "ORTA" `
                      -Details ".NET Framework yapilandirmasi"
    }

    # applicationHost.config
    $appHostConfig = "C:\Windows\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHostConfig -ErrorAction SilentlyContinue) {
        $content = Get-Content $appHostConfig -ErrorAction SilentlyContinue
        if ($content -match "(password|credentials)") {
            Write-Finding -Category "IIS applicationHost.config" `
                          -Finding $appHostConfig `
                          -Risk "YUKSEK" `
                          -Details "IIS ana yapilandirmasi - credentials iceriyor olabilir"
        }
    }
}

function Test-DPAPICredentials {
    Write-Host "`n[*] DPAPI Credential Files Kontrol Ediliyor..." -ForegroundColor Cyan

    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($user in $userFolders) {
        # Credential files
        $credPath = "$($user.FullName)\AppData\Local\Microsoft\Credentials"
        if (Test-Path $credPath -ErrorAction SilentlyContinue) {
            $creds = Get-ChildItem $credPath -ErrorAction SilentlyContinue
            if ($creds) {
                Write-Finding -Category "DPAPI Credentials" `
                              -Finding $credPath `
                              -Risk "YUKSEK" `
                              -Details "DPAPI ile sifrelenmis kimlik bilgileri: $($creds.Count) dosya"
            }
        }

        # Roaming credentials
        $credRoaming = "$($user.FullName)\AppData\Roaming\Microsoft\Credentials"
        if (Test-Path $credRoaming -ErrorAction SilentlyContinue) {
            $creds = Get-ChildItem $credRoaming -ErrorAction SilentlyContinue
            if ($creds) {
                Write-Finding -Category "DPAPI Roaming Credentials" `
                              -Finding $credRoaming `
                              -Risk "YUKSEK" `
                              -Details "Roaming credentials: $($creds.Count) dosya"
            }
        }

        # Vault
        $vaultPath = "$($user.FullName)\AppData\Local\Microsoft\Vault"
        if (Test-Path $vaultPath -ErrorAction SilentlyContinue) {
            Write-Finding -Category "Windows Vault" `
                          -Finding $vaultPath `
                          -Risk "ORTA" `
                          -Details "Windows Vault - web credentials iceriyor olabilir"
        }

        # DPAPI Master Keys
        $masterKeys = "$($user.FullName)\AppData\Roaming\Microsoft\Protect"
        if (Test-Path $masterKeys -ErrorAction SilentlyContinue) {
            Write-Finding -Category "DPAPI Master Keys" `
                          -Finding $masterKeys `
                          -Risk "ORTA" `
                          -Details "DPAPI master keys - credential decryption icin gerekli"
        }
    }

    # System credentials
    $systemCreds = "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials"
    if (Test-Path $systemCreds -ErrorAction SilentlyContinue) {
        Write-Finding -Category "System DPAPI Credentials" `
                      -Finding $systemCreds `
                      -Risk "YUKSEK" `
                      -Details "System account credentials"
    }
}

function Test-KerberosTickets {
    Write-Host "`n[*] Kerberos Tickets Kontrol Ediliyor..." -ForegroundColor Cyan

    $tickets = klist 2>$null
    if ($tickets -match "Cached Tickets:") {
        $ticketCount = ($tickets | Select-String "Server:").Count
        if ($ticketCount -gt 0) {
            Write-Finding -Category "Kerberos Tickets" `
                          -Finding "Cached Tickets Mevcut" `
                          -Risk "ORTA" `
                          -Details "$ticketCount adet ticket cached - pass-the-ticket icin kullanilabilir"
        }

        # TGT kontrolu
        if ($tickets -match "krbtgt") {
            Write-Finding -Category "Kerberos TGT" `
                          -Finding "TGT Mevcut" `
                          -Risk "YUKSEK" `
                          -Details "Ticket Granting Ticket - golden ticket saldirisi icin degerli"
        }
    }

    # Kerberoastable services
    $kerberoast = klist 2>$null | Select-String "Service:"
    if ($kerberoast) {
        Write-Finding -Category "Kerberos Services" `
                      -Finding "Service Tickets" `
                      -Risk "ORTA" `
                      -Details "Kerberoasting icin hedef olabilir"
    }
}

function Test-LAPS {
    Write-Host "`n[*] LAPS Password Kontrol Ediliyor..." -ForegroundColor Cyan

    # LAPS yuklu mu?
    $lapsInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -match "Local Administrator Password Solution" }

    if ($lapsInstalled) {
        Write-Finding -Category "LAPS Installed" `
                      -Finding "LAPS Mevcut" `
                      -Risk "DUSUK" `
                      -Details "LAPS yuklu - AD'den sifre okunabilir mi kontrol edilmeli"

        # LAPS PowerShell module
        if (Get-Module -ListAvailable -Name AdmPwd.PS -ErrorAction SilentlyContinue) {
            try {
                Import-Module AdmPwd.PS -ErrorAction SilentlyContinue
                $computerName = $env:COMPUTERNAME
                $lapsPassword = Get-AdmPwdPassword -ComputerName $computerName -ErrorAction SilentlyContinue

                if ($lapsPassword.Password) {
                    Write-Finding -Category "LAPS Password" `
                                  -Finding "LAPS Sifresi Okunabilir" `
                                  -Risk "KRITIK" `
                                  -Details "Local Admin sifresi: $($lapsPassword.Password)"
                }
            } catch {
                # Okuma yetkisi yok
            }
        }
    }

    # LAPS attributes okunabilir mi (AD'ye bagli ise)
    if ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
        Write-Finding -Category "LAPS Check" `
                      -Finding "Domain Joined" `
                      -Risk "DUSUK" `
                      -Details "Domain'e bagli - LAPS ms-Mcs-AdmPwd attribute kontrol edilmeli"
    }
}

function Test-SAMBackup {
    Write-Host "`n[*] SAM/SYSTEM Backup Dosyalari Kontrol Ediliyor..." -ForegroundColor Cyan

    # Bilinen backup lokasyonlari
    $samPaths = @(
        "C:\Windows\Repair\SAM",
        "C:\Windows\Repair\SYSTEM",
        "C:\Windows\Repair\SECURITY",
        "C:\Windows\System32\config\RegBack\SAM",
        "C:\Windows\System32\config\RegBack\SYSTEM",
        "C:\Windows\System32\config\RegBack\SECURITY"
    )

    foreach ($path in $samPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            $readable = $false
            try {
                $null = Get-Content $path -First 1 -ErrorAction Stop
                $readable = $true
            } catch { }

            if ($readable) {
                Write-Finding -Category "SAM/SYSTEM Backup" `
                              -Finding $path `
                              -Risk "KRITIK" `
                              -Details "Okunabilir! Hash dump yapilabilir (secretsdump.py)"
            } else {
                Write-Finding -Category "SAM/SYSTEM Backup" `
                              -Finding $path `
                              -Risk "ORTA" `
                              -Details "Dosya mevcut ama okunamiyor"
            }
        }
    }

    # Shadow Copy kontrolu (HiveNightmare/SeriousSAM - CVE-2021-36934)
    $shadowCopies = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($shadowCopies) {
        foreach ($shadow in $shadowCopies) {
            $shadowPath = $shadow.DeviceObject + "\Windows\System32\config\SAM"
            # Shadow copy'ye erisim testi
            $testPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM"
            if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                Write-Finding -Category "HiveNightmare (CVE-2021-36934)" `
                              -Finding "Shadow Copy SAM Erisilebilir" `
                              -Risk "KRITIK" `
                              -Details "Shadow Copy uzerinden SAM/SYSTEM okunabilir - hash dump mumkun"
            }
        }
    }
}

function Test-StartupFolders {
    Write-Host "`n[*] Startup Folder Yazma Izinleri Kontrol Ediliyor..." -ForegroundColor Cyan

    # Kullanici startup
    $userStartup = [Environment]::GetFolderPath('Startup')
    if ($userStartup -and (Test-Path $userStartup)) {
        try {
            $testFile = Join-Path $userStartup "test_$([guid]::NewGuid()).tmp"
            [IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            Write-Finding -Category "User Startup Folder" `
                          -Finding $userStartup `
                          -Risk "ORTA" `
                          -Details "Kullanici startup klasorune yazilabilir (kendi oturumu icin)"
        } catch { }
    }

    # Tum kullanicilar startup (All Users)
    $commonStartup = [Environment]::GetFolderPath('CommonStartup')
    if (-not $commonStartup) {
        $commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    }

    if (Test-Path $commonStartup -ErrorAction SilentlyContinue) {
        try {
            $testFile = Join-Path $commonStartup "test_$([guid]::NewGuid()).tmp"
            [IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            Write-Finding -Category "Common Startup Folder" `
                          -Finding $commonStartup `
                          -Risk "KRITIK" `
                          -Details "Tum kullanicilar icin startup klasorune yazilabilir - persistence icin ideal"
        } catch { }
    }

    # Diger kullanicilarin startup klasorleri
    $userFolders = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($user in $userFolders) {
        if ($user.Name -notin @("Public", "Default", "Default User", "All Users")) {
            $otherStartup = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            if (Test-Path $otherStartup -ErrorAction SilentlyContinue) {
                try {
                    $testFile = Join-Path $otherStartup "test_$([guid]::NewGuid()).tmp"
                    [IO.File]::WriteAllText($testFile, "test")
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    Write-Finding -Category "Other User Startup" `
                                  -Finding $otherStartup `
                                  -Risk "YUKSEK" `
                                  -Details "Baska kullanicinin startup klasorune yazilabilir"
                } catch { }
            }
        }
    }
}

function Test-KernelExploits {
    Write-Host "`n[*] Kernel Exploit Uygunlugu Kontrol Ediliyor..." -ForegroundColor Cyan

    $os = Get-WmiObject -Class Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    $version = $os.Version
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID

    $vulnerabilities = @()

    # Windows 10/11 ve Server 2016+ icin kontroller

    # PrintNightmare (CVE-2021-34527) - Build < 19041.1083 veya patch yok
    if ($build -lt 19041 -or ($hotfixes -notcontains "KB5004945" -and $hotfixes -notcontains "KB5004946" -and $hotfixes -notcontains "KB5004947")) {
        # Spooler servisi calisiyorsa
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spooler.Status -eq "Running") {
            $vulnerabilities += @{
                Name = "PrintNightmare (CVE-2021-34527)"
                Risk = "KRITIK"
                Details = "Print Spooler calisyor ve patch eksik olabilir - RCE/LPE mumkun"
            }
        }
    }

    # HiveNightmare/SeriousSAM (CVE-2021-36934) - Build 18362-19043
    if ($build -ge 18362 -and $build -le 19044) {
        if ($hotfixes -notcontains "KB5004476" -and $hotfixes -notcontains "KB5005565") {
            $vulnerabilities += @{
                Name = "HiveNightmare (CVE-2021-36934)"
                Risk = "KRITIK"
                Details = "SAM/SYSTEM Shadow Copy uzerinden okunabilir - hash dump mumkun"
            }
        }
    }

    # EternalBlue (MS17-010) - Eski sistemler
    if ($build -lt 15063) {
        if ($hotfixes -notcontains "KB4012212" -and $hotfixes -notcontains "KB4012215" -and $hotfixes -notcontains "KB4013429") {
            $vulnerabilities += @{
                Name = "EternalBlue (MS17-010)"
                Risk = "KRITIK"
                Details = "SMBv1 exploit - RCE mumkun"
            }
        }
    }

    # ZeroLogon (CVE-2020-1472) - Domain Controller ise
    $dcRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($dcRole -ge 4) {
        if ($hotfixes -notcontains "KB4565349" -and $hotfixes -notcontains "KB4566782") {
            $vulnerabilities += @{
                Name = "ZeroLogon (CVE-2020-1472)"
                Risk = "KRITIK"
                Details = "Domain Controller - Netlogon exploit ile domain admin alinabilir"
            }
        }
    }

    # PetitPotam - AD CS varsa
    $adcs = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($adcs) {
        $vulnerabilities += @{
            Name = "PetitPotam (AD CS)"
            Risk = "YUKSEK"
            Details = "AD CS servisi mevcut - NTLM relay ile domain admin mumkun"
        }
    }

    # Local Potato (CVE-2023-21746)
    if ($build -lt 22621) {
        $vulnerabilities += @{
            Name = "LocalPotato (CVE-2023-21746)"
            Risk = "YUKSEK"
            Details = "NTLM local relay - SeImpersonate olmadan LPE mumkun olabilir"
        }
    }

    # SpoolFool (CVE-2022-21999)
    if ($build -lt 19044) {
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spooler.Status -eq "Running") {
            $vulnerabilities += @{
                Name = "SpoolFool (CVE-2022-21999)"
                Risk = "YUKSEK"
                Details = "Print Spooler LPE - arbitrary file write"
            }
        }
    }

    # Sonuclari raporla
    foreach ($vuln in $vulnerabilities) {
        Write-Finding -Category "Kernel Exploit" `
                      -Finding $vuln.Name `
                      -Risk $vuln.Risk `
                      -Details $vuln.Details
    }

    if ($vulnerabilities.Count -eq 0) {
        Write-Host "  [OK] Bilinen kritik kernel exploit bulunamadi." -ForegroundColor Green
    }

    # Build bilgisi
    Write-Finding -Category "Windows Build" `
                  -Finding "Build $build" `
                  -Risk "DUSUK" `
                  -Details "Version: $version - searchsploit veya exploit-db'de aranabilir"
}

function Test-AVDetection {
    Write-Host "`n[*] AV/EDR Tespiti Yapiliyor..." -ForegroundColor Cyan

    $avProducts = @()

    # WMI ile AV kontrolu
    $avWmi = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
    foreach ($av in $avWmi) {
        $avProducts += @{
            Name = $av.displayName
            Path = $av.pathToSignedProductExe
            State = $av.productState
        }
    }

    # Bilinen AV/EDR process'leri
    $avProcesses = @{
        "MsMpEng" = "Windows Defender"
        "MsSense" = "Windows Defender ATP/EDR"
        "SenseIR" = "Windows Defender ATP"
        "csfalconservice" = "CrowdStrike Falcon"
        "CSFalconContainer" = "CrowdStrike Falcon"
        "cb" = "Carbon Black"
        "CbDefense" = "Carbon Black Defense"
        "CylanceSvc" = "Cylance"
        "CylanceUI" = "Cylance"
        "SentinelAgent" = "SentinelOne"
        "SentinelServiceHost" = "SentinelOne"
        "cortex" = "Palo Alto Cortex XDR"
        "Traps" = "Palo Alto Traps"
        "xagt" = "FireEye Endpoint Agent"
        "taniumclient" = "Tanium"
        "nessusd" = "Tenable Nessus"
        "DVPAPI" = "Trend Micro"
        "ds_agent" = "Trend Micro Deep Security"
        "coreServiceShell" = "Trend Micro"
        "mcshield" = "McAfee"
        "mfetp" = "McAfee ENS"
        "mfemms" = "McAfee"
        "avp" = "Kaspersky"
        "kavfs" = "Kaspersky"
        "bdagent" = "Bitdefender"
        "bdservicehost" = "Bitdefender"
        "epag" = "Bitdefender GravityZone"
        "SophosHealth" = "Sophos"
        "SophosUI" = "Sophos"
        "savservice" = "Sophos"
        "SEDService" = "Symantec/Broadcom"
        "ccSvcHst" = "Symantec/Broadcom"
        "WRSA" = "Webroot"
        "ERAAgent" = "ESET"
        "ekrn" = "ESET"
        "egui" = "ESET"
        "SUMService" = "Avast"
        "AvastSvc" = "Avast"
        "avgnt" = "Avira"
        "avscan" = "Avira"
        "fortiedr" = "FortiEDR"
        "elastic-agent" = "Elastic EDR"
        "elastic-endpoint" = "Elastic EDR"
        "filebeat" = "Elastic (SIEM)"
        "winlogbeat" = "Elastic (SIEM)"
        "osqueryd" = "OSQuery"
        "splunkd" = "Splunk (SIEM)"
        "nxlog" = "NXLog (SIEM)"
    }

    $runningAV = @()
    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $avProcesses.Keys) {
        if ($processes.Name -contains $proc) {
            $runningAV += $avProcesses[$proc]
        }
    }

    # Bilinen AV servisleri
    $avServices = @{
        "WinDefend" = "Windows Defender"
        "Sense" = "Windows Defender ATP"
        "CSFalconService" = "CrowdStrike"
        "CbDefense" = "Carbon Black"
        "CylanceSvc" = "Cylance"
        "SentinelAgent" = "SentinelOne"
        "CortexXDR" = "Palo Alto Cortex"
        "xagt" = "FireEye"
        "TaniumClient" = "Tanium"
        "mfefire" = "McAfee"
        "McShield" = "McAfee"
        "AVP" = "Kaspersky"
        "SAVService" = "Sophos"
        "SepMasterService" = "Symantec"
    }

    foreach ($svc in $avServices.Keys) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            if ($runningAV -notcontains $avServices[$svc]) {
                $runningAV += $avServices[$svc]
            }
        }
    }

    # Raporla
    $runningAV = $runningAV | Select-Object -Unique

    if ($runningAV.Count -gt 0) {
        foreach ($av in $runningAV) {
            $risk = "ORTA"
            if ($av -match "ATP|EDR|Falcon|SentinelOne|Cortex|Carbon Black") {
                $risk = "YUKSEK"
            }
            Write-Finding -Category "AV/EDR Detected" `
                          -Finding $av `
                          -Risk $risk `
                          -Details "Aktif koruma mevcut - bypass gerekebilir"
        }
    } else {
        Write-Finding -Category "AV/EDR" `
                      -Finding "AV/EDR Tespit Edilemedi" `
                      -Risk "DUSUK" `
                      -Details "Bilinen AV/EDR process'i bulunamadi"
    }

    # AMSI durumu
    try {
        $amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($amsi) {
            Write-Finding -Category "AMSI" `
                          -Finding "AMSI Aktif" `
                          -Risk "ORTA" `
                          -Details "PowerShell AMSI korumasi aktif - bypass gerekebilir"
        }
    } catch { }

    # Constrained Language Mode
    if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
        Write-Finding -Category "PowerShell CLM" `
                      -Finding "Constrained Language Mode" `
                      -Risk "YUKSEK" `
                      -Details "PowerShell kisitli modda - .NET ve bazi cmdlet'ler kullanamaz"
    }

    # AppLocker
    $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if ($applockerPolicy -and $applockerPolicy.RuleCollections.Count -gt 0) {
        Write-Finding -Category "AppLocker" `
                      -Finding "AppLocker Aktif" `
                      -Risk "YUKSEK" `
                      -Details "Uygulama whitelist'i mevcut - bypass gerekebilir"
    }
}

function Test-PotatoAttacks {
    Write-Host "`n[*] Potato Attack Uygunlugu Kontrol Ediliyor..." -ForegroundColor Cyan

    $privs = whoami /priv 2>$null
    $hasSeImpersonate = $privs -match "SeImpersonatePrivilege.*Enabled"
    $hasSeAssignPrimaryToken = $privs -match "SeAssignPrimaryTokenPrivilege.*Enabled"

    if (-not ($hasSeImpersonate -or $hasSeAssignPrimaryToken)) {
        Write-Host "  [OK] SeImpersonate/SeAssignPrimaryToken yetkisi yok - Potato ataklari uygun degil." -ForegroundColor Green
        return
    }

    $os = Get-WmiObject -Class Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    $arch = $env:PROCESSOR_ARCHITECTURE

    $potatoes = @()

    # JuicyPotato - Windows 10 1809 oncesi ve Server 2019 oncesi
    if ($build -lt 17763) {
        $potatoes += @{
            Name = "JuicyPotato"
            Risk = "KRITIK"
            Details = "Build $build - JuicyPotato calismali (CLSID gerekli)"
        }
    }

    # RoguePotato - Windows 10 1809+ (JuicyPotato calismadiginda)
    if ($build -ge 17763) {
        $potatoes += @{
            Name = "RoguePotato"
            Risk = "KRITIK"
            Details = "Build $build - Remote OXID resolver gerekli (baska makineden)"
        }
    }

    # PrintSpoofer - Windows 10 / Server 2016-2019
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler.Status -eq "Running") {
        $potatoes += @{
            Name = "PrintSpoofer"
            Risk = "KRITIK"
            Details = "Print Spooler calisyor - PrintSpoofer/SpoolSample calismali"
        }
    }

    # GodPotato - .NET 4.x ile calisan tum Windows versiyonlari
    $dotnet4 = Test-Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
    if ($dotnet4) {
        $potatoes += @{
            Name = "GodPotato"
            Risk = "KRITIK"
            Details = ".NET 4.x mevcut - GodPotato calismali (en guncel yontem)"
        }
    }

    # SweetPotato - Kombinasyon
    $potatoes += @{
        Name = "SweetPotato"
        Risk = "YUKSEK"
        Details = "PrintSpoofer + RoguePotato kombinasyonu - otomatik yontem secimi"
    }

    # EfsPotato (CVE-2021-36942)
    if ($build -lt 19043) {
        $potatoes += @{
            Name = "EfsPotato"
            Risk = "YUKSEK"
            Details = "EFS servisini kullanir - patch kontrolu yapilmali"
        }
    }

    # LocalPotato (CVE-2023-21746) - SeImpersonate bile gerektirmez
    if ($build -lt 22621) {
        $potatoes += @{
            Name = "LocalPotato (CVE-2023-21746)"
            Risk = "KRITIK"
            Details = "NTLM local relay - SeImpersonate gerektirmez!"
        }
    }

    # CoercedPotato
    $potatoes += @{
        Name = "CoercedPotato"
        Risk = "YUKSEK"
        Details = "MS-RPRN/MS-EFSR/MS-FSRVP coercion - en guncel yontemler"
    }

    # Sonuclari raporla
    foreach ($potato in $potatoes) {
        Write-Finding -Category "Potato Attack" `
                      -Finding $potato.Name `
                      -Risk $potato.Risk `
                      -Details $potato.Details
    }

    # Onerilen araclar
    Write-Finding -Category "Potato Tools" `
                  -Finding "Onerilen Araclar" `
                  -Risk "DUSUK" `
                  -Details "GodPotato > PrintSpoofer > SweetPotato > JuicyPotato (build'e gore)"
}

function Get-SystemInfo {
    Write-Host "`n[*] Sistem Bilgileri Toplaniyor..." -ForegroundColor Cyan

    $os = Get-WmiObject -Class Win32_OperatingSystem
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5

    Write-Host "`n  Isletim Sistemi: $($os.Caption) $($os.Version)" -ForegroundColor White
    Write-Host "  Mimari: $($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor White
    Write-Host "  Bilgisayar Adi: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "  Kullanici: $($env:USERNAME)" -ForegroundColor White
    Write-Host "  Domain: $($env:USERDOMAIN)" -ForegroundColor White
    Write-Host "`n  Son Yamalar:" -ForegroundColor White
    $hotfixes | ForEach-Object {
        Write-Host "    $($_.HotFixID) - $($_.InstalledOn)" -ForegroundColor Gray
    }
}

# Ana Calistirma
Clear-Host
Write-Host $Banner -ForegroundColor Cyan
Write-Host "`nTarama Basladi: $(Get-Date)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

Get-SystemInfo
Test-TokenPrivileges
Test-UnquotedServicePaths
Test-WeakServicePermissions
Test-AlwaysInstallElevated
Test-WritablePATH
Test-StoredCredentials
Test-ScheduledTasks
Test-AutoRuns
Test-UACSettings
Test-WSL
Test-InstalledSoftware

# Yeni Credential/Sifre Kontrolleri
Test-AutoLogon
Test-PowerShellHistory
Test-PuttySSH
Test-WinSCP
Test-BrowserCredentials
Test-WifiPasswords
Test-VNCPasswords
Test-MRemoteNG
Test-RDPCredentials
Test-GPPPasswords
Test-McAfeeSiteList
Test-CloudCredentials
Test-IISWebConfig
Test-DPAPICredentials
Test-KerberosTickets
Test-LAPS

# Yuksek Oncelikli Sistem Kontrolleri
Test-SAMBackup
Test-StartupFolders
Test-KernelExploits
Test-AVDetection
Test-PotatoAttacks

# Ozet
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "TARAMA TAMAMLANDI" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Yellow

$kritik = ($Results | Where-Object { $_.Risk -eq "KRITIK" }).Count
$yuksek = ($Results | Where-Object { $_.Risk -eq "YUKSEK" }).Count
$orta = ($Results | Where-Object { $_.Risk -eq "ORTA" }).Count
$dusuk = ($Results | Where-Object { $_.Risk -eq "DUSUK" }).Count

Write-Host "`nBulgu Ozeti:" -ForegroundColor Cyan
Write-Host "  KRITIK : $kritik" -ForegroundColor Red
Write-Host "  YUKSEK : $yuksek" -ForegroundColor Yellow
Write-Host "  ORTA   : $orta" -ForegroundColor Cyan
Write-Host "  DUSUK  : $dusuk" -ForegroundColor Green

# Raporu Kaydet
$Results | Format-List | Out-String -Width 4096 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nRapor kaydedildi: $OutputPath" -ForegroundColor Green

Write-Host "`n[!] UYARI: Bu arac yalnizca yetkilendirilmis guvenlik testleri icin kullanilmalidir." -ForegroundColor Red
