#Requires -Version 3.0
<#
.SYNOPSIS
    WSL Kaynakli Local Admin Privilege Escalation Scanner
.DESCRIPTION
    WSL uzerinden Windows'ta yerel admin yukseltme yollarini tarar.
    Guvenlik denetimi icin kullanilir.
#>

param(
    [string]$OutputPath = ".\WSL_PrivEsc_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$Banner = @"
====================================================
  WSL Privilege Escalation Scanner
  Windows Subsystem for Linux Guvenlik Taramasi
====================================================
"@

$Results = @()

function Write-Finding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Risk,
        [string]$Details,
        [string]$Exploitation = ""
    )

    $color = switch ($Risk) {
        "KRITIK"  { "Red" }
        "YUKSEK"  { "Yellow" }
        "ORTA"    { "Cyan" }
        "DUSUK"   { "Green" }
        "INFO"    { "Gray" }
        default   { "White" }
    }

    Write-Host "`n[$Risk] " -ForegroundColor $color -NoNewline
    Write-Host "$Category" -ForegroundColor White
    Write-Host "  Bulgu: $Finding" -ForegroundColor Gray
    Write-Host "  Detay: $Details" -ForegroundColor Gray
    if ($Exploitation) {
        Write-Host "  Istismar: $Exploitation" -ForegroundColor Magenta
    }

    $script:Results += [PSCustomObject]@{
        Kategori = $Category
        Bulgu = $Finding
        Risk = $Risk
        Detay = $Details
        Istismar = $Exploitation
    }
}

function Test-WSLInstalled {
    Write-Host "`n[*] WSL Kurulum Durumu Kontrol Ediliyor..." -ForegroundColor Cyan

    $wslPath = Get-Command wsl -ErrorAction SilentlyContinue
    if (-not $wslPath) {
        Write-Host "  [!] WSL yuklu degil. Tarama sonlandiriliyor." -ForegroundColor Red
        return $false
    }

    # WSL versiyonu
    $wslVersion = wsl --version 2>$null
    if ($wslVersion) {
        Write-Finding -Category "WSL Bilgisi" `
                      -Finding "WSL Yuklu" `
                      -Risk "INFO" `
                      -Details ($wslVersion | Out-String)
    }

    # WSL1 mi WSL2 mi?
    $distros = wsl -l -v 2>$null
    if ($distros) {
        Write-Finding -Category "WSL Dagitimlar" `
                      -Finding "Kurulu Dagitimlar" `
                      -Risk "INFO" `
                      -Details ($distros | Out-String)
    }

    return $true
}

function Test-WSLInterop {
    Write-Host "`n[*] WSL Interop Ayarlari Kontrol Ediliyor..." -ForegroundColor Cyan

    # Interop registry kontrolu
    $interopKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction SilentlyContinue

    # WSL'den Windows exe calistirma
    $testInterop = wsl -e which cmd.exe 2>$null
    if ($testInterop) {
        Write-Finding -Category "WSL Interop Aktif" `
                      -Finding "Linux'tan Windows komutlari calistirılabilir" `
                      -Risk "ORTA" `
                      -Details "WSL icinden Windows executable'lari calistirmak mumkun" `
                      -Exploitation "wsl -e /mnt/c/Windows/System32/cmd.exe ile Windows'a gecis yapilabilir"
    }

    # appendWindowsPath kontrolu
    $wslConf = wsl -e cat /etc/wsl.conf 2>$null
    if ($wslConf -match "appendWindowsPath\s*=\s*true" -or $wslConf -notmatch "appendWindowsPath\s*=\s*false") {
        Write-Finding -Category "Windows PATH WSL'de Aktif" `
                      -Finding "appendWindowsPath = true (varsayilan)" `
                      -Risk "ORTA" `
                      -Details "Windows PATH degiskenleri WSL'de gorunur" `
                      -Exploitation "PATH hijacking ile Windows uygulamalari intercept edilebilir"
    }
}

function Test-WSLRootAccess {
    Write-Host "`n[*] WSL Root Erisimi Kontrol Ediliyor..." -ForegroundColor Cyan

    # Varsayilan kullanici root mu?
    $defaultUser = wsl -e whoami 2>$null
    if ($defaultUser -match "root") {
        Write-Finding -Category "WSL Varsayilan Root" `
                      -Finding "WSL varsayilan kullanicisi root" `
                      -Risk "YUKSEK" `
                      -Details "WSL dogrudan root olarak calisiyor" `
                      -Exploitation "Root olarak Windows dosyalarina /mnt/c uzerinden erisim"
    }

    # sudo sifresiz mi?
    $sudoers = wsl -e cat /etc/sudoers 2>$null
    $sudoersD = wsl -e ls /etc/sudoers.d/ 2>$null
    if ($sudoers -match "NOPASSWD") {
        Write-Finding -Category "Sifresiz Sudo" `
                      -Finding "NOPASSWD sudoers yapilandirmasi" `
                      -Risk "YUKSEK" `
                      -Details "Sudo sifre sormadan root yetkisi veriyor" `
                      -Exploitation "sudo ile root ol, sonra Windows'a eriş"
    }
}

function Test-WSLFilePermissions {
    Write-Host "`n[*] WSL Dosya Sistemi Izinleri Kontrol Ediliyor..." -ForegroundColor Cyan

    # WSL dosya sistemi konumu
    $lxssPath = "$env:LOCALAPPDATA\Packages"
    $wslFolders = Get-ChildItem $lxssPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "CanonicalGroupLimited|TheDebianProject|Ubuntu|Kali|openSUSE" }

    foreach ($folder in $wslFolders) {
        $rootfsPath = Join-Path $folder.FullName "LocalState\rootfs"
        if (Test-Path $rootfsPath) {
            # etc/shadow erisilebilir mi?
            $shadowPath = Join-Path $rootfsPath "etc\shadow"
            if (Test-Path $shadowPath -ErrorAction SilentlyContinue) {
                $shadowContent = Get-Content $shadowPath -ErrorAction SilentlyContinue
                if ($shadowContent) {
                    Write-Finding -Category "Shadow Dosyasi Erisilebilir" `
                                  -Finding "Windows'tan /etc/shadow okunabilir" `
                                  -Risk "KRITIK" `
                                  -Details "Konum: $shadowPath" `
                                  -Exploitation "Hash'ler alinip kirilabilir veya dogrudan degistirilebilir"
                }
            }

            # sudoers dosyasi degistirilebilir mi?
            $sudoersPath = Join-Path $rootfsPath "etc\sudoers"
            if (Test-Path $sudoersPath -ErrorAction SilentlyContinue) {
                try {
                    $testWrite = [System.IO.File]::OpenWrite($sudoersPath)
                    $testWrite.Close()
                    Write-Finding -Category "Sudoers Yazilabilir" `
                                  -Finding "Windows'tan sudoers dosyasi degistirilebilir" `
                                  -Risk "KRITIK" `
                                  -Details "Konum: $sudoersPath" `
                                  -Exploitation "Kullaniciya NOPASSWD:ALL ekleyerek root ol"
                } catch {
                    # Yazma izni yok
                }
            }

            # cron dizini
            $cronPath = Join-Path $rootfsPath "etc\cron.d"
            if (Test-Path $cronPath -ErrorAction SilentlyContinue) {
                Write-Finding -Category "Cron Dizini Erisilebilir" `
                              -Finding "WSL cron dizinine Windows'tan erisim" `
                              -Risk "YUKSEK" `
                              -Details "Konum: $cronPath" `
                              -Exploitation "Cron job ekleyerek kod calistirma"
            }
        }
    }
}

function Test-WSLMountPoints {
    Write-Host "`n[*] WSL Mount Noktalari Kontrol Ediliyor..." -ForegroundColor Cyan

    # DrvFs mount secenekleri
    $mountInfo = wsl -e mount 2>$null | Where-Object { $_ -match "drvfs" }

    if ($mountInfo) {
        foreach ($mount in $mountInfo) {
            if ($mount -match "metadata") {
                Write-Finding -Category "DrvFs Metadata Aktif" `
                              -Finding "Windows diskleri metadata ile mount edilmis" `
                              -Risk "ORTA" `
                              -Details $mount `
                              -Exploitation "Linux izinleri Windows dosyalarina uygulanabilir"
            }
        }
    }

    # /mnt/c izinleri
    $mntCperms = wsl -e ls -la /mnt/c/ 2>$null | Select-Object -First 5
    if ($mntCperms) {
        Write-Finding -Category "Windows Disk Erisimi" `
                      -Finding "/mnt/c mount noktasi" `
                      -Risk "INFO" `
                      -Details ($mntCperms | Out-String)
    }
}

function Test-WSLScheduledTasks {
    Write-Host "`n[*] WSL ile Ilgili Zamanlanmis Gorevler Kontrol Ediliyor..." -ForegroundColor Cyan

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Actions.Execute -match "wsl|bash|ubuntu|debian" }

    foreach ($task in $tasks) {
        $action = $task.Actions | Select-Object -First 1
        Write-Finding -Category "WSL Zamanli Gorev" `
                      -Finding $task.TaskName `
                      -Risk "YUKSEK" `
                      -Details "Komut: $($action.Execute) $($action.Arguments)" `
                      -Exploitation "Gorev SYSTEM olarak calisiyorsa WSL uzerinden yetki yukseltme"
    }
}

function Test-WSLServices {
    Write-Host "`n[*] WSL Servisleri Kontrol Ediliyor..." -ForegroundColor Cyan

    $lxssService = Get-Service -Name "LxssManager" -ErrorAction SilentlyContinue
    if ($lxssService) {
        Write-Finding -Category "LxssManager Servisi" `
                      -Finding "WSL yonetim servisi aktif" `
                      -Risk "INFO" `
                      -Details "Durum: $($lxssService.Status)"
    }

    # WSL2 VM durumu
    $wsl2VM = Get-Process -Name "vmmem" -ErrorAction SilentlyContinue
    if ($wsl2VM) {
        Write-Finding -Category "WSL2 VM Aktif" `
                      -Finding "WSL2 sanal makinesi calisiyor" `
                      -Risk "INFO" `
                      -Details "Bellek kullanimi: $([math]::Round($wsl2VM.WorkingSet64/1MB, 2)) MB"
    }
}

function Test-WSLNetworking {
    Write-Host "`n[*] WSL Network Yapilandirmasi Kontrol Ediliyor..." -ForegroundColor Cyan

    # WSL IP adresi
    $wslIP = wsl -e hostname -I 2>$null
    if ($wslIP) {
        Write-Finding -Category "WSL Network" `
                      -Finding "WSL IP Adresi" `
                      -Risk "INFO" `
                      -Details "IP: $wslIP"
    }

    # Port forwarding kontrolu
    $portProxy = netsh interface portproxy show all 2>$null
    if ($portProxy -match "wsl|172\." ) {
        Write-Finding -Category "WSL Port Forwarding" `
                      -Finding "WSL port yonlendirmesi aktif" `
                      -Risk "ORTA" `
                      -Details ($portProxy | Out-String) `
                      -Exploitation "Yonlendirilen portlar uzerinden WSL'e erisim"
    }

    # WSL'den Windows servislerine erisim
    $wslNetstat = wsl -e ss -tlnp 2>$null
    if ($wslNetstat) {
        Write-Finding -Category "WSL Dinleyen Portlar" `
                      -Finding "WSL'de acik portlar" `
                      -Risk "INFO" `
                      -Details ($wslNetstat | Out-String)
    }
}

function Test-WSLCredentials {
    Write-Host "`n[*] WSL Credential Erisimi Kontrol Ediliyor..." -ForegroundColor Cyan

    # Windows credential dosyalari WSL'den erisilebilir mi?
    $credPaths = @(
        "/mnt/c/Users/*/AppData/Local/Microsoft/Credentials/*",
        "/mnt/c/Users/*/.ssh/*",
        "/mnt/c/Users/*/.aws/credentials",
        "/mnt/c/Users/*/.azure/*"
    )

    foreach ($path in $credPaths) {
        $found = wsl -e ls $path 2>$null
        if ($found) {
            Write-Finding -Category "Credential Dosyalari" `
                          -Finding "WSL'den Windows credential erisimi" `
                          -Risk "YUKSEK" `
                          -Details "Bulunan: $path" `
                          -Exploitation "SSH anahtarlari, AWS/Azure credential'lari alinabilir"
        }
    }

    # Git credentials
    $gitCreds = wsl -e cat /mnt/c/Users/*/.git-credentials 2>$null
    if ($gitCreds) {
        Write-Finding -Category "Git Credentials" `
                      -Finding "Git credential dosyasi bulundu" `
                      -Risk "YUKSEK" `
                      -Details "Plaintext git kimlik bilgileri mevcut" `
                      -Exploitation "Repository erisim bilgileri alinabilir"
    }
}

function Test-WSLBinaries {
    Write-Host "`n[*] WSL Binary Manipulasyonu Kontrol Ediliyor..." -ForegroundColor Cyan

    # WSL binary yazilabilir mi?
    $wslExe = "C:\Windows\System32\wsl.exe"
    if (Test-Path $wslExe) {
        $acl = Get-Acl $wslExe -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            ($_.FileSystemRights -match 'Write|FullControl|Modify') -and
            ($_.IdentityReference -match 'Everyone|Users|Authenticated Users')
        }
        if ($writeAccess) {
            Write-Finding -Category "WSL.exe Yazilabilir" `
                          -Finding "wsl.exe dosyasi degistirilebilir" `
                          -Risk "KRITIK" `
                          -Details "Konum: $wslExe" `
                          -Exploitation "WSL binary'si degistirilerek kod calistirma"
        }
    }

    # bash.exe kontrolu
    $bashExe = "C:\Windows\System32\bash.exe"
    if (Test-Path $bashExe) {
        Write-Finding -Category "Legacy Bash.exe" `
                      -Finding "Eski bash.exe mevcut" `
                      -Risk "DUSUK" `
                      -Details "Konum: $bashExe"
    }
}

function Test-WSLConfigFiles {
    Write-Host "`n[*] WSL Yapilandirma Dosyalari Kontrol Ediliyor..." -ForegroundColor Cyan

    # .wslconfig
    $wslConfig = "$env:USERPROFILE\.wslconfig"
    if (Test-Path $wslConfig) {
        $configContent = Get-Content $wslConfig -ErrorAction SilentlyContinue
        Write-Finding -Category ".wslconfig Dosyasi" `
                      -Finding "Kullanici WSL yapilandirmasi" `
                      -Risk "INFO" `
                      -Details ($configContent | Out-String)

        if ($configContent -match "safeMode\s*=\s*false") {
            Write-Finding -Category "Safe Mode Devre Disi" `
                          -Finding "WSL safe mode kapali" `
                          -Risk "ORTA" `
                          -Details "Guvenlik kısitlamalari azaltilmis"
        }
    }

    # /etc/wsl.conf her dagitimda
    $wslConfContent = wsl -e cat /etc/wsl.conf 2>$null
    if ($wslConfContent) {
        Write-Finding -Category "wsl.conf Icerik" `
                      -Finding "Dagitim WSL yapilandirmasi" `
                      -Risk "INFO" `
                      -Details ($wslConfContent | Out-String)

        if ($wslConfContent -match "automount.*enabled\s*=\s*true") {
            Write-Finding -Category "Otomatik Mount Aktif" `
                          -Finding "Windows diskleri otomatik mount ediliyor" `
                          -Risk "DUSUK" `
                          -Details "Varsayilan davranis"
        }
    }
}

function Test-WSLDockerSocket {
    Write-Host "`n[*] Docker Socket Kontrolu..." -ForegroundColor Cyan

    # Docker Desktop WSL entegrasyonu
    $dockerSocket = wsl -e ls -la /var/run/docker.sock 2>$null
    if ($dockerSocket) {
        Write-Finding -Category "Docker Socket Erisilebilir" `
                      -Finding "WSL'de Docker socket mevcut" `
                      -Risk "KRITIK" `
                      -Details $dockerSocket `
                      -Exploitation "Docker socket uzerinden container escape ve host erisimi"
    }

    # Docker group membership
    $dockerGroup = wsl -e groups 2>$null
    if ($dockerGroup -match "docker") {
        Write-Finding -Category "Docker Grup Uyeligi" `
                      -Finding "Kullanici docker grubunda" `
                      -Risk "KRITIK" `
                      -Details "Docker komutlari calistirabilir" `
                      -Exploitation "Privileged container ile host'a root erisimi"
    }
}

# Ana Calistirma
Clear-Host
Write-Host $Banner -ForegroundColor Cyan
Write-Host "`nTarama Basladi: $(Get-Date)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

# WSL yuklu mu kontrol et
if (-not (Test-WSLInstalled)) {
    Write-Host "`nWSL yuklu olmadigi icin tarama yapilamiyor." -ForegroundColor Red
    exit 1
}

Test-WSLInterop
Test-WSLRootAccess
Test-WSLFilePermissions
Test-WSLMountPoints
Test-WSLScheduledTasks
Test-WSLServices
Test-WSLNetworking
Test-WSLCredentials
Test-WSLBinaries
Test-WSLConfigFiles
Test-WSLDockerSocket

# Ozet
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "TARAMA TAMAMLANDI" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Yellow

$kritik = ($Results | Where-Object { $_.Risk -eq "KRITIK" }).Count
$yuksek = ($Results | Where-Object { $_.Risk -eq "YUKSEK" }).Count
$orta = ($Results | Where-Object { $_.Risk -eq "ORTA" }).Count
$dusuk = ($Results | Where-Object { $_.Risk -eq "DUSUK" }).Count
$info = ($Results | Where-Object { $_.Risk -eq "INFO" }).Count

Write-Host "`nBulgu Ozeti:" -ForegroundColor Cyan
Write-Host "  KRITIK : $kritik" -ForegroundColor Red
Write-Host "  YUKSEK : $yuksek" -ForegroundColor Yellow
Write-Host "  ORTA   : $orta" -ForegroundColor Cyan
Write-Host "  DUSUK  : $dusuk" -ForegroundColor Green
Write-Host "  INFO   : $info" -ForegroundColor Gray

# Raporu Kaydet
$Results | Format-List | Out-String -Width 4096 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nRapor kaydedildi: $OutputPath" -ForegroundColor Green

Write-Host "`n[!] UYARI: Bu arac yalnizca yetkilendirilmis guvenlik testleri icin kullanilmalidir." -ForegroundColor Red
