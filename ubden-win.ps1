param(
    [ValidateSet('run', 'setup', 'status')]
    [string] $Action = 'run'
)

# UBDEN uPenetrator - Windows-native (WSL YOK) tarayici arayuzlu tarama motoru.
# Ayni rapor motorunu kullanir; Npcap ile gercek L2/ARP erisimi sayesinde MAC ve
# cihaz tanimlarini doldurur. Ikinci tek-satirlik (bootstrap-win.ps1) ile kurulur.

$ErrorActionPreference = 'Stop'
$SourceRoot = Split-Path -Parent $PSCommandPath
$StateRoot  = Join-Path $env:LOCALAPPDATA 'UBDEN'
$Venv       = Join-Path $StateRoot 'win-venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Elevated {
    # Npcap ARP/MAC ve ham tarama icin yonetici gerekir. Zaten yukseltilmisse gec.
    if (Test-Administrator) { return }
    $shell = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
    $quotedScript = $PSCommandPath.Replace("'", "''")
    $command = "& '$quotedScript' -Action '$Action'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath $shell -Verb RunAs -WindowStyle Normal -Wait -PassThru `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
    if ($process.ExitCode -ne 0) { throw "Yukseltilmis islem $($process.ExitCode) koduyla durdu" }
    exit 0
}

function Write-UbdenBanner {
    $g = "`e[1;32m"; $c = "`e[1;36m"; $d = "`e[2;37m"; $r = "`e[0m"
    Write-Host ""
    Write-Host "$g   _   _ ____  ____  _____ _   _$r"
    Write-Host "$g  | | | | __ )|  _ \| ____| \ | |$r"
    Write-Host "$g  | | | |  _ \| | | |  _| |  \| |$r"
    Write-Host "$g  | |_| | |_) | |_| | |___| |\  |$r"
    Write-Host "$g   \___/|____/|____/|_____|_| \_|$r"
    Write-Host "  ${c}UBDEN uPenetrator$r ${d}- Windows-native tarayici arayuzu$r"
    Write-Host "  ${d}https://www.ubden.com | security@ubden.com$r"
    Write-Host ""
}

function Install-TestMachineMarker {
    # Bu bilgisayari "YETKILI PENTEST - TEST MAKINESI" olarak isaretler: kaynak
    # duvar kagidinin sag tarafina BGInfo tarzinda bir sistem bilgisi paneli isler
    # ve sonucu masaustu duvar kagidi yapar. Harici araca bagimli degildir; tamami
    # best-effort'tur (caller try/catch ile sarar, hata kurulumu durdurmaz).
    Add-Type -AssemblyName System.Drawing
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $wall = Join-Path $StateRoot 'ubden-testmachine.bmp'
    $assetPng = Join-Path $SourceRoot 'assets\wallpaper.png'
    if (Test-Path -LiteralPath $assetPng) {
        $src = [System.Drawing.Image]::FromFile($assetPng)
        try { $bmp = New-Object System.Drawing.Bitmap $src } finally { $src.Dispose() }
    }
    else {
        $bmp = New-Object System.Drawing.Bitmap 1920, 1080
        $bg = [System.Drawing.Graphics]::FromImage($bmp)
        $bg.Clear([System.Drawing.Color]::FromArgb(8, 13, 27)); $bg.Dispose()
    }
    $W = $bmp.Width; $H = $bmp.Height
    $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $domain = if ($cs -and $cs.Domain) { $cs.Domain } elseif ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { 'WORKGROUP' }
    $fqdn = if ($domain -and $domain -ne 'WORKGROUP') { "$env:COMPUTERNAME.$domain" } else { $env:COMPUTERNAME }
    $roleMap = @{ 0 = 'Standalone Workstation'; 1 = 'Member Workstation'; 2 = 'Standalone Server';
                  3 = 'Member Server'; 4 = 'Backup Domain Controller'; 5 = 'Primary Domain Controller' }
    $roleText = if ($cs) { $roleMap[[int]$cs.DomainRole] } else { '' }
    $ips = @()
    try { $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notmatch '^(169\.254|127\.)' } |
            Select-Object -ExpandProperty IPAddress) }
    catch { try { $ips = @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString }) } catch {} }
    $gw = ''
    try { $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop) } catch {}
    $dns = @()
    try { $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Select-Object -ExpandProperty ServerAddresses -Unique |
            Where-Object { $_ -and $_ -ne '0.0.0.0' }) } catch {}
    $boot = if ($os) { $os.LastBootUpTime } else { $null }
    $upStr = ''
    if ($boot) { $u = (Get-Date) - $boot; $upStr = "$($u.Days) gun $($u.Hours) saat $($u.Minutes) dk" }
    $memTotalMB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1MB) } else { 0 }
    $memFreePct = if ($os -and $os.TotalVisibleMemorySize) {
        [math]::Round(100 * $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) } else { 0 }
    $fields = [ordered]@{
        'Host Name' = $fqdn; 'Domain' = $domain
        'Uretici'   = if ($cs) { ("$($cs.Manufacturer) $($cs.Model)").Trim() } else { '' }
        'OS'        = if ($os) { $os.Caption } else { '' }; 'Rol' = $roleText
        'IP Adresi' = ($ips -join '   '); 'Ag Gecidi' = $gw; 'DNS' = ($dns -join '   ')
        'Kullanici' = "$env:USERNAME@$domain"
        'CPU'       = if ($cpu) { "$($cpu.NumberOfCores) Core   $($cpu.Name)" } else { '' }
        'Bellek'    = if ($memTotalMB) { "$memTotalMB MB  (%$memFreePct bos)" } else { '' }
        'Acilis'    = if ($boot) { $boot.ToString('dd.MM.yyyy HH:mm') } else { '' }
        'Uptime'    = $upStr; 'Snapshot' = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    }
    $rows = @(foreach ($k in $fields.Keys) { if ($fields[$k]) { [pscustomobject]@{ L = $k; V = [string]$fields[$k] } } })
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $green = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(120, 230, 170))
    $teal  = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(90, 205, 210))
    $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(232, 240, 252))
    $dim   = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150, 168, 200))
    $panelBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(165, 6, 11, 22))
    $accentPen  = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 185, 189), 2)
    $fTitle = New-Object System.Drawing.Font('Consolas', 26, [System.Drawing.FontStyle]::Bold)
    $fSub   = New-Object System.Drawing.Font('Consolas', 15, [System.Drawing.FontStyle]::Bold)
    $fLabel = New-Object System.Drawing.Font('Consolas', 13, [System.Drawing.FontStyle]::Bold)
    $fValue = New-Object System.Drawing.Font('Consolas', 13)
    $fFoot  = New-Object System.Drawing.Font('Consolas', 12)
    $panelW = [int][math]::Min(760, $W * 0.44); $margin = [int]($W * 0.03)
    $panelX = $W - $panelW - $margin; $pad = 26; $labelW = 168
    $valW = $panelW - $labelW - ($pad * 2); $lineH = 30
    $rowHeights = @($rows | ForEach-Object {
        $sz = $g.MeasureString($_.V, $fValue, [int]$valW)
        [int][math]::Max($lineH, [math]::Ceiling($sz.Height) + 6) })
    $contentH = ($rowHeights | Measure-Object -Sum).Sum; if (-not $contentH) { $contentH = 0 }
    $panelH = 84 + $contentH + 46 + ($pad * 2)
    $panelY = [int][math]::Max(40, ($H - $panelH) / 2)
    $g.FillRectangle($panelBrush, $panelX, $panelY, $panelW, $panelH)
    $x = $panelX + $pad; $y = $panelY + $pad
    $g.DrawString('UBDEN CYBER SECURITY', $fTitle, $green, $x, $y); $y += 40
    $g.DrawString('YETKILI PENTEST - TEST MAKINESI', $fSub, $teal, $x, $y); $y += 26
    $g.DrawLine($accentPen, $x, $y, ($panelX + $panelW - $pad), $y); $y += 14
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $g.DrawString($rows[$i].L, $fLabel, $dim, $x, $y)
        $valRect = New-Object System.Drawing.RectangleF(($x + $labelW), $y, $valW, $rowHeights[$i])
        $g.DrawString($rows[$i].V, $fValue, $white, $valRect); $y += $rowHeights[$i]
    }
    $y += 14
    $g.DrawString('https://www.ubden.com   |   security@ubden.com', $fFoot, $teal, $x, $y)
    $g.Dispose()
    $bmp.Save($wall, [System.Drawing.Imaging.ImageFormat]::Bmp); $bmp.Dispose()
    try {
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value '10' -ErrorAction Stop
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name TileWallpaper -Value '0' -ErrorAction Stop
    } catch {}
    if (-not ([System.Management.Automation.PSTypeName]'UbdenWallpaper').Type) {
        Add-Type @'
using System; using System.Runtime.InteropServices;
public class UbdenWallpaper {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
    }
    [UbdenWallpaper]::SystemParametersInfo(20, 0, $wall, 3) | Out-Null
    Write-Host '  Test makinesi isareti uygulandi (duvar kagidi + sistem bilgi paneli).' -ForegroundColor Green
}

function Set-PowerForLongRun {
    # Saatlerce surecek tarama boyunca PC uyumasin/hazirda beklemesin/ekran kapanmasin;
    # yuksek performans guc plani etkin olsun. Onceki plan durum ciktisinda geri alinabilir.
    try {
        $active = (& powercfg.exe /getactivescheme) 2>$null
        if ($active -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
            Set-Content -LiteralPath (Join-Path $StateRoot 'prev-power-scheme.txt') -Value $Matches[1] -ErrorAction SilentlyContinue
        }
        # Ultimate varsa onu, yoksa High performance.
        & powercfg.exe /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
        if ($LASTEXITCODE -ne 0) { & powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null }
        foreach ($t in 'standby-timeout-ac', 'standby-timeout-dc', 'monitor-timeout-ac', 'monitor-timeout-dc',
                        'hibernate-timeout-ac', 'hibernate-timeout-dc', 'disk-timeout-ac', 'disk-timeout-dc') {
            & powercfg.exe /change $t 0 2>$null
        }
        # Ekran koruyucuyu (ve onun kilit tetigini) kapat.
        try {
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value '0' -ErrorAction Stop
            Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value '0' -ErrorAction SilentlyContinue
        } catch {}
        Write-Host '  Guc profili: yuksek performans; uyku / hazirda bekleme / ekran kapanmasi devre disi.' -ForegroundColor Green
    }
    catch { Write-Host "  Guc ayari atlandi: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}

function Restore-Power {
    try {
        $f = Join-Path $StateRoot 'prev-power-scheme.txt'
        if (Test-Path -LiteralPath $f) {
            $guid = (Get-Content -LiteralPath $f -ErrorAction Stop | Select-Object -First 1).Trim()
            if ($guid) { & powercfg.exe /setactive $guid 2>$null }
        }
    } catch {}
}

function Get-BasePython {
    # Sifirdan PC: once mevcut python, sonra winget, olmazsa python.org'dan dogrudan indirip sessiz kur.
    $found = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($found -and $found.Source -notmatch 'WindowsApps') { return $found.Source }
    $known = @((Join-Path $env:ProgramFiles 'Python313\python.exe'),
               (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')) |
             Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($known) { return $known }
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
        Write-Host '  Windows Python 3.13 kuruluyor (winget)...' -ForegroundColor Cyan
        & winget.exe install --exact --id Python.Python.3.13 --scope machine `
            --accept-source-agreements --accept-package-agreements | Out-Null
        $known = @((Join-Path $env:ProgramFiles 'Python313\python.exe'),
                   (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')) |
                 Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($known) { return $known }
    }
    # Son care: python.org resmi kurulumunu dogrudan indir (winget yok / eski Windows).
    Write-Host '  winget yok; Python 3.13 python.org uzerinden indiriliyor...' -ForegroundColor Cyan
    $ver = '3.13.1'
    $url = "https://www.python.org/ftp/python/$ver/python-$ver-amd64.exe"
    $exe = Join-Path $env:TEMP "python-$ver-amd64.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
        Start-Process -FilePath $exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_test=0' -Wait
    } catch { throw "Python otomatik kurulamadi: $($_.Exception.Message) — https://python.org uzerinden elle kurun" }
    $known = @((Join-Path $env:ProgramFiles 'Python313\python.exe'),
               (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
               (Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch 'WindowsApps' } |
                Select-Object -First 1 -ExpandProperty Source)) |
             Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $known) { throw 'Kurulan Windows Python bulunamadi' }
    return $known
}

function Ensure-WinPython {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        $basePython = Get-BasePython
        & $basePython -m venv $Venv
        if ($LASTEXITCODE -ne 0) { throw 'Python ortami (venv) olusturulamadi' }
    }
    Write-Host '  Python bagimliliklari kuruluyor (reportlab, Pillow, ldap3, paramiko, PyYAML)...' -ForegroundColor Cyan
    & $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $SourceRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Python bagimliliklari kurulamadi' }
    & $VenvPython -m pip install --disable-pip-version-check 'playwright>=1.54,<2' | Out-Null
}

function Install-Winget([string] $Id, [string] $Label) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Host "  winget yok; $Label elle kurulmali." -ForegroundColor DarkYellow
        return
    }
    Write-Host "  $Label kuruluyor (winget: $Id)..." -ForegroundColor Cyan
    & winget.exe install --exact --id $Id --accept-source-agreements --accept-package-agreements | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  $Label otomatik kurulamadi (bilgilendirme)." -ForegroundColor DarkYellow
    }
}

function Ensure-ScanTools {
    # "Tum araclar": Windows'ta temiz kurulabilenleri kur; kalanlar icin probe suite
    # Nmap NSE / yerlesik esdegerleri kullanir, gercekten yoksa missing_tool yazar.
    $nmapPaths = @('C:\Program Files (x86)\Nmap\nmap.exe', 'C:\Program Files\Nmap\nmap.exe')
    if (-not (Get-Command nmap.exe -ErrorAction SilentlyContinue) -and
        -not ($nmapPaths | Where-Object { Test-Path $_ })) {
        Install-Winget 'Insecure.Nmap' 'Nmap + Npcap'   # cekirdek: ARP/MAC/L2
        # Sifirdan PC / winget yoksa: Nmap resmi kurulumunu dogrudan indir (Npcap paketli).
        if (-not (Get-Command nmap.exe -ErrorAction SilentlyContinue) -and
            -not ($nmapPaths | Where-Object { Test-Path $_ })) {
            $nver = '7.95'
            $nurl = "https://nmap.org/dist/nmap-$nver-setup.exe"
            $nexe = Join-Path $env:TEMP "nmap-$nver-setup.exe"
            Write-Host "  Nmap + Npcap dogrudan indiriliyor (nmap.org $nver)..." -ForegroundColor Cyan
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $nurl -OutFile $nexe -UseBasicParsing
                Start-Process -FilePath $nexe -ArgumentList '/S' -Wait   # sessiz; Npcap paketli
            }
            catch { Write-Host "  Nmap otomatik kurulamadi: $($_.Exception.Message) — nmap.org uzerinden elle kurun." -ForegroundColor DarkYellow }
        }
    }
    if (-not (Get-Command whois.exe -ErrorAction SilentlyContinue)) {
        Install-Winget 'Microsoft.Sysinternals.Whois' 'Sysinternals Whois'
    }
    # nuclei + sslscan GitHub-release ikilileri, pip araclari (wafw00f/fierce/
    # theHarvester/puresnmp) ve nuclei sablonlari — hepsi win_tools install ile.
    Write-Host '  Araclar kuruluyor: nuclei + sslscan (GitHub) ve pip araclari...' -ForegroundColor Cyan
    try { & $VenvPython (Join-Path $SourceRoot 'win_tools.py') install | Out-Null } catch {}
}

function Add-ScanToolsToPath {
    $toolsDir = Join-Path $StateRoot 'tools'
    $dirs = @('C:\Program Files (x86)\Nmap', 'C:\Program Files\Nmap', $toolsDir)
    if (Test-Path $toolsDir) {
        $dirs += (Get-ChildItem -LiteralPath $toolsDir -Directory -ErrorAction SilentlyContinue |
                  ForEach-Object { $_.FullName })
    }
    foreach ($dir in $dirs) {
        if ((Test-Path $dir) -and ($env:PATH -notlike "*$dir*")) {
            $env:PATH = "$dir;$env:PATH"
        }
    }
}

function Disable-SecurityForTesting {
    # YETKILI PENTEST TEST makinesinde, operator onayiyla: tarama araclari (nuclei/
    # sslscan/nmap) Defender'a "virus" gorunup karantinaya alinmasin ve Guvenlik
    # Duvari taramayi engellemesin diye Defender gercek-zamanli korumayi + Guvenlik
    # Duvarini kapatir ve klasor/surec istisnalari ekler. Onaya baglidir; geri alma
    # komutlari 'status' ciktisinda yazar. Bu adim kurulumu asla durdurmaz.
    if (-not (Test-Administrator)) { return }
    $marker = Join-Path $StateRoot 'security-disabled.flag'
    $consent = if ($env:UBDEN_DISABLE_SECURITY) { $env:UBDEN_DISABLE_SECURITY }
               elseif (Test-Path -LiteralPath $marker) { 'yes' } else { '' }
    if (-not $consent) {
        Write-Host ''
        Write-Host '  UYARI: Bu YETKILI PENTEST TEST makinesidir. Tarama araclari (nuclei, sslscan,' -ForegroundColor Yellow
        Write-Host '  nmap) Windows Defender tarafindan virus sanilip karantinaya alinabilir; Guvenlik' -ForegroundColor Yellow
        Write-Host '  Duvari da taramayi engelleyebilir. Bunlari kapatmak onerilir (test makinesinde).' -ForegroundColor Yellow
        $ans = Read-Host '  Windows Defender + Guvenlik Duvarini devre disi birak? (E/H)'
        $consent = if ($ans -match '^(e|evet|y|yes)$') { 'yes' } else { 'no' }
    }
    if ($consent -ne 'yes') {
        Write-Host '  Guvenlik yazilimlari acik birakildi; bazi araclar karantinaya alinabilir.' -ForegroundColor DarkYellow
        return
    }
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    # 1) Defender klasor/surec istisnalari (Tamper Protection acikken bile calisir).
    foreach ($p in @($StateRoot, (Join-Path $StateRoot 'tools'), $Venv, $SourceRoot,
                     (Join-Path $env:LOCALAPPDATA 'UBDEN-Cyber'))) {
        try { Add-MpPreference -ExclusionPath $p -ErrorAction Stop } catch {}
    }
    foreach ($proc in 'nmap.exe', 'nuclei.exe', 'sslscan.exe', 'python.exe') {
        try { Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop } catch {}
    }
    # 2) Defender gercek-zamanli koruma kapat (Tamper Protection kapali degilse basarisiz olur).
    $rtOff = $false
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        $rtOff = [bool](Get-MpPreference -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
    } catch {}
    # 3) Guvenlik Duvari tum profillerde kapat.
    $fwOff = $false
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Stop
        $fwOff = -not @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }).Count
    }
    catch {
        try { & netsh.exe advfirewall set allprofiles state off | Out-Null; $fwOff = $true } catch {}
    }
    # 4) Dogrula, durumu yaz, onay isaretini birak.
    Write-Host ''
    Write-Host ('  Defender gercek-zamanli koruma : ' + $(if ($rtOff) { 'KAPALI' } else { 'ACIK' })) -ForegroundColor $(if ($rtOff) { 'Green' } else { 'DarkYellow' })
    Write-Host ('  Guvenlik Duvari (tum profiller): ' + $(if ($fwOff) { 'KAPALI' } else { 'ACIK' })) -ForegroundColor $(if ($fwOff) { 'Green' } else { 'DarkYellow' })
    Write-Host '  Defender istisnalari eklendi (tools/venv/reports/kaynak).' -ForegroundColor Green
    if (-not $rtOff) {
        Write-Host '  NOT: Gercek-zamanli koruma kapanmadi (Kurcalama Korumasi/Tamper Protection acik olabilir).' -ForegroundColor DarkYellow
        Write-Host '       Windows Guvenligi > Virus & tehdit korumasi > Ayarlari yonet > Kurcalama Korumasi KAPAT, sonra tekrar calistir.' -ForegroundColor DarkYellow
    }
    try { Set-Content -LiteralPath $marker -Value ((Get-Date).ToString('o')) -ErrorAction Stop } catch {}
}

function Invoke-Setup {
    Invoke-Elevated
    Write-UbdenBanner
    Disable-SecurityForTesting   # once guvenligi kapat: araclar karantinaya alinmasin
    Ensure-WinPython
    Ensure-ScanTools
    Write-Host '  Kurulum tamamlandi.' -ForegroundColor Green
}

function Invoke-Run {
    Invoke-Setup
    Add-ScanToolsToPath
    # Windows-native calismadan once (WSL'deki gibi) test makinesi isareti: BGInfo tarzi
    # panel + duvar kagidi. Sonra saatlerce surecek tarama icin guc/uyku ayarlari.
    try { Install-TestMachineMarker } catch { Write-Host "  Test makinesi isareti atlandi: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    Set-PowerForLongRun
    $env:UBDEN_WINDOWS_BRIDGE = Join-Path $SourceRoot 'windows-bridge.ps1'
    Write-Host ''
    Write-Host '  Tarayici arayuzu baslatiliyor; varsayilan tarayici acilacak.' -ForegroundColor Cyan
    Write-Host '  Bu pencere SUNUCUDUR ve acik kalmalidir. Tarama tarayicida yurur;' -ForegroundColor DarkYellow
    Write-Host '  her tarama bitince bu pencerede "RAPOR HAZIR" bandi ve rapor yolu gorunur.' -ForegroundColor DarkYellow
    Write-Host '  Temiz kapatmak icin bu pencerede Ctrl+C. Beklenmedik cokmede sunucu otomatik yeniden baslar.' -ForegroundColor DarkYellow
    # Denetleyici (supervisor): sunucu beklenmedik sekilde cokerse otomatik yeniden
    # baslatir; pencere HICBIR durumda kendiliginden kapanmaz. Ctrl+C = temiz cikis.
    $webapp = Join-Path $SourceRoot 'webapp.py'
    $attempt = 0
    while ($true) {
        $attempt++
        $code = 0
        try { & $VenvPython $webapp; $code = $LASTEXITCODE }
        catch { $code = 1; Write-Host ("  Sunucu istisnasi: " + $_.Exception.Message) -ForegroundColor Red }
        if ($null -eq $code -or $code -eq 0) { break }   # temiz cikis (Ctrl+C)
        if ($attempt -ge 100) { Write-Host '  Cok fazla yeniden baslatma; denetleyici durduruldu.' -ForegroundColor Red; break }
        Write-Host ("  Sunucu beklenmedik sekilde durdu (kod $code). 5 sn icinde yeniden baslatiliyor (deneme $attempt)...") -ForegroundColor DarkYellow
        Start-Sleep -Seconds 5
    }
    Restore-Power
    Write-Host ''
    Write-Host '  Sunucu durdu. Guc plani geri alindi.' -ForegroundColor Cyan
    try { Read-Host '  Kapatmak icin Enter tusuna basin' | Out-Null } catch {}
}

function Invoke-Status {
    Write-UbdenBanner
    $py = if (Test-Path -LiteralPath $VenvPython) { 'kurulu' } else { 'yok' }
    Add-ScanToolsToPath
    $nm = if (Get-Command nmap.exe -ErrorAction SilentlyContinue) { 'kurulu' } else { 'yok' }
    $np = if (Get-Command nuclei.exe -ErrorAction SilentlyContinue) { 'kurulu' } else { 'yok' }
    Write-Host "  Windows Python venv : $py"
    Write-Host "  Nmap (Npcap)        : $nm"
    Write-Host "  Nuclei              : $np"
    Write-Host "  Raporlar            : $(Join-Path $env:LOCALAPPDATA 'UBDEN-Cyber\Reports')"
    try {
        $rt = (Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring
        $fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }).Count -eq 0
        Write-Host ("  Defender RT koruma   : " + $(if ($rt) { 'KAPALI' } else { 'ACIK' }))
        Write-Host ("  Guvenlik Duvari      : " + $(if ($fw) { 'KAPALI' } else { 'ACIK' }))
    } catch {}
    Write-Host ''
    Write-Host '  Guvenligi geri acmak icin (yonetici PowerShell):' -ForegroundColor DarkYellow
    Write-Host '    Set-MpPreference -DisableRealtimeMonitoring $false' -ForegroundColor DarkYellow
    Write-Host '    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' -ForegroundColor DarkYellow
    if (Test-Path -LiteralPath $VenvPython) {
        Write-Host ''
        Write-Host '  Arac envanteri (present/total):' -ForegroundColor Cyan
        try { & $VenvPython (Join-Path $SourceRoot 'win_tools.py') report } catch {}
    }
}

try {
    switch ($Action) {
        'status' { Invoke-Status }
        'setup' { Invoke-Setup }
        default { Invoke-Run }
    }
}
catch {
    Write-Host ("UBDEN: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host ($_.ScriptStackTrace) -ForegroundColor DarkGray
    # Pencere hicbir durumda kendiliginden kapanmasin: hatayi goster ve bekle.
    try { Read-Host 'Bir hata olustu. Kapatmak icin Enter tusuna basin' | Out-Null } catch {}
    exit 1
}
