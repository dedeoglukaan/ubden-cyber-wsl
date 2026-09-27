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

function Ensure-WinPython {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        $found = Get-Command python.exe -ErrorAction SilentlyContinue
        $basePython = if ($found) { $found.Source } else { '' }
        if (-not $basePython) {
            if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
                throw 'Windows Python ve winget bulunamadi; https://python.org uzerinden Python 3.13 kurun'
            }
            Write-Host '  Windows Python 3.13 kuruluyor (winget)...' -ForegroundColor Cyan
            & winget.exe install --exact --id Python.Python.3.13 --scope machine `
                --accept-source-agreements --accept-package-agreements | Out-Null
            $basePython = @(
                (Join-Path $env:ProgramFiles 'Python313\python.exe'),
                (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')) |
                Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            if (-not $basePython) { throw 'Kurulan Windows Python bulunamadi' }
        }
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
    }
    if (-not (Get-Command nuclei.exe -ErrorAction SilentlyContinue)) {
        Install-Winget 'ProjectDiscovery.Nuclei' 'Nuclei'
    }
    if (-not (Get-Command whois.exe -ErrorAction SilentlyContinue)) {
        Install-Winget 'Microsoft.Sysinternals.Whois' 'Sysinternals Whois'
    }
    # pip tabanli CLI araclari (wafw00f, fierce, theHarvester) venv'e kur.
    Write-Host '  pip araclari kuruluyor (wafw00f, fierce, theHarvester)...' -ForegroundColor Cyan
    try { & $VenvPython (Join-Path $SourceRoot 'win_tools.py') install | Out-Null } catch {}
}

function Add-ScanToolsToPath {
    foreach ($dir in @('C:\Program Files (x86)\Nmap', 'C:\Program Files\Nmap')) {
        if ((Test-Path (Join-Path $dir 'nmap.exe')) -and ($env:PATH -notlike "*$dir*")) {
            $env:PATH = "$dir;$env:PATH"
        }
    }
}

function Invoke-Setup {
    Invoke-Elevated
    Write-UbdenBanner
    Ensure-WinPython
    Ensure-ScanTools
    Write-Host '  Kurulum tamamlandi.' -ForegroundColor Green
}

function Invoke-Run {
    Invoke-Setup
    Add-ScanToolsToPath
    $env:UBDEN_WINDOWS_BRIDGE = Join-Path $SourceRoot 'windows-bridge.ps1'
    Write-Host ''
    Write-Host '  Tarayici arayuzu baslatiliyor; varsayilan tarayici acilacak.' -ForegroundColor Cyan
    Write-Host '  Bu pencereyi acik tutun; kapatmak sunucuyu durdurur.' -ForegroundColor DarkYellow
    & $VenvPython (Join-Path $SourceRoot 'webapp.py')
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
    throw
}
