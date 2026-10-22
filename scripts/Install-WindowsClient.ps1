#requires -Version 5.1
[CmdletBinding()]
param([switch]$PrepareOnly,[string]$ReceiptFile,[switch]$NoProvision,[string]$IdentityFile,[string]$ExportVpsCommand)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run on your Windows CLIENT.' }
if (-not $PrepareOnly -and -not $ReceiptFile) { throw 'Provide -ReceiptFile or -PrepareOnly.' }
if($PrepareOnly -and ($ReceiptFile -or $ExportVpsCommand)){throw 'Preparation cannot also import a receipt or export a VPS command.'}
. "$PSScriptRoot\WindowsCommon.ps1"
$null=Get-Command ssh.exe,ssh-keygen.exe -ErrorAction Stop
foreach($name in @('IdentityFile','ReceiptFile','ExportVpsCommand')){
    $value=Get-Variable -Name $name -ValueOnly
    if($PSBoundParameters.ContainsKey($name) -and -not $value){throw "Provide a non-empty $name path."}
    if($value){Set-Variable -Name $name -Value $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($value)}
}
$root=Join-Path $env:LOCALAPPDATA 'RemoteSSHClient'
if (Test-Path -LiteralPath $root) {
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or -not (Test-Path -LiteralPath "$root\.managed-client")) { throw 'Unmanaged client directory.' }
}
if ($root -match '["%\r\n]') { throw 'Unsupported profile path for OpenSSH configuration.' }
$key=Join-Path "$root\ssh" 'id_ed25519'
foreach($item in @('.managed-client','bin','ssh','backups','receipt.json','ssh/config','ssh/known_hosts','ssh/id_ed25519','client-key.pub','client-acceptance.json','bin/Start-WindowsClient.ps1','bin/WindowsCommon.ps1','bin/init-vps.sh','bin/remote-ssh.cmd')){
    $entry=Join-Path $root $item
    if((Test-Path -LiteralPath $entry) -and ((Get-Item -LiteralPath $entry -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse points are not allowed in managed client paths.'}
}
if($ExportVpsCommand){
    $ExportVpsCommand=[IO.Path]::GetFullPath($ExportVpsCommand)
    if((Test-Path -LiteralPath $ExportVpsCommand) -or -not (Test-Path -LiteralPath (Split-Path $ExportVpsCommand -Parent) -PathType Container)){throw 'EXPORT_EXISTS: choose a new output filename in an existing directory.'}
    $NoProvision=$true
}
$identity=$null
if($IdentityFile){$identity=Get-ClientIdentity $IdentityFile}
if(Test-Path -LiteralPath $key){
    $existing=Get-ClientIdentity $key
    if($identity -and $identity.Fingerprint -cne $existing.Fingerprint){throw 'CLIENT_KEY_CONFLICT: installed key differs; no key was replaced.'}
    $identity=$existing
}
if(-not $PrepareOnly){
    $receipt=Get-Content -LiteralPath $ReceiptFile -Raw | ConvertFrom-Json
    Test-ServerReceipt $receipt
    if(-not $identity){throw 'CLIENT_KEY_MISSING: prepare this client, or explicitly reuse its existing key with -IdentityFile PRIVATE_KEY.'}
    if($identity.Fingerprint -cne $receipt.clientKeyFingerprint){throw 'CLIENT_KEY_MISMATCH: receipt authorizes a different client; no provisioning performed.'}
}
$null=New-Item -ItemType Directory -Path "$root\bin","$root\ssh","$root\backups" -Force
Protect-PrivateDirectory $root
$null=New-Item -ItemType File -Path "$root\.managed-client" -Force
foreach($name in @('Start-WindowsClient.ps1','WindowsCommon.ps1','init-vps.sh')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination "$root\bin\$name" -Force }
$key=Join-Path "$root\ssh" 'id_ed25519'
if (Test-Path -LiteralPath $key) {
    if ((Get-Item -LiteralPath $key).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Symlinked SSH key.' }
} elseif($IdentityFile) {
    $candidate=Join-Path "$root\ssh" ([guid]::NewGuid().ToString()+'.identity')
    try {
        [IO.File]::Copy($IdentityFile,$candidate,$false)
        Protect-PrivateFile $candidate
        $copied=Get-ClientIdentity $candidate
        if($copied.Fingerprint -cne $identity.Fingerprint){throw 'IDENTITY_CHANGED: source key changed during import.'}
        [IO.File]::Move($candidate,$key)
        Write-Host "CLIENT_IDENTITY_IMPORTED: $($identity.Fingerprint); source file preserved."
    } finally {if(Test-Path -LiteralPath $candidate){Remove-Item -LiteralPath $candidate}}
} else {
    if ($PSVersionTable.PSVersion.Major -ge 7) { & ssh-keygen.exe -q -t ed25519 -N '' -C remote-ssh-client -f $key }
    else { & ssh-keygen.exe -q -t ed25519 -N '""' -C remote-ssh-client -f $key }
    if($LASTEXITCODE -ne 0){throw 'Key generation failed.'}
}
$identity=Get-ClientIdentity $key
$public=$identity.PublicKey
[IO.File]::WriteAllText("$root\client-key.pub",($public -join "`n")+"`n",[Text.Encoding]::ASCII)
$wrapper=Join-Path "$root\bin" 'remote-ssh.cmd'
if(Test-Path -LiteralPath $wrapper){Copy-Item -LiteralPath $wrapper -Destination (Join-Path "$root\backups" ([guid]::NewGuid().ToString()+'.cmd'))}
[IO.File]::WriteAllText($wrapper,"@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0Start-WindowsClient.ps1`" %*`r`nexit /b %errorlevel%`r`n",[Text.Encoding]::ASCII)
$bin="$root\bin"; $userPath=[string][Environment]::GetEnvironmentVariable('Path','User')
if(($userPath -split ';') -notcontains $bin){[Environment]::SetEnvironmentVariable('Path',($userPath.TrimEnd(';')+';'+$bin).TrimStart(';'),'User')}
if(($env:PATH -split ';') -notcontains $bin){$env:PATH+=';'+$bin}
Write-Host "Public key for the SERVER installer: $root\client-key.pub"
if($PrepareOnly){Write-Host "clientPublicKey: $($public -join ' ')"; Write-Host 'CLIENT_PREPARED: paste the public key into setup.json clientPublicKey. Only setup.json is needed on the server. No remote connection made.'; return}
$known="remote-ssh-jump $($receipt.jumpHostKey)`nremote-ssh-server $($receipt.hostKey)`n"
$candidate=Join-Path $root ([guid]::NewGuid().ToString()+'.known-hosts')
try {
    [IO.File]::WriteAllText($candidate,$known,[Text.Encoding]::ASCII)
    & ssh-keygen.exe -lf $candidate | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Invalid host public keys.'}
    $backup=Join-Path "$root\backups" ([guid]::NewGuid().ToString())
    $null=New-Item -ItemType Directory -Path $backup
    foreach($file in @('receipt.json','ssh/config','ssh/known_hosts')) {
        if(Test-Path -LiteralPath (Join-Path $root $file)){Copy-Item -LiteralPath (Join-Path $root $file) -Destination (Join-Path $backup (Split-Path $file -Leaf))}
    }
    Move-Item -LiteralPath $candidate -Destination "$root\ssh\known_hosts" -Force
} finally {if(Test-Path -LiteralPath $candidate){Remove-Item -LiteralPath $candidate}}
if([IO.Path]::GetFullPath($ReceiptFile) -ne [IO.Path]::GetFullPath("$root\receipt.json")){Copy-Item -LiteralPath $ReceiptFile -Destination "$root\receipt.json" -Force}
$identity=$key.Replace('\','/'); $knownPath="$root\ssh\known_hosts".Replace('\','/')
$configPath="$root\ssh\config".Replace('\','/')
$config=@"
Host remote-ssh-jump
    HostName $($receipt.jumpHost)
    HostKeyAlias remote-ssh-jump
    User remote-jump
    Port $($receipt.jumpPort)
Host remote-ssh-server
    HostName $($receipt.host)
    HostKeyAlias remote-ssh-server
    User $($receipt.user)
    Port 22
    # Keep the config path quoted when the Windows profile contains spaces.
    ProxyCommand ssh.exe -F "$configPath" -W %h:%p remote-ssh-jump
Host *
    BatchMode yes
    PreferredAuthentications publickey
    IdentityFile "$identity"
    IdentitiesOnly yes
    IdentityAgent none
    UserKnownHostsFile "$knownPath"
    GlobalKnownHostsFile NUL
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    ForwardAgent no
    ForwardX11 no
    PermitLocalCommand no
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ConnectTimeout 15
    IPQoS none
"@
[IO.File]::WriteAllText("$root\ssh\config",$config+"`n",[Text.UTF8Encoding]::new($false))
Write-ClientStatus $root pending client-configured 0
if($ExportVpsCommand){
    Write-NewUtf8File $ExportVpsCommand (New-VpsCommand (Join-Path $PSScriptRoot 'init-vps.sh') $receipt $public)
    Write-Host "VPS_COMMAND_EXPORTED: $ExportVpsCommand"
    Write-Host 'Run this script as root in your trusted VPS console, then run remote-ssh -Check here. No repository login is needed on the VPS.'
}
if(-not $NoProvision){
    $keyData=($public -split '\s+')[1]
    if($keyData -notmatch '^[A-Za-z0-9+/=]+$'){throw 'Invalid public key.'}
    Write-Host 'VPS setup: enter root password only at the SSH prompt.'
    $arguments=@('-F','NUL','-T','-a','-x','-p',[string]$receipt.jumpPort,'-o',('UserKnownHostsFile="'+$knownPath+'"'),'-o','HostKeyAlias=remote-ssh-jump','-o','GlobalKnownHostsFile=NUL','-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=15','-o','IPQoS=none','-o','ForwardAgent=no','-o','PermitLocalCommand=no',("root@"+$receipt.jumpHost),"bash -s -- $($receipt.host) 22 $keyData $($receipt.jumpTailnetIp)")
    Write-ClientStatus $root pending jump-setup 0
    $code=Invoke-Ssh -Arguments $arguments -InputFile (Join-Path $PSScriptRoot 'init-vps.sh')
    if($code -ne 0){Write-ClientStatus $root failed jump-setup $code;throw 'VPS_SETUP_FAILED: check root SSH access, or rerun with -ExportVpsCommand FILE for a trusted VPS console.'}
    $start=Join-Path "$root\bin" 'Start-WindowsClient.ps1'
    if((Invoke-NativeConsole -Executable 'powershell.exe' -Arguments @('-NoProfile','-ExecutionPolicy','Bypass','-File',$start,'-Check')) -ne 0){throw 'Remote SSH identity check failed.'}
    Write-Host 'CLIENT_CHAIN_READY: SSH authentication and server identity passed from this client.'
}else{Write-Host 'CLIENT_CONFIGURED_OFFLINE: provisioning and end-to-end check have NOT run.'}
