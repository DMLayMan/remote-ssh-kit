function ConvertTo-NativeArgument([string]$Value) {
    return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function Invoke-NativeConsole([string]$Executable,[string[]]$Arguments,[string]$InputFile='',[string]$OutputFile='') {
    # PowerShell 5.1's native invocation drops empty arguments and embedded quotes.
    $p=@{FilePath=$Executable; ArgumentList=(($Arguments | ForEach-Object {ConvertTo-NativeArgument $_}) -join ' '); NoNewWindow=$true; Wait=$true; PassThru=$true}
    if ($InputFile) { $p.RedirectStandardInput=$InputFile }
    if ($OutputFile) { $p.RedirectStandardOutput=$OutputFile }
    $child=Start-Process @p
    return $child.ExitCode
}
function Invoke-Ssh([string[]]$Arguments, [string]$InputFile='', [string]$OutputFile='') {
    return (Invoke-NativeConsole -Executable (Get-Command ssh.exe -ErrorAction Stop).Source -Arguments $Arguments -InputFile $InputFile -OutputFile $OutputFile)
}
function Protect-PrivateDirectory([string]$Path) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($sid)
    foreach ($id in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Test-PrivateIdentityPath([string]$Path) {
    $file=Get-Item -LiteralPath $Path -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 65536){throw 'INVALID_IDENTITY: use a regular local Ed25519 private key file.'}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=Get-Acl -LiteralPath $Path
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'UNSAFE_KEY_OWNER: source key must belong to the current user.'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($sid.Value,'S-1-5-18','S-1-5-32-544')){
            throw 'UNSAFE_KEY_ACL: source key grants access to other users. Review its Windows file permissions before importing.'
        }
    }
}
function Protect-PrivateFile([string]$Path) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($sid)
    foreach($id in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-ClientIdentity([string]$Path) {
    Test-PrivateIdentityPath $Path
    $publicFile=[IO.Path]::GetTempFileName()
    try {
        $exe=(Get-Command ssh-keygen.exe -ErrorAction Stop).Source
        if((Invoke-NativeConsole -Executable $exe -Arguments @('-y','-P','','-f',$Path) -OutputFile $publicFile) -ne 0){throw 'IDENTITY_LOCKED_OR_INVALID: use a dedicated unencrypted Ed25519 key for unattended SSH. Source key unchanged.'}
        $public=([IO.File]::ReadAllText($publicFile).Trim() -split '\s+')
        if($public.Count -lt 2 -or $public[0] -cne 'ssh-ed25519' -or $public[1] -cnotmatch '\A[A-Za-z0-9+/=]+\z'){throw 'INVALID_IDENTITY: Ed25519 private key required.'}
        $fingerprint=& ssh-keygen.exe -lf $publicFile -E sha256
        if($LASTEXITCODE -ne 0){throw 'INVALID_IDENTITY: cannot validate derived public key.'}
        return [pscustomobject]@{PublicKey=($public[0]+' '+$public[1]);Fingerprint=($fingerprint -split '\s+')[1]}
    } finally {Remove-Item -LiteralPath $publicFile -ErrorAction SilentlyContinue}
}
function Write-ClientStatus([string]$Root,[string]$State,[string]$Stage,[int]$Code) {
    $destination=Join-Path $Root 'client-acceptance.json'
    if((Test-Path -LiteralPath $destination) -and ((Get-Item -LiteralPath $destination -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unsafe client acceptance path.'}
    $tmp=Join-Path $Root ([guid]::NewGuid().ToString()+'.status')
    try {
        $data=@{schemaVersion=1;state=$State;stage=$Stage;exitCode=$Code;updatedAt=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
        [IO.File]::WriteAllText($tmp,($data|ConvertTo-Json)+"`n",[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $destination -Force
    } finally {if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp}}
}
function New-VpsCommand([string]$ScriptFile,$Receipt,[string]$PublicKey) {
    Test-ServerReceipt $Receipt
    if($PublicKey -cnotmatch '\Assh-ed25519 ([A-Za-z0-9+/=]+)\z'){throw 'Invalid public key for VPS command.'}
    $data=$Matches[1]
    $bytes=[IO.File]::ReadAllBytes($ScriptFile)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
    $payload=[Convert]::ToBase64String($bytes)
    return (@(
        '#!/bin/bash',
        '# Self-contained VPS setup. Contains public network inputs only.',
        'set -euo pipefail',
        'umask 077',
        'bundle=$(mktemp -d)',
        'trap ''rm -rf "$bundle"'' EXIT',
        'base64 -d > "$bundle/init-vps.sh" <<''REMOTE_SSH_PAYLOAD''',
        $payload,
        'REMOTE_SSH_PAYLOAD',
        ('printf '''+$digest+'  %s\n'' "$bundle/init-vps.sh" | sha256sum -c -'),
        ('bash "$bundle/init-vps.sh" '+$Receipt.host+' 22 '+$data+' '+$Receipt.jumpTailnetIp)
    ) -join "`n")+"`n"
}
function Write-NewUtf8File([string]$Path,[string]$Content) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes($Content);$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
}
function Test-ServerReceipt($Receipt) {
    $allowed=@('schemaVersion','kind','serverOs','serverReady','host','port','user','hostKey','jumpHost','jumpPort','jumpTailnetIp','jumpHostKey','clientKeyFingerprint')
    foreach($name in $Receipt.PSObject.Properties.Name) { if($name -notin $allowed){throw 'Unsupported receipt field.'} }
    if ($Receipt.schemaVersion -ne 1 -or $Receipt.kind -ne 'remote-ssh' -or $Receipt.serverOs -ne 'macos' -or $Receipt.serverReady -isnot [bool] -or -not $Receipt.serverReady -or $Receipt.port -ne 22) { throw 'A ready Remote SSH Mac server receipt is required.' }
    if ($Receipt.host -notmatch '\A100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z') { throw 'Server must use a Tailscale IPv4.' }
    if ([int]$Matches[1] -lt 64 -or [int]$Matches[1] -gt 127 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 255) { throw 'Invalid server address.' }
    if ($Receipt.user -notmatch '\A[a-zA-Z0-9_][a-zA-Z0-9_.-]*\z' -or $Receipt.hostKey -notmatch '\Assh-ed25519 [A-Za-z0-9+/=]+\z') { throw 'Invalid server identity.' }
    if ($Receipt.jumpHost -notmatch '\A[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\z' -or $Receipt.jumpHost.Length -gt 253 -or $Receipt.jumpHost.Contains('..')) { throw 'Invalid jump host.' }
    if ([string]$Receipt.jumpPort -notmatch '\A[0-9]{1,5}\z' -or [int]$Receipt.jumpPort -lt 1 -or [int]$Receipt.jumpPort -gt 65535) { throw 'Invalid jump port.' }
    if ($Receipt.jumpHostKey -notmatch '\Assh-ed25519 [A-Za-z0-9+/=]+\z' -or $Receipt.clientKeyFingerprint -notmatch '\ASHA256:[A-Za-z0-9+/]+\z') { throw 'Invalid host key or client fingerprint.' }
    if ($Receipt.jumpTailnetIp -notmatch '\A100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z') { throw 'Invalid jump address.' }
    if ([int]$Matches[1] -lt 64 -or [int]$Matches[1] -gt 127 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 255 -or $Receipt.host -eq $Receipt.jumpTailnetIp) { throw 'Invalid jump/server addresses.' }
}
function Get-SshIdentityCommand([string]$User) {
    if ($User -notmatch '\A[a-zA-Z0-9_][a-zA-Z0-9_.-]*\z') { throw 'Invalid remote user.' }
    return 'test "$(/usr/bin/id -un)" = '''+$User+''' && test "$(/usr/bin/uname -s)" = Darwin && printf ''REMOTE_SSH_OK\n'''
}
