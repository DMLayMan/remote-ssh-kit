$ErrorActionPreference='Stop'
$scripts=Join-Path $PSScriptRoot '../scripts'
foreach($file in Get-ChildItem "$scripts/*.ps1"){
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if($errors){throw ($errors | Out-String)}
}
. "$scripts/WindowsCommon.ps1"
function Assert-Equal($Actual,$Expected){if($Actual -cne $Expected){throw "Expected <$Expected>; got <$Actual>"}}
Assert-Equal (ConvertTo-NativeArgument 'C:\A B\') '"C:\A B\\"'
Assert-Equal (ConvertTo-NativeArgument 'a"b') '"a\"b"'
Assert-Equal (ConvertTo-NativeArgument '') '""'
function Start-Process {
    param($FilePath,$ArgumentList,[switch]$NoNewWindow,[switch]$Wait,[switch]$PassThru,$RedirectStandardInput,$RedirectStandardOutput)
    $script:captured=@{args=$ArgumentList;input=$RedirectStandardInput;output=$RedirectStandardOutput}
    return [pscustomobject]@{ExitCode=23}
}
Assert-Equal (Invoke-NativeConsole -Executable 'C:\Program Files\ssh.exe' -Arguments @('-T','a"b','') -InputFile 'C:\input.txt' -OutputFile 'C:\output.txt') 23
Assert-Equal $script:captured.args '"-T" "a\"b" ""'
Assert-Equal $script:captured.input 'C:\input.txt'
Assert-Equal $script:captured.output 'C:\output.txt'
Remove-Item Function:Start-Process
$r=[pscustomobject]@{schemaVersion=1;kind='remote-ssh';serverOs='macos';serverReady=$true;port=22;host='100.90.2.3';user='remote_user';hostKey='ssh-ed25519 YWJj';jumpHost='203.0.113.10';jumpPort=2222;jumpTailnetIp='100.80.0.1';jumpHostKey='ssh-ed25519 YWJj';clientKeyFingerprint='SHA256:fixture'}
Test-ServerReceipt $r
foreach($patch in @(@{jumpHost='host;bad'},@{jumpPort=70000},@{jumpPort="22`nProxyCommand bad"},@{jumpTailnetIp=$r.host},@{serverReady=$false},@{serverReady='true'},@{clientKeyFingerprint='bad'},@{host='100.90.999.1'},@{user="x`nProxyCommand bad"},@{kind='different'},@{unexpected='value'})){
    $bad=$r | ConvertTo-Json | ConvertFrom-Json
    foreach($key in $patch.Keys){$bad|Add-Member -NotePropertyName $key -NotePropertyValue $patch[$key] -Force}
    $rejected=$false;try{Test-ServerReceipt $bad}catch{$rejected=$true}
    if(-not $rejected){throw 'Accepted malformed network receipt.'}
}
$command=Get-SshIdentityCommand 'remote_user'
Assert-Equal $command 'test "$(/usr/bin/id -un)" = ''remote_user'' && test "$(/usr/bin/uname -s)" = Darwin && printf ''REMOTE_SSH_OK\n'''
$rejected=$false;try{Get-SshIdentityCommand "x'; touch BAD"}catch{$rejected=$true}
if(-not $rejected){throw 'Accepted command injection.'}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('remote-ssh-contracts-'+[guid]::NewGuid().ToString())
$null=New-Item -ItemType Directory -Path $fixture
try {
    $payloadFile=Join-Path $fixture 'script with spaces.sh'
    [IO.File]::WriteAllText($payloadFile,"#!/bin/bash`nprintf 'FIXTURE_ONLY\n'`n",[Text.UTF8Encoding]::new($false))
    $command=New-VpsCommand $payloadFile $r 'ssh-ed25519 YWJj'
    if($command.Contains("`r")){throw 'Export must use LF, including on Windows.'}
    $lines=$command -split "`n"
    Assert-Equal $lines[7] ([Convert]::ToBase64String([IO.File]::ReadAllBytes($payloadFile)))
    $digest=(Get-FileHash -LiteralPath $payloadFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if(-not $lines[9].Contains($digest)){throw 'Export checksum differs from bundled bytes.'}
    Assert-Equal $lines[10] 'bash "$bundle/init-vps.sh" 100.90.2.3 22 YWJj 100.80.0.1'
    $rejected=$false;try{New-VpsCommand $payloadFile $r 'ssh-ed25519 YWJj;bad'}catch{$rejected=$true}
    if(-not $rejected){throw 'Accepted command injection in export.'}
    $out=Join-Path $fixture 'vps-init.sh'
    Write-NewUtf8File $out $command
    Assert-Equal ([IO.File]::ReadAllText($out)) $command
    $rejected=$false;try{Write-NewUtf8File $out 'overwrite'}catch{$rejected=$true}
    if(-not $rejected){throw 'Overwrote an existing export.'}
    Assert-Equal ([IO.File]::ReadAllText($out)) $command
    foreach($state in @('pending','checking','ready','failed','pending')){
        $code=if($state -eq 'failed'){255}else{0}
        Write-ClientStatus $fixture $state ssh-check $code
        $statusText=Get-Content -LiteralPath (Join-Path $fixture 'client-acceptance.json') -Raw
        $status=$statusText | ConvertFrom-Json
        Assert-Equal $status.state $state
        Assert-Equal $status.exitCode $code
        if($statusText -notmatch '"updatedAt"\s*:\s*"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"'){throw 'Expected UTC acceptance timestamp.'}
    }
    # Portable contract only: native Windows ownership/ACLs require Windows hardware.
    $savedInvoke=${function:Invoke-NativeConsole}
    $savedCheck=${function:Test-PrivateIdentityPath}
    function Test-PrivateIdentityPath([string]$Path){$script:checkedIdentity=$Path}
    function ssh-keygen.exe {
        $global:LASTEXITCODE=0
        '256 SHA256:fixture fixture (ED25519)'
    }
    $script:keyExit=0;$script:keyPublic='ssh-ed25519 YWJj old-comment'
    function Invoke-NativeConsole([string]$Executable,[string[]]$Arguments,[string]$InputFile='',[string]$OutputFile=''){
        $script:keyArgs=$Arguments;$script:publicOutput=$OutputFile
        [IO.File]::WriteAllText($OutputFile,$script:keyPublic)
        return $script:keyExit
    }
    try {
        $identity=Get-ClientIdentity 'C:\Old Client\id_ed25519'
        Assert-Equal $identity.PublicKey 'ssh-ed25519 YWJj'
        Assert-Equal $identity.Fingerprint 'SHA256:fixture'
        Assert-Equal $script:checkedIdentity 'C:\Old Client\id_ed25519'
        Assert-Equal ($script:keyArgs -join '|') '-y|-P||-f|C:\Old Client\id_ed25519'
        if(Test-Path -LiteralPath $script:publicOutput){throw 'Public-key temporary output was not removed.'}
        $script:keyExit=255
        $rejected=$false;try{Get-ClientIdentity 'C:\Old Client\id_ed25519'}catch{$rejected=$_.Exception.Message -like 'IDENTITY_LOCKED_OR_INVALID:*'}
        if(-not $rejected){throw 'Encrypted or invalid identity must fail without a passphrase prompt.'}
        if(Test-Path -LiteralPath $script:publicOutput){throw 'Failed key extraction left temporary output.'}
        $script:keyExit=0;$script:keyPublic='ssh-rsa YWJj'
        $rejected=$false;try{Get-ClientIdentity 'C:\Old Client\id_ed25519'}catch{$rejected=$true}
        if(-not $rejected){throw 'Accepted a non-Ed25519 identity.'}
    } finally {
        Set-Item Function:Invoke-NativeConsole $savedInvoke
        Set-Item Function:Test-PrivateIdentityPath $savedCheck
        Remove-Item Function:ssh-keygen.exe
    }
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
Write-Output 'PASS: PowerShell parsing; native quoting/output; receipts and identity commands; no-prompt key import contract; exact offline payload/checksum; overwrite refusal; acceptance state transitions. Windows ACLs and real SSH remain separate hardware checks.'
