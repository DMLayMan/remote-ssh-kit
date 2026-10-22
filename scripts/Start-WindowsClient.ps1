#requires -Version 5.1
[CmdletBinding()]
param([switch]$Check,[switch]$Help)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Help){Write-Host 'remote-ssh [-Check]: open a remote terminal or verify SSH identity.'; return}
if($env:OS -ne 'Windows_NT'){throw 'Use the Windows client on Windows.'}
. "$PSScriptRoot\WindowsCommon.ps1"
$root=Join-Path $env:LOCALAPPDATA 'RemoteSSHClient'
$stage='client-preflight';$output=$null
try {
    if($Check -and (Test-Path -LiteralPath $root -PathType Container)){Write-ClientStatus $root checking $stage 0}
    if(-not (Test-Path -LiteralPath "$root\receipt.json") -or -not (Test-Path -LiteralPath "$root\ssh\config")){throw 'Import the server receipt first.'}
    $receipt=Get-Content -LiteralPath "$root\receipt.json" -Raw | ConvertFrom-Json
    Test-ServerReceipt $receipt
    if($Check){
        $stage='ssh-check'
        $output=Join-Path $root ([guid]::NewGuid().ToString()+'.check-output')
        Write-ClientStatus $root checking $stage 0
        $command=Get-SshIdentityCommand $receipt.user
        $code=Invoke-Ssh -Arguments @('-F',"$root\ssh\config",'-T','-o','BatchMode=yes','remote-ssh-server',$command) -OutputFile $output
        if($code -ne 0){Write-ClientStatus $root failed ssh-check $code;exit $code}
        if(@(Get-Content -LiteralPath $output) -cnotcontains 'REMOTE_SSH_OK'){throw 'SSH_CHECK_FAILED: expected identity confirmation was not returned.'}
        Write-ClientStatus $root ready ssh-check 0
        Write-Host 'SSH_CHAIN_READY: authenticated to the expected Mac account through the jump server.'
    }else{
        Write-Host "REMOTE TERMINAL: $($receipt.user)@$($receipt.host)"
        exit (Invoke-Ssh -Arguments @('-F',"$root\ssh\config",'-tt','remote-ssh-server'))
    }
} catch {
    if($Check -and (Test-Path -LiteralPath $root -PathType Container)){Write-ClientStatus $root failed $stage 1}
    throw
} finally {if($output -and (Test-Path -LiteralPath $output)){Remove-Item -LiteralPath $output}}
