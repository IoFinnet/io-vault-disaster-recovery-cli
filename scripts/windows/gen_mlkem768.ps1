#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a NIST FIPS 203 ML-KEM-768 key pair using OpenSSL and writes it to PEM files.

.DESCRIPTION
    Windows equivalent of scripts/posix/gen_mlkem768.sh. Produces the same two files, byte-for-byte
    compatible with that script and with this repo's recovery tool.

    Requires OpenSSL 3.5.0 or later: ML-KEM support landed in 3.5, and the -provparam flag used
    below does not exist before it. Check your build with `openssl version`. Note that the openssl
    bundled with Git for Windows is frequently older than 3.5 -- if the capability probe below
    fails, install a current OpenSSL and make sure it precedes Git's copy in PATH.

.PARAMETER BaseName
    Basename for the output files. Defaults to "mlkem768".

.OUTPUTS
    <BaseName>_priv.pem   Private key, PKCS#8 PEM, RFC 9935 minimal "bare-seed" form: just the
                          64-byte FIPS 203 seed, no OpenSSL-specific CHOICE wrapper. ACL is
                          restricted to the current user.
    <BaseName>_pub.pem    Public key, PEM SubjectPublicKeyInfo, raw FIPS 203 "ek" bytes.

.EXAMPLE
    .\gen_mlkem768.ps1

.EXAMPLE
    .\gen_mlkem768.ps1 production-dr
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'This is an interactive operator script, not a module: its status lines and the ACL warning are meant for a human at a console and must display unconditionally. Write-Information would stay silent unless the caller opts in, which could hide the "secure this file manually" warning.')]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $BaseName = 'mlkem768'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Alg     = 'ML-KEM-768'
$PrivKey = Join-Path (Get-Location) "${BaseName}_priv.pem"
$PubKey  = Join-Path (Get-Location) "${BaseName}_pub.pem"

# Native executables do not raise terminating errors in PowerShell, so every openssl call has to
# have its exit code checked explicitly or a failure would sail past $ErrorActionPreference.
function Invoke-OpenSSL {
    param([Parameter(Mandatory)][string[]] $Arguments)

    & openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "openssl $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

# --- Sanity checks -------------------------------------------------------

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw 'openssl not found in PATH. Install OpenSSL 3.5.0 or later and re-run.'
}

Write-Host "Using: $(& openssl version)"

# Verify this build of OpenSSL actually knows about ML-KEM-768 before attempting to use it, so we
# can give a clear error message instead of an opaque OpenSSL failure.
$keyManagers = & openssl list -key-managers 2>$null
if (-not ($keyManagers | Select-String -SimpleMatch -Quiet $Alg)) {
    throw "This OpenSSL build does not support $Alg. ML-KEM support requires OpenSSL 3.5.0 or later."
}

# Listed on their own lines first: PowerShell collapses embedded newlines when it renders an
# exception message, which would run the paths together into one unreadable string.
$existing = @($PrivKey, $PubKey) | Where-Object { Test-Path -LiteralPath $_ }
if ($existing) {
    Write-Host 'Output file(s) already exist:'
    $existing | ForEach-Object { Write-Host "  $_" }
    throw 'Refusing to overwrite. Remove the file(s) listed above or choose a different basename.'
}

# --- Key generation ------------------------------------------------------

# By default OpenSSL writes BOTH the 64-byte FIPS 203 seed and the full expanded decapsulation key
# into the file (its "seed-priv"/"both" form), using an OpenSSL-specific CHOICE encoding that
# predates the finalized standard and that this repo's Go parser rejects.
#
# We instead request the "bare-seed" output format: just the 64-byte seed, stored directly as the
# PKCS#8 privateKey OCTET STRING with no extra ASN.1 wrapping. This is the minimal form defined by
# RFC 9935 and is what non-OpenSSL tooling (e.g. Go's crypto/mlkem) expects.
#
# Note both calls use openssl's own -out rather than PowerShell redirection: `>` would re-encode
# the stream as UTF-16LE on Windows PowerShell 5.1 and silently corrupt the PEM.
Invoke-OpenSSL @('genpkey', '-algorithm', $Alg,
                 '-provparam', 'ml-kem.output_formats=bare-seed',
                 '-out', $PrivKey)

# Restrict the private key to the current user: disable ACL inheritance, drop everything it would
# have inherited, and grant only this account. This is the Windows counterpart of `chmod 600`.
try {
    $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -LiteralPath $PrivKey
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $me, 'FullControl', 'None', 'None', 'Allow')))
    Set-Acl -LiteralPath $PrivKey -AclObject $acl
    $aclNote = "restricted to $me"
} catch {
    # Do not fail the run -- the key is valid -- but make it impossible to miss that the file is
    # still readable by others (can happen on non-NTFS volumes or in some container images).
    Write-Warning "Could not restrict the ACL on $PrivKey : $($_.Exception.Message)"
    Write-Warning 'Secure this file manually before using it -- it decrypts every .dr file produced by the paired Virtual Signer.'
    $aclNote = 'DEFAULT ACL - SECURE THIS FILE MANUALLY'
}

# Derive the public key from the private key.
Invoke-OpenSSL @('pkey', '-in', $PrivKey, '-pubout', '-out', $PubKey)

# --- Summary -------------------------------------------------------------

Write-Host ''
Write-Host "Generated $Alg key pair:"
Write-Host "  Private key: $PrivKey ($aclNote)"
Write-Host "  Public key:  $PubKey"
Write-Host ''
Write-Host 'Keep the private key offline and backed up. Configure only the PUBLIC key on the'
Write-Host 'Virtual Signer; the private key is what performs recovery.'
