$ErrorActionPreference = "Stop"

$TargetPath = [Environment]::GetEnvironmentVariable("PF_SECURE_PATH")
$TargetKind = [Environment]::GetEnvironmentVariable("PF_SECURE_KIND")
if ([string]::IsNullOrWhiteSpace($TargetPath) -or $TargetKind -notin @("file", "directory")) {
    throw "secure path input is invalid"
}

$Item = Get-Item -LiteralPath $TargetPath -Force
$Cursor = $Item
while ($null -ne $Cursor) {
    if ($Cursor.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "reparse path components are forbidden"
    }
    $Cursor = $Cursor.Parent
}
if (($TargetKind -eq "directory") -ne $Item.PSIsContainer) { throw "secure path kind mismatch" }

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $Identity.User
$SystemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$Acl = Get-Acl -LiteralPath $TargetPath
$Acl.SetAccessRuleProtection($true, $false)
$Acl.SetOwner($CurrentSid)
foreach ($Rule in @($Acl.Access)) { [void]$Acl.RemoveAccessRuleAll($Rule) }
$Inheritance = if ($TargetKind -eq "directory") {
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
} else { [Security.AccessControl.InheritanceFlags]::None }
foreach ($Sid in @($CurrentSid, $SystemSid)) {
    $Rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Sid, [Security.AccessControl.FileSystemRights]::FullControl, $Inheritance,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$Acl.AddAccessRule($Rule)
}
Set-Acl -LiteralPath $TargetPath -AclObject $Acl

$Verified = Get-Acl -LiteralPath $TargetPath
$Rules = @($Verified.Access)
$Sids = @($Rules | ForEach-Object { $_.IdentityReference.Translate(
    [Security.Principal.SecurityIdentifier]
).Value } | Sort-Object -Unique)
$OwnerMatches = $Verified.Owner -eq $CurrentSid.Value -or $Verified.Owner -eq $Identity.Name
$RulesAreExact = $Rules.Count -eq 2 -and @($Rules | Where-Object {
    $_.IsInherited -or $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
    ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
        [Security.AccessControl.FileSystemRights]::FullControl
}).Count -eq 0
$Secure = $OwnerMatches -and $Verified.AreAccessRulesProtected -and $Sids.Count -eq 2 -and
    $Sids -contains $CurrentSid.Value -and $Sids -contains $SystemSid.Value -and $RulesAreExact
if (-not $Secure) { throw "ACL verification failed" }

@{
    schema_version = "1.0"; status = "secure"; owner = "current-user"; protected = $true
    reparse_point = $false; allowed_sids = @("current-user", "S-1-5-18")
} | ConvertTo-Json -Compress
