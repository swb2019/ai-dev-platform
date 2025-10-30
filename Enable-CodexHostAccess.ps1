Param(
    [ValidateSet("Enable","Disable","Status")]
    [string]$Action = "Enable",
    [string]$UserName = "codex-automation",
    [System.Security.SecureString]$Password,
    [string]$PublicKeyPath,
    [string]$PublicKey,
    [switch]$GrantAdministrators,
    [switch]$AllowPasswordAuthentication,
    [switch]$SkipFirewall,
    [string[]]$AllowedSources,
    [int]$AccessTimeoutMinutes = 60,
    [switch]$RemoveUser,
    [switch]$Force,
    [switch]$FipsMode,
    [switch]$DisableOpenSshAfter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:EventSource = "CodexHostAccess"
$script:AutoDisableTaskName = "CodexHostAccess-AutoDisable"
$script:FirewallRuleName = "Codex-OpenSSH-In"
$script:IsFipsMode = $false
$script:ForceMode = $false
$script:NormalizedAllowedSources = @("Any")
$script:RequiredSshdConfigOptions = @{
    "PubkeyAuthentication"    = "yes"
    "PasswordAuthentication"  = "no"
    "AuthenticationMethods"   = "publickey"
    "PermitTunnel"            = "no"
    "AllowAgentForwarding"    = "no"
    "AllowTcpForwarding"      = "no"
    "PermitUserEnvironment"   = "no"
}

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Ensure-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session (Run as Administrator)."
    }
}

function Ensure-EventSource {
    if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
        New-EventLog -LogName Application -Source $script:EventSource
    }
}

function Write-Audit {
    param(
        [string]$Message,
        [int]$EventId = 1000,
        [System.Diagnostics.EventLogEntryType]$EntryType = [System.Diagnostics.EventLogEntryType]::Information
    )
    Ensure-EventSource
    Write-EventLog -LogName Application -Source $script:EventSource -EntryType $EntryType -EventId $EventId -Message $Message
}

function Validate-PublicKeyData {
    param([string]$KeyData)
    if ([string]::IsNullOrWhiteSpace($KeyData)) {
        throw "SSH public key data cannot be empty."
    }
    $trimmed = $KeyData.Trim()
    $lines = $trimmed -split "[\r\n]+"
    if ($lines.Count -ne 1) {
        throw "Public key must be a single line."
    }
    $parts = $lines[0] -split "\s+"
    if ($parts.Count -lt 2) {
        throw "Public key must include key type and key material."
    }
    $keyMaterial = $parts[1]
    $allowedTypes = if ($script:IsFipsMode) {
        @("ssh-rsa","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","sk-ecdsa-sha2-nistp256@openssh.com")
    } else {
        @("ssh-ed25519","ssh-rsa","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","sk-ssh-ed25519@openssh.com","sk-ecdsa-sha2-nistp256@openssh.com")
    }
    if (-not ($allowedTypes -contains $parts[0])) {
        $modeHint = if ($script:IsFipsMode) { " (FIPS mode allows RSA or NIST P-256/384/521 ECDSA only)." } else { "." }
        throw "Unsupported key type '$($parts[0])'. Provide a modern OpenSSH public key$modeHint"
    }
    if ($keyMaterial -notmatch '^[A-Za-z0-9+/=]+$') {
        throw "Public key material is not valid Base64."
    }
    if ($keyMaterial.Length -lt 40) {
        throw "Public key material length appears too short."
    }
    return $lines[0]
}

function Normalize-AllowedSources {
    param([string[]]$Sources)
    if (-not $Sources -or $Sources.Count -eq 0) {
        return @("Any")
    }
    $normalized = @()
    foreach ($item in $Sources) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            continue
        }
        $value = $item.Trim()
        if ($value -eq "Any") {
            return @("Any")
        }
        if ($value -match "^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$") {
            $normalized += $value
            continue
        }
        if ($value -match "^[a-fA-F0-9:]+(\/\d{1,3})?$") {
            $normalized += $value
            continue
        }
        throw "Invalid allowed source '$value'. Use IPv4/IPv6 address or CIDR."
    }
    if ($normalized.Count -eq 0) {
        return @("Any")
    }
    return ($normalized | Sort-Object -Unique)
}

function Confirm-RiskyConfiguration {
    param(
        [string]$Prompt
    )
    if ($script:ForceMode) {
        return
    }
    $response = Read-Host "$Prompt Type 'YES' to continue"
    if ($response -ne "YES") {
        throw "Aborted by user."
    }
}

function Get-OpenSshCapability {
    Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
}

function Ensure-OpenSshServer {
    Write-Section "Ensuring OpenSSH Server is installed"
    $capability = Get-OpenSshCapability
    if ($capability.State -ne "Installed") {
        Write-Host "Installing OpenSSH Server capability..."
        Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
        Write-Host "OpenSSH Server installed." -ForegroundColor Green
    } else {
        Write-Host "OpenSSH Server already installed." -ForegroundColor Green
    }

    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "sshd service not found even after installing OpenSSH. Verify the capability was applied correctly."
    }
    if ($service.StartType -ne "Automatic") {
        Set-Service -Name sshd -StartupType Automatic
    }
    if ($service.Status -ne "Running") {
        Start-Service -Name sshd
    }

    $agent = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
    if ($agent -and $agent.StartType -ne "Automatic") {
        Set-Service -Name ssh-agent -StartupType Automatic
    }
}

function Disable-OpenSshServer {
    param(
        [switch]$RemoveCapability
    )
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name sshd -Force
        }
        Set-Service -Name sshd -StartupType Disabled
    }
    $agent = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
    if ($agent) {
        if ($agent.Status -ne "Stopped") {
            Stop-Service -Name ssh-agent -Force
        }
        Set-Service -Name ssh-agent -StartupType Disabled
    }
    if ($RemoveCapability) {
        try {
            $capability = Get-OpenSshCapability
            if ($capability.State -eq "Installed") {
                Write-Host "Removing OpenSSH Server capability..."
                Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
                Write-Audit -Message "OpenSSH Server capability removed after disable." -EventId 1200
            }
        } catch {
            Write-Warning ("Unable to remove OpenSSH capability automatically: {0}" -f $_.Exception.Message)
        }
    }
}

function Ensure-FirewallRule {
    param([string[]]$Sources)
    if ($SkipFirewall) {
        Write-Section "Skipping firewall configuration by request"
        return
    }
    Write-Section "Configuring dedicated firewall rule for SSH"
    $remoteAddresses = Normalize-AllowedSources -Sources $Sources
    $rule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        Set-NetFirewallRule -DisplayName $script:FirewallRuleName -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol TCP -RemoteAddress $remoteAddresses -LocalPort 22 | Out-Null
        Set-NetFirewallRule -DisplayName $script:FirewallRuleName -NewDisplayName $script:FirewallRuleName | Out-Null
    } else {
        New-NetFirewallRule -Name $script:FirewallRuleName -DisplayName $script:FirewallRuleName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -RemoteAddress $remoteAddresses -Profile Any | Out-Null
    }
    $defaultRule = Get-NetFirewallRule -DisplayName "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($defaultRule -and $defaultRule.Enabled -eq "True") {
        Disable-NetFirewallRule -DisplayName "OpenSSH-Server-In-TCP" | Out-Null
    }
    Write-Audit -Message ("Firewall rule {0} active for sources: {1}" -f $script:FirewallRuleName, ($remoteAddresses -join ", "))
}

function Remove-FirewallRule {
    if ($SkipFirewall) {
        return
    }
    $rule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $script:FirewallRuleName | Out-Null
        Write-Audit -Message ("Firewall rule {0} removed." -f $script:FirewallRuleName) -EventId 1001
    }
}

function Get-AutoDisableTaskName {
    param([string]$UserName)
    return ("{0}-{1}" -f $script:AutoDisableTaskName, $UserName)
}

function Remove-AutoDisableTask {
    param([string]$UserName)
    $taskName = Get-AutoDisableTaskName -UserName $UserName
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Audit -Message ("Removed auto-disable task '{0}'." -f $taskName) -EventId 1002
        }
    } catch {
        Write-Warning ("Unable to remove auto-disable task '{0}': {1}" -f $taskName, $_.Exception.Message)
    }
}

function Schedule-AutoDisable {
    param(
        [string]$UserName,
        [int]$Minutes,
        [switch]$RemoveUserOnDisable,
        [switch]$SkipFirewallState,
        [switch]$DisableOpenSshAfter
    )
    Remove-AutoDisableTask -UserName $UserName
    if ($Minutes -le 0) {
        return
    }
    $taskName = Get-AutoDisableTaskName -UserName $UserName
    $disableArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$script:ScriptPath`" -Action Disable -UserName `"$UserName`""
    if ($RemoveUserOnDisable) {
        $disableArgs += " -RemoveUser"
    }
    if ($SkipFirewallState) {
        $disableArgs += " -SkipFirewall"
    }
    if ($DisableOpenSshAfter) {
        $disableArgs += " -DisableOpenSshAfter"
    }
    try {
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($Minutes))
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $disableArgs
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Principal $principal -Force | Out-Null
        Write-Audit -Message ("Scheduled auto-disable task '{0}' to run in {1} minutes." -f $taskName, $Minutes) -EventId 1003
    } catch {
        Write-Warning ("Failed to schedule auto-disable task: {0}" -f $_.Exception.Message)
    }
}

function New-RandomPassword {
    param([int]$Length = 28)
    $chars = ('abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+')
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $sb = New-Object Text.StringBuilder
    for ($i=0; $i -lt $Length; $i++) {
        $sb.Append($chars[$bytes[$i] % $chars.Length]) | Out-Null
    }
    return $sb.ToString()
}

function Ensure-LocalUser {
    param(
        [string]$UserName,
        [System.Security.SecureString]$Password,
        [switch]$GrantAdministrators
    )

    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Section ("Creating local account '{0}'" -f $UserName)
        $effectivePassword = $Password
        if (-not $effectivePassword) {
            $generated = New-RandomPassword
            Write-Host ("No password supplied. Generating random password for {0}." -f $UserName) -ForegroundColor Yellow
            $secure = ConvertTo-SecureString -String $generated -AsPlainText -Force
            $effectivePassword = $secure
            Write-Host "Store the generated password securely if interactive login is required." -ForegroundColor Yellow
        }
        New-LocalUser -Name $UserName -Password $effectivePassword -PasswordNeverExpires:$true -UserMayNotChangePassword:$true -AccountNeverExpires | Out-Null
        $user = Get-LocalUser -Name $UserName
    } elseif ($Password) {
        Write-Host ("Updating password for existing user '{0}'." -f $UserName)
        Set-LocalUser -Name $UserName -Password $Password
    }

    if ($GrantAdministrators) {
        $adminGroup = [ADSI]"WinNT://./Administrators,group"
        $member = "WinNT://./$UserName,user"
        $members = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
        if (-not ($members -contains $UserName)) {
            Write-Host ("Adding '{0}' to Administrators group." -f $UserName)
            $adminGroup.Add($member)
        }
    }

    if (-not $user.Enabled) {
        Enable-LocalUser -Name $UserName
        Write-Host ("Re-enabled local account '{0}'." -f $UserName) -ForegroundColor Yellow
    }

    return $user
}

function Ensure-UserProfileDirectory {
    param([string]$UserName)
    $profileRoot = Join-Path $env:SystemDrive "Users"
    $profilePath = Join-Path $profileRoot $UserName
    if (-not (Test-Path $profilePath)) {
        Write-Host ("Creating profile directory '{0}'." -f $profilePath)
        New-Item -ItemType Directory -Path $profilePath | Out-Null
        $owner = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$UserName")
        $acl = Get-Acl -Path $profilePath
        $acl.SetOwner($owner)
        Set-Acl -Path $profilePath -AclObject $acl
    }
    return $profilePath
}

function Configure-AuthorizedKeys {
    param([string]$UserName,[string]$KeyData)
    Write-Section "Configuring authorized_keys"
    $profilePath = Ensure-UserProfileDirectory -UserName $UserName
    $sshDir = Join-Path $profilePath ".ssh"
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir | Out-Null
    }
    $authPath = Join-Path $sshDir "authorized_keys"
    $KeyData | Set-Content -Path $authPath -Encoding ascii
    & icacls $sshDir /inheritance:r *> $null
    & icacls $sshDir /grant:r "$env:COMPUTERNAME\$UserName:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" *> $null
    & icacls $authPath /inheritance:r *> $null
    & icacls $authPath /grant:r "$env:COMPUTERNAME\$UserName:F" "BUILTIN\Administrators:F" *> $null
    Write-Host ("authorized_keys updated for {0}" -f $UserName) -ForegroundColor Green
}

function Update-SshdConfig {
    param([string]$UserName,[switch]$AllowPasswordAuthentication)
    $configPath = Join-Path $env:ProgramData "ssh\sshd_config"
    if (-not (Test-Path $configPath)) {
        throw "sshd_config not found at $configPath."
    }
    $backupPath = "$configPath.codex-backup"
    if (-not (Test-Path $backupPath)) {
        Copy-Item -Path $configPath -Destination $backupPath -Force
    }
    $content = Get-Content -Path $configPath -Raw
    $content = [regex]::Replace($content, "(?s)# CODEx HOST ACCESS BEGIN.*?# CODEx HOST ACCESS END\s*", "")
    foreach ($option in $script:RequiredSshdConfigOptions.Keys) {
        $value = $script:RequiredSshdConfigOptions[$option]
        $pattern = "(?im)^\s*$option\s+.*$"
        if ($content -match $pattern) {
            $content = [regex]::Replace($content, $pattern, "$option $value", 1)
        } else {
            $content = ($content.TrimEnd() + "`r`n$option $value`r`n")
        }
    }
    $passwordDirective = if ($AllowPasswordAuthentication) { "yes" } else { "no" }
    $block = @"
# CODEx HOST ACCESS BEGIN
Match User $UserName
    PubkeyAuthentication yes
    PasswordAuthentication $passwordDirective
# CODEx HOST ACCESS END
"@
    $newContent = if ($content.Trim().Length -gt 0) { ($content.TrimEnd() + "`r`n`r`n" + $block) } else { $block }
    Set-Content -Path $configPath -Value $newContent -Encoding UTF8
    Test-SshdConfig
}

function Restore-SshdConfig {
    $configPath = Join-Path $env:ProgramData "ssh\sshd_config"
    $backupPath = "$configPath.codex-backup"
    if (-not (Test-Path $backupPath)) {
        return
    }
    Copy-Item -Path $backupPath -Destination $configPath -Force
    Write-Host "sshd_config restored from backup." -ForegroundColor Yellow
}

function Restart-Sshd {
    Restart-Service -Name sshd -Force
}

function Test-SshdConfig {
    $configPath = Join-Path $env:ProgramData "ssh\sshd_config"
    $sshdPath = Join-Path $env:WINDIR "System32\OpenSSH\sshd.exe"
    if (-not (Test-Path $sshdPath)) {
        throw "sshd binary not found at $sshdPath."
    }
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $sshdPath
    $processInfo.ArgumentList.Add("-t")
    $processInfo.ArgumentList.Add("-f")
    $processInfo.ArgumentList.Add($configPath)
    $processInfo.RedirectStandardError = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.Dispose()
    if ($process.ExitCode -ne 0) {
        throw "sshd configuration validation failed: $stderr"
    }
    if ($stdout) {
        Write-Audit -Message ("sshd -t output: {0}" -f $stdout.Trim()) -EventId 1004
    }
}

function Get-PublicKeyData {
    if ($PublicKey) {
        return (Validate-PublicKeyData -KeyData $PublicKey)
    }
    if ($PublicKeyPath) {
        if (-not (Test-Path $PublicKeyPath)) {
            throw "Public key file '$PublicKeyPath' not found."
        }
        $fileKey = Get-Content -Path $PublicKeyPath -Raw
        return (Validate-PublicKeyData -KeyData $fileKey)
    }
    Write-Section "Public key required"
    $input = Read-Host "Paste the SSH public key for $UserName"
    if ([string]::IsNullOrWhiteSpace($input)) {
        throw "No public key provided."
    }
    return (Validate-PublicKeyData -KeyData $input)
}

function Remove-LocalUserSafe {
    param([string]$UserName)
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        return
    }
    Remove-LocalUser -Name $UserName
    $profilePath = Join-Path (Join-Path $env:SystemDrive "Users") $UserName
    if (Test-Path $profilePath) {
        Remove-Item -Path $profilePath -Recurse -Force
    }
    Write-Host ("Removed local account '{0}'." -f $UserName) -ForegroundColor Yellow
    Write-Audit -Message ("Local account {0} removed as part of host access teardown." -f $UserName) -EventId 1102
}

function Disable-LocalUserSafe {
    param([string]$UserName)
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        return
    }
    if ($user.Enabled) {
        Disable-LocalUser -Name $UserName
        Write-Host ("Disabled local account '{0}'." -f $UserName) -ForegroundColor Yellow
        Write-Audit -Message ("Local account {0} disabled as part of host access teardown." -f $UserName) -EventId 1103
    }
}

function Show-Status {
    Write-Section "Host access status"
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host ("sshd service : {0} (StartupType: {1})" -f $service.Status, $service.StartType)
    } else {
        Write-Host "sshd service : not installed"
    }
    try {
        $capability = Get-OpenSshCapability
        Write-Host ("OpenSSH capability: {0}" -f $capability.State)
    } catch {
        Write-Host ("OpenSSH capability: unavailable ({0})" -f $_.Exception.Message)
    }
    $fipsStatus = if ($script:IsFipsMode) { "Enabled" } else { "Disabled" }
    Write-Host ("FIPS validation mode: {0}" -f $fipsStatus)
    $rule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        $addresses = (($rule | Get-NetFirewallAddressFilter).RemoteAddress) -join ", "
        if ([string]::IsNullOrWhiteSpace($addresses)) {
            $addresses = "Any"
        }
        Write-Host ("Firewall rule: {0} (allowed: {1})" -f ($rule.Enabled -eq "True" ? "Enabled" : "Disabled"), $addresses)
    } else {
        Write-Host "Firewall rule: not present"
    }
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if ($user) {
        Write-Host ("Local user   : Present (Enabled: {0})" -f $user.Enabled)
        $profilePath = Join-Path (Join-Path $env:SystemDrive "Users") $UserName
        $authPath = Join-Path (Join-Path $profilePath ".ssh") "authorized_keys"
        Write-Host ("authorized_keys: {0}" -f (Test-Path $authPath ? "Configured" : "Missing"))
        $admins = Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$UserName$" }
        Write-Host ("Administrators membership: {0}" -f ($admins ? "Yes" : "No"))
    } else {
        Write-Host "Local user   : not present"
    }
    $configPath = Join-Path $env:ProgramData "ssh\sshd_config"
    if (Test-Path $configPath) {
        $content = Get-Content -Path $configPath -Raw
        $hasBlock = $content -match "# CODEx HOST ACCESS BEGIN"
        Write-Host ("sshd_config block: {0}" -f ($hasBlock ? "Installed" : "Not present"))
    }
    try {
        $taskName = Get-AutoDisableTaskName -UserName $UserName
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            $next = $task.Triggers | ForEach-Object { $_.StartBoundary } | Sort-Object | Select-Object -First 1
            Write-Host ("Auto-disable task: Scheduled ({0})" -f $next)
        } else {
            Write-Host "Auto-disable task: none"
        }
    } catch {
        Write-Host ("Auto-disable task: unavailable ({0})" -f $_.Exception.Message)
    }
}

Ensure-Administrator

$script:IsFipsMode = [bool]$FipsMode
$script:ForceMode = [bool]$Force

if ($Action -eq "Enable") {
    if ($AllowPasswordAuthentication -and -not $Password) {
        throw "AllowPasswordAuthentication was specified without providing -Password."
    }
    if (-not $script:ForceMode) {
        if ($AllowPasswordAuthentication) {
            throw "Password authentication is disabled by default. Re-run with -Force to allow it."
        }
        if ($GrantAdministrators) {
            throw "Granting Administrators access requires -Force."
        }
        if ($SkipFirewall) {
            throw "Skipping firewall updates requires -Force."
        }
        if ($AccessTimeoutMinutes -le 0) {
            throw "-AccessTimeoutMinutes must be greater than zero. Provide a positive value or use -Force."
        }
        if ($AccessTimeoutMinutes -gt 240) {
            throw "-AccessTimeoutMinutes exceeds the 4-hour maximum. Use -Force to override."
        }
    }

    if (-not $AllowedSources -or $AllowedSources.Count -eq 0) {
        if ($script:ForceMode) {
            $AllowedSources = @("Any")
        } else {
            throw "-AllowedSources is required. Provide one or more IP addresses or CIDR ranges."
        }
    }

    $normalizedSources = Normalize-AllowedSources -Sources $AllowedSources
    if (-not $script:ForceMode) {
        if ($normalizedSources -contains "Any") {
            throw "-AllowedSources cannot include 'Any' without -Force."
        }
        if ($normalizedSources -contains "0.0.0.0/0" -or $normalizedSources -contains "::/0") {
            throw "CIDR ranges 0.0.0.0/0 or ::/0 are not permitted without -Force."
        }
    }
    $script:NormalizedAllowedSources = $normalizedSources
}

switch ($Action.ToLowerInvariant()) {
    "enable" {
        Ensure-OpenSshServer
        $sourcesForAudit = $script:NormalizedAllowedSources
        if ($sourcesForAudit -contains "Any") {
            Confirm-RiskyConfiguration -Prompt "SSH access will be reachable from ANY source."
        }
        if ($AccessTimeoutMinutes -le 0) {
            Confirm-RiskyConfiguration -Prompt "Access timeout is not set; access will persist until manually disabled."
        } elseif ($AccessTimeoutMinutes -gt 240) {
            Confirm-RiskyConfiguration -Prompt "Access timeout exceeds 4 hours."
        }
        if ($AllowPasswordAuthentication) {
            Confirm-RiskyConfiguration -Prompt "Password authentication is being enabled."
        }
        if ($GrantAdministrators) {
            Confirm-RiskyConfiguration -Prompt "User will be added to the Administrators group."
        }
        if ($DisableOpenSshAfter) {
            Confirm-RiskyConfiguration -Prompt "OpenSSH Server will be fully removed after disable."
        }
        if ($SkipFirewall) {
            Confirm-RiskyConfiguration -Prompt "Firewall updates are being skipped; existing rules must limit SSH exposure."
        }
        Ensure-FirewallRule -Sources $script:NormalizedAllowedSources
        $user = Ensure-LocalUser -UserName $UserName -Password $Password -GrantAdministrators:$GrantAdministrators
        $keyData = Get-PublicKeyData
        Configure-AuthorizedKeys -UserName $UserName -KeyData $keyData
        Update-SshdConfig -UserName $UserName -AllowPasswordAuthentication:$AllowPasswordAuthentication
        Restart-Sshd
        Schedule-AutoDisable -UserName $UserName -Minutes $AccessTimeoutMinutes -RemoveUserOnDisable:$RemoveUser -SkipFirewallState:$SkipFirewall -DisableOpenSshAfter:$DisableOpenSshAfter
        $autoDisableText = if ($AccessTimeoutMinutes -gt 0) { "$AccessTimeoutMinutes" } else { "disabled" }
        $modeFlags = @()
        if ($script:IsFipsMode) { $modeFlags += "FIPS" }
        if ($DisableOpenSshAfter) { $modeFlags += "DisableOpenSSH" }
        if ($GrantAdministrators) { $modeFlags += "Admin" }
        if ($AllowPasswordAuthentication) { $modeFlags += "PasswordAuth" }
        $flagText = if ($modeFlags.Count -gt 0) { " Flags: " + ($modeFlags -join ", ") } else { "" }
        Write-Audit -Message ("Host access enabled for user {0}. Sources: {1}. Auto-disable: {2}.{3}" -f $UserName, ($sourcesForAudit -join ", "), $autoDisableText, $flagText) -EventId 1100
        Write-Host ""
        Write-Host ("Host access enabled. Connect with: ssh {0}@{1}" -f $UserName, (hostname)) -ForegroundColor Green
        if (-not $AllowPasswordAuthentication) {
            Write-Host "Password authentication is disabled for this account. Ensure the SSH key works before ending the session." -ForegroundColor Yellow
        }
        if (-not ($sourcesForAudit.Count -eq 1 -and $sourcesForAudit[0] -eq "Any")) {
            Write-Host ("Firewall limited to: {0}" -f ($sourcesForAudit -join ", ")) -ForegroundColor Yellow
        }
        if ($SkipFirewall) {
            Write-Host "Firewall updates were skipped. Ensure another control restricts inbound SSH." -ForegroundColor Yellow
        }
        if ($script:IsFipsMode) {
            Write-Host "FIPS mode active: only RSA or NIST P-256/384/521 keys accepted for Codex access." -ForegroundColor Yellow
        }
        if ($AccessTimeoutMinutes -gt 0) {
            Write-Host ("Access will auto-disable in {0} minutes." -f $AccessTimeoutMinutes) -ForegroundColor Yellow
        }
        Write-Host "Review Application log events from source 'CodexHostAccess' or forward them to your SIEM." -ForegroundColor Yellow
    }
    "disable" {
        Write-Section "Disabling host access"
        Disable-OpenSshServer -RemoveCapability:$DisableOpenSshAfter
        Remove-AutoDisableTask -UserName $UserName
        Remove-FirewallRule
        Restore-SshdConfig
        if ($RemoveUser) {
            Remove-LocalUserSafe -UserName $UserName
        } else {
            Disable-LocalUserSafe -UserName $UserName
        }
        $disableFlags = @()
        if ($RemoveUser) { $disableFlags += "AccountRemoved" }
        if ($DisableOpenSshAfter) { $disableFlags += "OpenSSHRemoved" }
        $disableFlagText = if ($disableFlags.Count -gt 0) { " Flags: " + ($disableFlags -join ", ") } else { "" }
        Write-Audit -Message ("Host access disabled for user {0}.{1}" -f $UserName, $disableFlagText) -EventId 1101
        Write-Host "Host access disabled." -ForegroundColor Green
        if ($DisableOpenSshAfter) {
            Write-Host "OpenSSH Server capability removed as part of teardown." -ForegroundColor Yellow
        }
    }
    "status" {
        Show-Status
    }
    default {
        throw "Unsupported action '$Action'."
    }
}
