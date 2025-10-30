Param(
    [ValidateSet("Create","Bootstrap","Destroy","Checkpoint","Restore")]
    [string]$Action = "Create",
    [string]$VmName = "AiDevPlatform",
    [string]$VmRoot = "C:\HyperV\AiDevPlatform",
    [string]$BaseImagePath,
    [switch]$UseBaseImageCopy,
    [string]$VirtualSwitch = "Default Switch",
    [string]$ExternalAdapterName,
    [int]$MemoryStartupGB = 8,
    [int]$ProcessorCount = 4,
    [int]$VhdSizeGB = 200,
    [System.Management.Automation.PSCredential]$GuestCredential,
    [string[]]$BootstrapArguments,
    [string]$CheckpointName = "AiDevPlatform-Bootstrap",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$repoRoot = Resolve-Path -Path (Split-Path -Parent $PSCommandPath)

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Ensure-Administrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session (Run as Administrator)."
    }
}

function Ensure-HyperVFeature {
    Write-Section "Ensuring Hyper-V role is enabled"
    $features = @(
        "Microsoft-Hyper-V-All",
        "Microsoft-Hyper-V-Tools-All",
        "Microsoft-Hyper-V-Management-PowerShell"
    )
    $missing = @()
    foreach ($feature in $features) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature
        if ($state.State -ne "Enabled") {
            $missing += $feature
        }
    }
    if ($missing.Count -eq 0) {
        Write-Host "Hyper-V role already enabled." -ForegroundColor Green
        Import-Module Hyper-V -ErrorAction Stop
        return
    }
    Write-Host ("Enabling Hyper-V components: {0}" -f ($missing -join ", "))
    Enable-WindowsOptionalFeature -Online -FeatureName $missing -NoRestart | Out-Null
    Write-Warning "Hyper-V features were enabled. Restart Windows, then rerun this script."
    exit 1
}

function Ensure-HyperVModule {
    if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
        Ensure-HyperVFeature
    }
    Import-Module Hyper-V -ErrorAction Stop
}

function Get-DefaultSwitchName {
    $switch = Get-VMSwitch -SwitchType Internal,Private,External -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Default Switch" }
    if ($switch) {
        return $switch.Name
    }
    return $null
}

function Ensure-VirtualSwitch {
    param([string]$Name,[string]$Adapter)
    $existing = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        return $existing.Name
    }
    if ([string]::IsNullOrWhiteSpace($Adapter)) {
        $default = Get-DefaultSwitchName
        if ($default) {
            Write-Host ("Switch '{0}' not found. Using Hyper-V default switch instead." -f $Name) -ForegroundColor Yellow
            return $default
        }
        throw "Virtual switch '$Name' not found and no adapter provided. Supply -ExternalAdapterName to create one."
    }
    Write-Section ("Creating Hyper-V switch '{0}'" -f $Name)
    $null = New-VMSwitch -Name $Name -NetAdapterName $Adapter -AllowManagementOS $true -Notes "AiDevPlatform automation" -ErrorAction Stop
    return $Name
}

function Assert-VirtualizationSupport {
    Write-Section "Checking virtualization support"
    try {
        $info = Get-ComputerInfo -Property HyperVRequirementVirtualizationFirmwareEnabled,HyperVRequirementDataExecutionPreventionAvailable,HyperVRequirementSecondLevelAddressTranslation,HyperVRequirementHyperVFeatureAvailable
    } catch {
        Write-Warning "Unable to query virtualization status automatically ($($_.Exception.Message)). Ensure virtualization is enabled in firmware."
        return
    }
    $issues = @()
    if ($info.HyperVRequirementVirtualizationFirmwareEnabled -notin @("True", "Yes")) {
        $issues += "Enable virtualization (Intel VT-x/AMD-V) in BIOS/UEFI."
    }
    if ($info.HyperVRequirementDataExecutionPreventionAvailable -notin @("True", "Yes")) {
        $issues += "Enable Data Execution Prevention in firmware."
    }
    if ($info.HyperVRequirementSecondLevelAddressTranslation -notin @("True", "Yes")) {
        $issues += "CPU must expose SLAT (EPT/NPT)."
    }
    if ($issues.Count -eq 0) {
        Write-Host "Hyper-V prerequisites satisfied." -ForegroundColor Green
        return
    }
    foreach ($issue in $issues) {
        Write-Warning $issue
    }
    Write-Warning "Resolve the virtualization prerequisites before continuing."
    exit 1
}

function Get-VirtualHardDiskPath {
    param([string]$Root,[string]$VmName)
    $vmFolder = Join-Path $Root $VmName
    if (-not (Test-Path $vmFolder)) {
        New-Item -ItemType Directory -Path $vmFolder | Out-Null
    }
    return Join-Path $vmFolder "$VmName.vhdx"
}

function New-DifferencingDisk {
    param([string]$Path,[string]$ParentPath)
    if (-not (Test-Path $ParentPath)) {
        throw "Base image '$ParentPath' not found. Supply -BaseImagePath pointing to a generalized Windows VHDX."
    }
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Force
    }
    New-VHD -Path $Path -ParentPath $ParentPath -Differencing | Out-Null
}

function Copy-BaseDisk {
    param([string]$Destination,[string]$Source,[int]$SizeGB)
    if (-not (Test-Path $Source)) {
        throw "Base image '$Source' not found. Supply -BaseImagePath pointing to a generalized Windows VHDX."
    }
    if (Test-Path $Destination) {
        Remove-Item -Path $Destination -Force
    }
    Copy-Item -Path $Source -Destination $Destination -Force
    if ($SizeGB -gt 0) {
        Resize-VHD -Path $Destination -SizeBytes ($SizeGB * 1GB)
    }
}

function Initialize-VirtualMachine {
    param(
        [string]$Name,
        [string]$VhdPath,
        [string]$SwitchName,
        [int]$MemoryGB,
        [int]$CpuCount
    )
    Write-Section ("Creating VM '{0}'" -f $Name)
    $vm = New-VM -Name $Name -MemoryStartupBytes ($MemoryGB * 1GB) -VHDPath $VhdPath -Generation 2 -SwitchName $SwitchName -ErrorAction Stop
    Set-VM -Name $Name -DynamicMemoryEnabled $false -AutomaticStopAction ShutDown
    Set-VMProcessor -VMName $Name -Count $CpuCount -ExposeVirtualizationExtensions $true
    Enable-VMIntegrationService -VMName $Name -Name "Guest Service Interface" -ErrorAction SilentlyContinue
    return $vm
}

function Wait-VmState {
    param([string]$Name,[Microsoft.HyperV.PowerShell.VMState]$Desired,[int]$TimeoutSeconds = 180)
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $vm = Get-VM -Name $Name -ErrorAction Stop
        if ($vm.State -eq $Desired) {
            return
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
    }
    throw "VM '$Name' did not reach state '$Desired' within $TimeoutSeconds seconds."
}

function Remove-VirtualMachine {
    param([string]$Name,[string]$Root,[switch]$Force)
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host ("VM '{0}' not found. Nothing to remove." -f $Name)
        return
    }
    Write-Section ("Removing VM '{0}'" -f $Name)
    if ($vm.State -ne "Off") {
        Stop-VM -Name $Name -Force -TurnOff
    }
    Remove-VM -Name $Name -Force
    $vmFolder = Join-Path $Root $Name
    if ($Force -and (Test-Path $vmFolder)) {
        Remove-Item -Path $vmFolder -Recurse -Force
        Write-Host ("Removed VM storage at {0}" -f $vmFolder)
    } else {
        Write-Host ("VM storage retained at {0}" -f $vmFolder)
    }
}

function New-RepoArchive {
    param([string]$Destination)
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("ai-dev-platform-stage-{0}" -f ([Guid]::NewGuid().ToString("N")))
    $stageDir = Join-Path $tempRoot "ai-dev-platform"
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    $excludeDirs = @(".git","node_modules",".pnpm-store","tmp","artifacts",".turbo","dist")
    $robocopyArgs = @($repoRoot, $stageDir, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/XJ")
    foreach ($dir in $excludeDirs) {
        $robocopyArgs += "/XD"
        $robocopyArgs += $dir
    }
    & robocopy @robocopyArgs | Out-Null
    $copyCode = $LASTEXITCODE
    if ($copyCode -gt 7) {
        throw "Robocopy failed with exit code $copyCode while staging repository."
    }
    Compress-Archive -Path $stageDir -DestinationPath $Destination -CompressionLevel Optimal -Force
    Remove-Item -Path $tempRoot -Recurse -Force
}

function Invoke-GuestBootstrap {
    param(
        [string]$VmName,
        [System.Management.Automation.PSCredential]$Credential,
        [string[]]$Arguments
    )
    if (-not $Credential) {
        throw "-GuestCredential is required for the Bootstrap action."
    }
    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        Start-VM -Name $VmName | Out-Null
        Wait-VmState -Name $VmName -Desired "Running" -TimeoutSeconds 120
    }
    Enable-VMIntegrationService -VMName $VmName -Name "Guest Service Interface" -ErrorAction SilentlyContinue
    $repoZip = Join-Path ([IO.Path]::GetTempPath()) ("ai-dev-platform-{0}.zip" -f ([Guid]::NewGuid().ToString("N")))
    New-RepoArchive -Destination $repoZip
    $remoteZip = "C:\Temp\ai-dev-platform.zip"
    $remoteRoot = "C:\ai-dev-platform"
    Copy-VMFile -Name $VmName -SourcePath $repoZip -DestinationPath $remoteZip -FileSource Host -CreateFullPath -Credential $Credential
    Remove-Item -Path $repoZip -Force
    $scriptBlock = {
        param($zipPath,$targetDir,$bootstrapArgs)
        $targetParent = Split-Path -Parent $targetDir
        if (-not (Test-Path $targetParent)) {
            New-Item -ItemType Directory -Path $targetParent | Out-Null
        }
        if (Test-Path $targetDir) {
            Remove-Item -Path $targetDir -Recurse -Force
        }
        Expand-Archive -Path $zipPath -DestinationPath $targetParent -Force
        Remove-Item -Path $zipPath -Force
        $scriptPath = Join-Path $targetDir "BestSetup-AiDevPlatform.ps1"
        if (-not (Test-Path $scriptPath)) {
            throw "BestSetup-AiDevPlatform.ps1 not found in extracted archive."
        }
        $argumentList = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$scriptPath)
        if ($bootstrapArgs) {
            $argumentList += $bootstrapArgs
        }
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $argumentList -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw ("Bootstrap script exited with code {0}." -f $process.ExitCode)
        }
    }
    Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $remoteZip, $remoteRoot, $Arguments
    Write-Host "Bootstrap completed successfully." -ForegroundColor Green
}

function New-HyperVCheckpoint {
    param([string]$Name,[string]$CheckpointName)
    $vm = Get-VM -Name $Name -ErrorAction Stop
    Checkpoint-VM -VM $vm -SnapshotName $CheckpointName -SnapshotType Standard | Out-Null
    Write-Host ("Checkpoint '{0}' created." -f $CheckpointName) -ForegroundColor Green
}

function Restore-HyperVCheckpoint {
    param([string]$Name,[string]$CheckpointName,[switch]$Force)
    $vm = Get-VM -Name $Name -ErrorAction Stop
    $checkpoint = Get-VMSnapshot -VMName $Name -Name $CheckpointName -ErrorAction SilentlyContinue
    if (-not $checkpoint) {
        throw "Checkpoint '$CheckpointName' not found for VM '$Name'."
    }
    if ($vm.State -ne "Off") {
        if ($Force) {
            Stop-VM -Name $Name -Force -TurnOff
        } else {
            throw "VM must be Off to restore checkpoint. Stop the VM or pass -Force."
        }
    }
    Restore-VMSnapshot -Name $CheckpointName -VMName $Name -Confirm:$false
    Write-Host ("Checkpoint '{0}' restored." -f $CheckpointName) -ForegroundColor Green
}

Ensure-Administrator
Ensure-HyperVModule
Assert-VirtualizationSupport

switch ($Action.ToLowerInvariant()) {
    "create" {
        if (-not $BaseImagePath) {
            throw "-BaseImagePath is required for the Create action."
        }
        $existing = Get-VM -Name $VmName -ErrorAction SilentlyContinue
        if ($existing) {
            if (-not $Force) {
                throw "VM '$VmName' already exists. Use -Force to remove it first."
            }
            Remove-VirtualMachine -Name $VmName -Root $VmRoot -Force:$true
        }
        $switchName = Ensure-VirtualSwitch -Name $VirtualSwitch -Adapter $ExternalAdapterName
        $vhdPath = Get-VirtualHardDiskPath -Root $VmRoot -VmName $VmName
        if ($UseBaseImageCopy) {
            Copy-BaseDisk -Destination $vhdPath -Source $BaseImagePath -SizeGB $VhdSizeGB
        } else {
            New-DifferencingDisk -Path $vhdPath -ParentPath $BaseImagePath
        }
        Initialize-VirtualMachine -Name $VmName -VhdPath $vhdPath -SwitchName $switchName -MemoryGB $MemoryStartupGB -CpuCount $ProcessorCount | Out-Null
        Write-Host ""
        Write-Host "VM created. Install Windows (if required), create an admin user, then run this script with -Action Bootstrap." -ForegroundColor Green
    }
    "bootstrap" {
        Invoke-GuestBootstrap -VmName $VmName -Credential $GuestCredential -Arguments $BootstrapArguments
    }
    "destroy" {
        Remove-VirtualMachine -Name $VmName -Root $VmRoot -Force:$Force
    }
    "checkpoint" {
        New-HyperVCheckpoint -Name $VmName -CheckpointName $CheckpointName
    }
    "restore" {
        Restore-HyperVCheckpoint -Name $VmName -CheckpointName $CheckpointName -Force:$Force
    }
    default {
        throw "Unsupported action '$Action'."
    }
}
