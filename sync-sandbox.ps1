Param(
    [string]$RepoDir = "C:\dev\ai-dev-platform"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $RepoDir)) {
    throw "Repository directory '$RepoDir' not found."
}

$originUrl = git remote get-url origin 2>$null
if ($originUrl -match 'github.com[:/](.+?)(\.git)?$') {
    $SandboxRepo = $matches[1]
    $OriginUrl = "https://github.com/$SandboxRepo.git"
} else {
    throw "Sandbox repository remote could not be determined. Configure 'origin' before running the script."
}

function Get-ProcessesUsingPath {
    param([string]$Path)
    $results = @()
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $results
    }
    $normalized = ($Path -replace '/', '\\').TrimEnd('\\')
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $results
    }
    $normalized = $normalized.ToLowerInvariant()
    try {
        $processes = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    } catch {
        Write-Warning "Unable to enumerate running processes ($_)."
        return $results
    }

    foreach ($proc in $processes) {
        if ($proc.ProcessId -eq $PID) { continue }
        $cmd = if ($proc.CommandLine) { $proc.CommandLine.ToLowerInvariant() } else { "" }
        $exe = if ($proc.ExecutablePath) { $proc.ExecutablePath.ToLowerInvariant() } else { "" }
        if (($cmd -and $cmd.Contains($normalized)) -or ($exe -and $exe.StartsWith($normalized))) {
            $results += [pscustomobject]@{
                Name        = $proc.Name
                Id          = $proc.ProcessId
                CommandLine = $proc.CommandLine
            }
        }
    }
    return $results
}

function Ensure-RepoDirectoryIsFree {
    param([string]$Path)
    $attempt = 0
    while ($true) {
        $lockers = Get-ProcessesUsingPath -Path $Path
        if (-not $lockers -or $lockers.Count -eq 0) {
            return
        }

        Write-Host ""; Write-Host "The following processes are using ${Path}:" -ForegroundColor Yellow
        $lockers | Select-Object Name, Id, CommandLine | Format-Table -AutoSize | Out-String | Write-Host

        $response = Read-Host "Close these processes automatically? [Y/n]"
        if ($response -match '^[Nn]') {
            throw "Cannot continue while processes are locking $Path. Close them manually and rerun."
        }

        foreach ($proc in $lockers) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host ("Stopped {0} (PID {1})." -f $proc.Name, $proc.Id) -ForegroundColor Yellow
            } catch {
                Write-Warning ("Unable to stop {0} (PID {1}): {2}" -f $proc.Name, $proc.Id, $_.Exception.Message)
            }
        }
        Start-Sleep -Seconds 2
        $attempt++
        if ($attempt -ge 3) {
            throw "Processes continue to use $Path after multiple attempts. Close them manually and rerun."
        }
    }
}

function Ensure-GitHubAuthentication {
    $statusOutput = try {
        & gh auth status --hostname github.com 2>&1
    } catch {
        $_.Exception.Message
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GitHub CLI is not authenticated. Launching browser login..." -ForegroundColor Yellow
        gh auth login --hostname github.com --git-protocol https --web --scopes "repo,workflow,admin:org"
        if ($LASTEXITCODE -ne 0) {
            throw "GitHub authentication failed."
        }
    }
}

function Ensure-RepositoryExists {
    gh repo view $SandboxRepo --json name *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }
    Write-Host "GitHub repository '$SandboxRepo' not found. Creating it now..." -ForegroundColor Yellow
    gh repo create $SandboxRepo --private --source $RepoDir --push --confirm --disable-wiki --disable-issues
    if ($LASTEXITCODE -ne 0) {
        throw "Automatic repository creation failed. Create the repo manually and rerun."
    }
    Write-Host "Repository '$SandboxRepo' created." -ForegroundColor Green
}

Push-Location $RepoDir
try {
    Ensure-GitHubAuthentication
    Ensure-RepositoryExists
    Ensure-RepoDirectoryIsFree -Path $RepoDir

    $upstreamUrl = "https://github.com/swb2019/ai-dev-platform.git"
    if (-not ((git remote | Select-String -Quiet "^upstream$"))) {
        git remote add upstream $upstreamUrl
    } else {
        git remote set-url upstream $upstreamUrl
    }

    git fetch upstream

    $gitStatus = git status --porcelain
    if ($gitStatus) {
        Write-Host "Working tree contains local changes; resetting to a clean state..." -ForegroundColor Yellow
        git reset --hard HEAD
        git clean -fd
        if (git status --porcelain) {
            throw "Unable to clean working tree automatically. Resolve manually and rerun."
        }
    }

    git checkout main
    git reset --hard upstream/main

    if (-not ((git remote | Select-String -Quiet "^origin$"))) {
        git remote add origin $OriginUrl
    } else {
        git remote set-url origin $OriginUrl
    }

    git push --force-with-lease origin main

    Write-Host "Sandbox repository synchronized with upstream." -ForegroundColor Green
}
finally {
    Pop-Location
}
