# --------------------------------------------------
# Classes
# --------------------------------------------------

Class DockerContainers : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $DockerContainers = docker ps -a --format '{{.Names}}' | Sort
        return [String[]] $DockerContainers
    }
}


# --------------------------------------------------
# Git/GitHub
# --------------------------------------------------

Function Get-GHMetadata {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory)]
        [string]
        $Project
    )

    Invoke-RestMethod "https://raw.githubusercontent.com/${Project}/master/tools/metadata.json"

}

Function Get-GitLog {

    git.exe log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit

}

New-Alias glog Get-GitLog -Force


Function Change-GitFileMod {

    [CmdletBinding()]
    [Alias("gchmx")]
    param (
        [Parameter()]
        [string]
        $FilePath
    )

    git.exe update-index --chmod=+x $FilePath
}

Function Get-GitUncleanRepos {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $RepoRoot = "C:\code"
    )

    Write-Verbose "Checking Git repositories at $RepoRoot for uncommited changes" -Verbose

    $GitDirs = gci -Path $RepoRoot -Recurse -Force -Directory -Filter '.git' | Select -Expand Parent | Where { $_.FullName -notlike '*\.terra*' } | Sort FullName

    Write-Verbose "$($GitDirs.Count) repositories found, checking status" -Verbose

    $UncleanRepos = $GitDirs | ForEach {
        pushd $_.FullName
        If (!(git status | Select-String "nothing to commit, working tree clean")) {
            $_
        }
        popd
    }

    If ($UncleanRepos) {
        Write-Verbose "$($UncleanRepos.Count) unclean repo(s) found" -Verbose
        return $UncleanRepos | Select -Expand FullName
    }

}


# --------------------------------------------------
# Misc
# --------------------------------------------------

Function Convert-Base64 {

    [CmdletBinding()]
    [Alias("base64", "b64")]

    Param(

        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [AllowEmptyString()]
        [Alias('Input')]
        [string[]]$InputString,

        [Parameter(Mandatory = $False)]
        [Alias('d')]
        [switch]$decode

    )

    # Must be wrapped in "process" scriptblock, in order to handle blank lines in pipeline input
    process {

        If ($InputString) {

            If ($decode) {
                Return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($InputString))
            }

            else {
                Return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputString))
            }

        }

    }

}


Function Out-FileUnix {

    [CmdletBinding()]
    [Alias("outlf")]

    Param(

        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [Alias('Path')]
        [string]$FilePath,

        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [AllowEmptyString()]
        [string[]]$InputString,

        [Parameter(Mandatory = $False)]
        [switch]$Append,

        [Parameter(Mandatory = $False)]
        [switch]$Force

    )

    begin {

        If (!$Append) {
            If (Test-Path -Path $FilePath) {
                Remove-Item -Path $FilePath -Force
            }
        }
    }

    # Must be wrapped in "process" scriptblock, in order to handle blank lines in pipeline input
    process {
        # Out-file needs to always append, in order to handle multi-line input
        "$($InputString)`n" | Out-File -FilePath $FilePath -Append -Force:$Force -NoNewline
    }

}


Function Get-EnvironmentVariable {

    [CmdletBinding()]
    [Alias("gev", "Get-Env")]

    param (

        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        # [ValidateNotNullOrEmpty]
        [string[]]$Name,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateSet("User", "Machine")]
        [string]$Scope = "User",

        [switch]$AsObject

    )

    # Get requested variables
    $EnvVars = ForEach ($EnvName in $Name) {
        [Environment]::GetEnvironmentVariable($EnvName, $Scope) | Select-Object @{ N = 'Name'; E = { $EnvName } }, @{ N = 'Value'; E = { $_ } }, @{ N = 'Scope'; E = { $Scope } }
    }

    # Output variables
    If ($AsObject) {
        Return $EnvVars
    }
    else {
        Return $EnvVars | Select-Object -ExpandProperty Value
    }

}


Function Set-EnvironmentVariable {

    [CmdletBinding()]
    [Alias("sev", "Set-Env")]

    param (

        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        # [ValidateNotNullOrEmpty]
        [string]$Name,

        [Parameter(
            Position = 1,
            Mandatory = $True,
            ValueFromPipeline = $False,
            ValueFromPipelineByPropertyName = $True
        )]
        # [ValidateNotNullOrEmpty]
        [string]$Value,

        [Parameter(
            Position = 2,
            Mandatory = $False,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateSet("User", "Machine")]
        [string]$Scope = "User",

        [switch]$AsObject

    )

    Try { [Environment]::SetEnvironmentVariable($Name, $Value, $Scope) }
    Catch { Throw "$($Error[0].Exception.Message)" }

    Return [PSCustomObject]@{
        Name  = $Name
        Value = $Value
        Scope = $Scope
    }

}

Function Set-WindowTitle {

    [CmdletBinding()]
    [Alias("title")]

    Param(
        [string]$WindowTitle
    )

    If (-Not($WindowTitle)) {

        Switch ($PSVersionTable.PSEdition) {

            "Core" { $WindowTitle = "PowerShell Core" }
            default { $WindowTitle = "Windows PowerShell" }

        }

    }

    $host.ui.RawUI.WindowTitle = $WindowTitle

}

Function Download-Video {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $VideoUrl,

        [Parameter()]
        [string]
        # $Output = '~/Videos/%(title)s-%(id)s.%(ext)s',
        $Output = '~/Videos/%(title)s.%(ext)s',

        [string[]]
        $YoutubeDlArgs = @('--write-thumbnail', '--write-description', '--add-metadata', '--all-subs')
    )

    process {
        youtube-dl --output $Output $YoutubeDlArgs $VideoUrl
    }

}


Function Set-PwshModulePath {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ModulePath = (Join-Path -Path (Join-Path -Path $HOME -ChildPath ".powershell") -ChildPath "Modules"),

        [Parameter()]
        [string]
        $ConfigFilePath = (Join-Path -Path (Split-Path $PROFILE.CurrentUserCurrentHost) -ChildPath "powershell.config.json")

    )

    <#
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_config
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath?view=powershell-7.1#powershell-psmodulepath-construction
    https://docs.microsoft.com/en-us/powershell/scripting/developer/module/modifying-the-psmodulepath-installation-path
    #>

    If ($PSVersionTable.PSEdition -eq 'Core') {

        # Create .powershell folder in profile (if missing)
        New-Item $PwshPath -ItemType Directory -Force | Out-Null

        # Determine new content of config file
        If (Test-Path $ConfigFilePath -PathType Leaf) {
            # Add or replace in existing config
            $CurrentPwshConfig = Get-Content $PwshCoreConfigFilePath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
            $CurrentPwshConfig | Add-Member -MemberType NoteProperty -Name PSModulePath -Value $ModulePath -Force
            $NewPwshConfig = $CurrentPwshConfig | ConvertTo-Json
        }
        Else {
            # New config
            $NewPwshConfig = @{PSModulePath = $ModulePath } | ConvertTo-Json
        }

        $NewPwshConfig | Out-file -FilePath $ConfigFilePath

    }
    else {

        Write-Warning "Only relevant for PowerShell Core - no changes made."

    }

}


Function Get-PublicIP {
    Invoke-RestMethod -Uri https://api.ipify.org?format=json | Select -Expand ip
}


Function New-SSHKeyPair {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $FileName,

        [Parameter()]
        [string]
        $Comment = $FileName,

        [Parameter()]
        [ValidateSet('ed25519', 'rsa')]
        [string]
        $Type = 'ed25519',

        [Parameter()]
        [int16]
        $Bits = 4096,

        [Parameter()]
        [string]
        $Path = (Join-Path -Path '~' -ChildPath '.ssh')
    )

    $FilePath = Join-Path -Path (Resolve-Path $Path) -ChildPath $FileName

    If ($Type -eq 'ed25519') {
        & ssh-keygen -t $Type -C $Comment -f $FilePath
    }
    Else {
        & ssh-keygen -t $Type -b $Bits -C $Comment -f $FilePath
    }

}


Function Remove-SSHKnownHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $HostName
    )

    $KnownHostsPath = '~/.ssh/known_hosts'
    Set-Content $KnownHostsPath -Value (Get-Content $KnownHostsPath | Select-String -Pattern "^$HostName," -NotMatch)

}


Function Get-DateTime {

    [CmdletBinding(DefaultParameterSetName = 'DateTime')]

    param (
        [Parameter(
            ParameterSetName = 'DateTime',
            Position = 0
        )]
        [datetime]
        $Date,

        [Parameter(
            ParameterSetName = 'UnixTime',
            Position = 0,
            Mandatory
        )]
        [int64]
        $UnixTime
    )

    # Get specified time or current
    Switch ($PSCmdlet.ParameterSetName) {
        "DateTime" {
            if ($Date) {
                $DateTime = Get-Date -Date $Date
            }
            else {
                $DateTime = Get-Date
            }
        }
        "UnixTime" {
            $InputUnixTime = $UnixTime
            $DateTime = ([datetimeoffset]::FromUnixTimeSeconds($UnixTime)).LocalDateTime
        }
    }

    # Convert time
    $Epoch = ([datetimeoffset]::FromUnixTimeSeconds(0)).DateTime
    $DateTimeUTC = (Get-Date -Date $DateTime).ToUniversalTime()
    $UnixTimeS = [math]::Round((($DateTimeUTC - $Epoch) | Select-Object -Expand TotalSeconds), 3)

    # Return date in various formats
    Return [pscustomobject]@{
        Epoch          = $Epoch
        InputDateTime  = $Date
        InputUnixTime  = $InputUnixTime
        DateTime       = $DateTime
        DateTimeUTC    = $DateTimeUTC
        ISOSortable    = (Get-Date $DateTime -Format u) -replace "Z$", ""
        ISOSortableUTC = (Get-Date $DateTimeUTC -Format u) -replace "Z$", ""
        TimeStamp      = Get-Date -Date $DateTime -Format "yyyyMMdd-HHmmss"
        TimeStampUTC   = Get-Date -Date $DateTimeUTC -Format "yyyyMMdd-HHmmss"
        UnixTime       = [int64]$UnixTimeS
        UnixTimeMs     = [int64]$UnixTimeS * 1000
    }

}

Function Check-BinVersion {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [scriptblock]
        $LocalVerCmd,

        [Parameter(Mandatory)]
        [scriptblock]
        $RemoteVerCmd
    )

    $LocalVer = Invoke-Command $LocalVerCmd
    $RemoteVer = Invoke-Command $RemoteVerCmd

    If ($LocalVer -ne $RemoteVer) {
        Write-Host "${Name} ${RemoteVer} is available (${LocalVer} installed)" -ForegroundColor Yellow
    }

}


Function Remove-TerraDir {

    # Terragrunt cache first (may contain .terraform dirs too)
    $dirs = gci -Recurse -Directory -Filter '.terragrunt-cache'
    Write-Host "Deleting $($dirs.Count) '.terragrunt-cache' dir(s) recursively..." -ForegroundColor Green
    $dirs | rm -Recurse -Force

    # Terraform dirs
    $dirs = gci -Recurse -Directory -Filter '.terraform'
    Write-Host "Deleting $($dirs.Count) '.terraform' dir(s) recursively..." -ForegroundColor Green
    $dirs | rm -Recurse -Force

}


# --------------------------------------------------
# Docker
# --------------------------------------------------

Function Attach-DockerContainer {

    [CmdletBinding()]
    [Alias("adc")]

    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet([DockerContainers])]
        [string]
        $ContainerName
    )

    docker start $ContainerName
    docker attach $ContainerName

}

Function Remove-DockerContainer {

    [CmdletBinding()]
    [Alias("rdc")]

    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet([DockerContainers])]
        [string]
        $ContainerName
    )

    docker stop $ContainerName
    docker rm $ContainerName

}



# --------------------------------------------------
# Strings
# --------------------------------------------------

Function Get-EOLChar {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path
    )

    If ((Get-Content -Raw -Path $Path ).contains("`r`n")) {
        Return '`r`n'
    }

    If ((Get-Content -Raw -Path $Path ).contains("`n")) {
        Return '`n'
    }
    else {
        Write-Warning "No EOL character detected"
        Return ''
    }
}


Function Print-EOLChar {

    [CmdletBinding()]
    [Alias("gceol")]

    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter()]
        [string]
        $EOLColour = 'Magenta'
    )

    $EOLChar = Get-EOLChar -Path $Path

    Switch ($EOLChar) {

        '`r`n' {
            $PrintEOLChar = "$([char]0x240D)$([char]0x2424)"
            (Get-Content -Raw -Path $Path) -split "`r`n" | ForEach {
                Write-Host "$_" -NoNewline
                Write-Host  $PrintEOLChar -ForegroundColor $EOLColour
            }
        }

        '`n' {
            $PrintEOLChar = "$([char]0x2424)"
            (Get-Content -Raw -Path $Path) -split "`n" | ForEach {
                Write-Host "$_" -NoNewline
                Write-Host  $PrintEOLChar -ForegroundColor $EOLColour
            }
        }

    }

}


Function Out-StringWithLineNum {

    [CmdletBinding()]
    [Alias("outln")]

    param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [AllowEmptyString()]
        [Alias('Input')]
        [string[]]$InputString,

        [Parameter()]
        [string]
        $LineNumColour = 'Magenta'

    )

    begin {
        $count = 1
    }

    # Must be wrapped in "process" scriptblock, in order to handle blank lines in pipeline input
    process {
        Write-Host "$($count.ToString().PadLeft(4, ' ')): " -ForegroundColor $LineNumColour -NoNewline
        $InputString
        $count++
    }

    end {
        Return
    }

}
