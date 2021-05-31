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
    & ssh-keygen -t $Type -b $Bits -C $Comment -f $FilePath

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
    $dirs = gci -Recurse -Directory | ? { $_.Name -eq '.terragrunt-cache' }
    Write-Host "Deleting $($dirs.Count) '.terragrunt-cache' dir(s) recursively..." -ForegroundColor Green
    $dirs | rm -Recurse -Force

    # Terraform dirs
    $dirs = gci -Recurse -Directory | ? { $_.Name -eq '.terraform' }
    Write-Host "Deleting $($dirs.Count) '.terraform' dir(s) recursively..." -ForegroundColor Green
    $dirs | rm -Recurse -Force

}


# --------------------------------------------------
# SSH/1Password
# --------------------------------------------------

Function Signin-1Password {
    Invoke-Expression $(op signin 1rask)
}

Function Get-1PVault {
    op list vaults | ConvertFrom-Json | Select name, uuid | Sort Name
}


Function Get-1PSecureNote {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Vault = 'Private',

        [Parameter()]
        [string]
        $Tags,

        [Parameter()]
        [string]
        $Fields = 'title'

    )

    # Default args
    $1pArgs = @(
        'list', 'items'
        '--categories', 'Secure Note'
        '--vault', $Vault
    )

    # Tags args
    If ($Tags) {
        $1pArgs += @(
            '--tags', $Tags
        )
    }

    op @1pArgs | ConvertFrom-Json | Select-Object -ExpandProperty uuid | ForEach { op get item $_ --fields $Fields } | ConvertFrom-Json

}


<#
Get-1PsecureNote -Tags 'ssh-sync' -Fields 'title,public key,private key'
gci ~/.ssh | ? {$_.Name -ne 'known_hosts' -and $_.Name -ne 'config' -and $_.Extension -ne '.pub'} | % {$_.FullName}


# Create blank secure note
op create item 'Secure Note' $(op get template 'secure note' | op encode) --title "Test SSH" --vault Private --tags ssh-sync
op create item 'Secure Note' $('{"notesPlain":"","sections":[{"fields":[{"k":"string","n":"br6c6faj3tohyyorxhai463z2m","t":"private key"},{"k":"string","n":"5dq64yw6iex34tbzsaolhqi5a4","t":"public key"}],"name":"keypair"}]}' | op encode) --title "Test SSH" --vault Private --tags ssh-sync


$enc = '{"notesPlain":"","sections":[{"fields":[{"k":"string","n":"br6c6faj3tohyyorxhai463z2m","t":"private key","v":"privkey"},{"k":"string","n":"5dq64yw6iex34tbzsaolhqi5a4","t":"public key","v":"pubkey"}],"name":"keypair"}]}' | op encode
op create item 'Secure Note' $enc --title "Test SSH" --vault Private --tags ssh-sync

# Edit item
op edit item bl4ilpgiie53ecgzlkmu3qlkxu $enc --vault Private
# [ERROR] 2020/07/06 00:51:25 Nothing changed. Assignment statement number 1 is not formatted correctly. Use: [<section>.]<field>=<value>
#>