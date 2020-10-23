# --------------------------------------------------
# Init
# --------------------------------------------------

$AutorunScript = $MyInvocation.MyCommand.Source
Write-Host "Running ""$AutorunScript"" (`$AutorunScript)" -ForegroundColor DarkGray


# --------------------------------------------------
# Autoload file
# --------------------------------------------------

# Define variables
$ProfilePath = $profile.CurrentUserAllHosts
$LoadCommand = ". $AutorunScript"
$ProfileAppendString = @"


# Load autorun script on launch
$LoadCommand
"@

# Ensure profile folder and script exists
If (-Not(Test-Path (Split-Path $ProfilePath -Parent) -PathType Container)) {
    New-Item (Split-Path $ProfilePath -Parent) -ItemType Directory -Force | Out-Null
}
If (-Not(Test-Path $ProfilePath -PathType Leaf)) {
    New-Item $ProfilePath -ItemType File
}

# Add script to profile script
If ((Get-Content -Path $ProfilePath -ErrorAction SilentlyContinue) -notcontains $LoadCommand) {
    Write-Host "Adding ""$LoadCommand"" to ""$ProfilePath""" -ForegroundColor DarkGray
    $ProfileAppendString | Out-File -Path $ProfilePath -Append
}


# --------------------------------------------------
# Classes
# --------------------------------------------------

Class KubeContexts : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $KubeContexts = Kube-Context -List -NameOnly
        return [String[]] $KubeContexts
    }
}

Class KubeNamespaces : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $KubeNamespaces = Kube-Namespace -List -NameOnly
        return [String[]] $KubeNamespaces
    }
}

Class AwsProfiles : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $AwsProfiles = Aws-Profile -List
        return [String[]] $AwsProfiles
    }
}


# --------------------------------------------------
# Theming
# --------------------------------------------------

# If (Get-Module PowerLine -ListAvailable) {
#     Import-Module PowerLine
#     Set-PowerLinePrompt -SetCurrentDirectory -RestoreVirtualTerminal -Newline -Timestamp
#     Add-PowerLineBlock { New-PromptText { if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { 'N/A' } } -Bg '#FFA500' } -Index 2
#     #Add-PowerLineBlock { New-PromptText { "&curren;$(kubectl.exe config current-context)" } -Bg '#add8e6' } -Index 2
#     Add-PowerLineBlock { New-PromptText { "&curren;$(kubectl.exe config current-context)/$(kubectl.exe config view --minify --output 'jsonpath={..namespace}')" } -Bg '#add8e6' } -Index 2
# }
# Else {
#     Write-Warning "PowerLine module not found, skipping theming"
# }

# If (Get-Module oh-my-posh -ListAvailable) {
#     Import-Module oh-my-posh
#     Set-Theme Paradox
# }
# Else {
#     Write-Warning "oh-my-posh module not found, skipping theming"
# }

Invoke-Expression (&starship init powershell)


# --------------------------------------------------
# AWS
# --------------------------------------------------

Function Aws-Profile {

    [CmdletBinding(DefaultParameterSetName = 'List')]
    [Alias("awp")]

    Param(

        [Parameter(
            ParameterSetName = 'Set',
            Mandatory = $True,
            Position = 0
        )]
        # [ArgumentCompleter( { Aws-Profile -List } )]
        [ValidateSet([AwsProfiles])]
        [string]$Profile,

        [Parameter(ParameterSetName = 'Unset', Mandatory = $False)]
        [switch]$Unset,

        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$List
       
    )

    Switch ($PSCmdlet.ParameterSetName) {

        'Set' {
            $env:AWS_PROFILE = $Profile    
        }

        'Unset' {
            $env:AWS_PROFILE = ''
        }

        'List' {
            (Get-Content ~\.aws\config | Select-String -Pattern "\[profile ") -replace '\[profile ', '' -replace '\]', '' | Sort
        }

    }

}

Function Assume-AWSCLIRole {

    [CmdletBinding(DefaultParameterSetName = 'NotARN')]

    param (

        [Parameter(ParameterSetName = 'NotARN', Mandatory = $True)]
        [string]$AccountId,
        
        [Parameter(ParameterSetName = 'NotARN', Mandatory = $False)]
        [string]$RoleName = 'OrgRole'

    )

    Switch ($PSCmdlet.ParameterSetName) {

        'NotARN' {

            $AssumedCreds = (aws.exe sts assume-role --role-arn "arn:aws:iam::$($AccountId):role/$($RoleName)" --role-session-name $AccountId-$RoleName --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text).Split()

            $env:AWS_ASSUMED_ACCESS_KEY_ID = $AssumedCreds[0]
            $env:AWS_ASSUMED_SECRET_ACCESS_KEY = $AssumedCreds[1]
            $env:AWS_ASSUMED_SESSION_TOKEN = $AssumedCreds[2]

        }

    }

}


Function Assume-AwsRole {

    [CmdletBinding(DefaultParameterSetName = 'NotARN')]
    [Alias('awr')]

    param (

        [Parameter(ParameterSetName = 'NotARN', Mandatory = $True)]
        [string]$AccountId,
        
        [Parameter(ParameterSetName = 'NotARN', Mandatory = $False)]
        [string]$RoleName = 'OrgRole',

        [Parameter(ParameterSetName = 'NotARN', Mandatory = $False)]
        [string]
        $SourceProfile,

        [Parameter(ParameterSetName = 'NotARN', Mandatory = $False)]
        [string]
        $DestinationProfile = 'Assume'

    )

    # Use specified AWS profile if defined (else default credential search)
    If ($SourceProfile) {    
        Set-AWSCredential -ProfileName $SourceProfile
    }

    Switch ($PSCmdlet.ParameterSetName) {

        'NotARN' {
            $RoleArn = "arn:aws:iam::${AccountId}:role/${RoleName}"
            Try { $Creds = Use-STSRole -RoleArn $RoleArn -RoleSessionName Assume-Role | Select-Object -Expand Credentials }
            Catch { Throw "Failed to assume role: ($_.Message)" }
            Set-AWSCredential -AccessKey $Creds.AccessKeyId -SecretKey $Creds.SecretAccessKey -SessionToken $Creds.SessionToken -StoreAs $DestinationProfile
            Write-Host "Assumed role stored in '$DestinationProfile' profile"
        }

    }

}


Function Get-AwsEc2Instances {

    [CmdletBinding()]

    param (

        [Parameter(Mandatory = $False)]
        [string]
        $AwsProfile,

        [Parameter(Mandatory = $False)]
        [string[]]
        $Region

    )

    # Use specified AWS profile if defined (else default credential search)
    If ($AwsProfile) {    
        Set-AWSCredential -ProfileName $AwsProfile
    }

    If (-Not($Region)) {
        $Region = Get-AWSRegion | Select-Object -Expand Region | Sort
    }
    Write-Verbose "Querying $($Region.Count) region(s)" -Verbose

    ForEach ($Reg in $Region) {

        Try { Get-EC2Instance -Region $Reg | Select -Expand Instances | Select InstanceId, PrivateDnsName, InstanceType, LaunchTime }
        Catch { <#Write-Warning "$_"#> }

    }

}


function Get-AwsEksImage ([string]$KubernetesVersion = '*', [int]$Latest = 10) {
    #Requires -Module @{ ModuleName = 'AWSPowerShell.NetCore'; ModuleVersion = '4.0.0' }
    Get-EC2Image -Owner amazon -Filter @{ Name = "name"; Values = "amazon-eks-node-${KubernetesVersion}-*" } | Select CreationDate, Name, Description, ImageId | Sort CreationDate -Descending | Select -First $Latest
}


Function Get-AwsRdsInstances {

    [CmdletBinding()]

    param (

        [Parameter(Mandatory = $False)]
        [string]
        $AwsProfile,

        [Parameter(Mandatory = $False)]
        [string[]]
        $Region

    )

    # Use specified AWS profile if defined (else default credential search)
    If ($AwsProfile) {    
        Set-AWSCredential -ProfileName $AwsProfile
    }

    If (-Not($Region)) {
        $Region = Get-AWSRegion | Select-Object -Expand Region | Sort
    }
    Write-Verbose "Querying $($Region.Count) region(s)" -Verbose

    ForEach ($Reg in $Region) {

        Try { Get-RDSDBInstance -Region $Reg -ProfileName $AwsProfile | Select DBInstanceIdentifier, DBInstanceClass, Engine, InstanceCreateTime }
        Catch { <#Write-Warning "$_"#> }

    }

}


Function Get-AwsAccount {

    [CmdletBinding()]

    param (

        [Parameter(Mandatory = $False)]
        [string]
        $AwsProfile

    )

    # Use specified AWS profile if defined (else default credential search)
    If ($AwsProfile) {    
        Set-AWSCredential -ProfileName $AwsProfile
    }

    Get-ORGAccountList -AWSProfileName $AwsProfile | Select-Object Name, Id | Sort-Object Name

}


Function Set-KubernetesInstanceUnhealthy {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory)]
        [string]
        $NodeName,

        [string]
        $AwsProfile = 'oxygen-orgrole',

        [string]
        $AwsRegion = 'eu-west-1'

    )

    # Get Instance id
    $InstanceId = aws --profile $AwsProfile --region $AwsRegion ec2 describe-instances --filters "Name=private-dns-name,Values=$NodeName" --query "Reservations[].Instances[].InstanceId" --output text
    Write-Host "Instance id of '$NodeName' is $InstanceId"

    aws --profile $AwsProfile --region $AwsRegion autoscaling set-instance-health --instance-id $InstanceId --health-status Unhealthy

}


Function Roll-KubernetesNode {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory)]
        [string]
        $NodeName,

        [string]
        $AwsProfile = 'oxygen-orgrole',

        [string]
        $AwsRegion = 'eu-west-1'

    )

    kubectl drain $NodeName --ignore-daemonsets --delete-local-data --grace-period=30 --timeout=2m --force
    If ($LASTEXITCODE -eq 0) {
        Set-KubernetesInstanceUnhealthy -NodeName $NodeName -AwsProfile $AwsProfile -AwsRegion $AwsRegion
    }

}


# --------------------------------------------------
# Kubernetes
# --------------------------------------------------

If (Test-Path ~/.kube -PathType Container) {
    $env:KUBECONFIG = (gci ~/.kube/*.config).FullName -join ';'
} 

Function Kube-Context {

    [CmdletBinding(DefaultParameterSetName = 'List')]
    [Alias('kubectx', 'kctx')]

    Param(

        [Parameter(
            ParameterSetName = 'Set',
            Mandatory = $True,
            Position = 0
        )]
        # [ArgumentCompleter( { Kube-Context -List -NameOnly } )]
        [ValidateSet([KubeContexts])]
        [string]$Context,
        
        [Parameter(ParameterSetName = 'Unset', Mandatory = $False)]
        [switch]$Unset,

        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$List,
    
        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$NameOnly

    )

    process {

        Switch ($PSCmdlet.ParameterSetName) {

            'Set' {
                kubectl.exe config use-context $Context
            }

            'List' {
                If ($NameOnly) {
                    (kubectl.exe config get-contexts -o name) -replace 'namespace/', ''
                }
                else {
                    kubectl.exe config get-contexts
                }
            }

        }

    }

}

Function Kube-Namespace {

    [CmdletBinding(DefaultParameterSetName = "List")]
    [Alias("kubens", "kns")]

    Param(

        [Parameter(
            ParameterSetName = 'Set',
            Mandatory = $True,
            Position = 0
        )]
        # [ArgumentCompleter( { Kube-Namespace -List -NameOnly } )]
        [ValidateSet([KubeNamespaces])]
        [string]$Namespace,

        [Parameter(ParameterSetName = 'Unset', Mandatory = $False)]
        [switch]$Unset,

        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$List,
    
        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$NameOnly

    )

    Switch ($PSCmdlet.ParameterSetName) {

        'Set' {
            kubectl.exe config set-context --current --namespace $Namespace
            Set-Variable -Name Namespace -Value $Namespace -Scope Global -Force
        }

        'Unset' {
            kubectl.exe config unset "contexts.$(kubectl.exe config current-context).namespace"
            Remove-Variable -Name Namespace -Scope Global -Force -ErrorAction SilentlyContinue
        }

        'List' {
            If ($NameOnly) {
                (kubectl.exe get namespace -o name) -replace 'namespace/', ''
            }
            else {
                kubectl.exe get namespace
            }
        }

    }

}


# --------------------------------------------------
# Kubernetes sandbox
# --------------------------------------------------

Function Start-K8sSandboxInstances {

    # Add -wait option

    # Start stopped instances
    $StoppedInstances = aws.exe --profile default ec2 describe-instances --filters "Name=tag:Name,Values=k8s-sandbox-*" "Name=instance-state-name,Values=stopped" --query "Reservations[].Instances[].InstanceId" --output text
    If ($StoppedInstances) {
        $StoppedInstances.Split() | % { Write-Host "Starting instance $_"; aws.exe --profile default ec2 start-instances --instance-ids $_ | Out-Null }
    }

}

Function Stop-K8sSandboxInstances {

    # Add -wait option

    # Start stopped instances
    $Instances = aws.exe --profile default ec2 describe-instances --filters "Name=tag:Name,Values=k8s-sandbox-*"  --query "Reservations[].Instances[].InstanceId" --output text
    If ($Instances) {
        $Instances.Split() | % { Write-Host "Stopping instance $_"; aws.exe --profile default ec2 stop-instances --instance-ids $_ | Out-Null }
    }

}


Function Add-K8sSandboxEndpointVariables {

    # Wait for public endpoints to be assigned
    do {
        Start-Sleep 1
        $RunningInstances = aws.exe --profile default ec2 describe-instances --filters "Name=tag:Name,Values=k8s-sandbox-*" "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].[Tags[?Key==``Name``]|[0].Value, NetworkInterfaces[0].Association.PublicDnsName]" --output text
        $RunningInstanceCount = $RunningInstances.Count
        $RunningInstanceWithEndpointCount = ($RunningInstances -match "\sec2-").Count
        Write-Host "$RunningInstanceWithEndpointCount of $RunningInstanceCount running instances have been assigned public endpoints" -Verbose
    } until ($RunningInstanceWithEndpointCount -ge $RunningInstanceCount)

    # Save public DNS names in variables
    $RunningInstances | % { New-Variable -Name $_.Split()[0] -Value $_.Split()[1] -Force -Scope Global }

    Write-Host "`nConnect with:"
    Get-Variable "k8s-sandbox-*" | ForEach {
        Write-Host "ssh -i ~/.ssh/id_rsa_ec2_eu-central-1 ubuntu@`${$($_.Name)}" -ForegroundColor White
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

    & git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit

}

New-Alias glog GetGitLog
# git.exe update-index --chmod=+x

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
        [string]
        $Type = 'rsa',

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

    op @1pArgs | ConvertFrom-Json | Select-Object -ExpandProperty uuid | ForEach {op get item $_ --fields $Fields} | ConvertFrom-Json

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


# --------------------------------------------------
# Other customisations
# --------------------------------------------------

$ErrorView = "ConciseView"

# PSModules path
Set-Env -Name PSModulePath -Value "C:\Users\${env:USERNAME}\.powershell\Modules;C:\Program Files\PowerShell\7\Modules"


# --------------------------------------------------
# Aliases
# --------------------------------------------------

New-Alias grep Select-String -Force
New-Alias k kubectl.exe -Force
New-Alias g git.exe -Force
New-Alias m multipass.exe -Force


# --------------------------------------------------
#
# --------------------------------------------------

# Check if using latest version
# $LatestVersion = (Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/metadata.json).StableReleaseTag -replace "v", ""
# $CurrentVersion = $PSVersionTable.PSVersion.ToString()
# If ($LatestVersion -ne $CurrentVersion) {
#     Write-Host "PowerShell Core $LatestVersion is available" -ForegroundColor Yellow
# }

$Bin = @()
$Bin += @{
    Name         = 'Kubectl'
    LocalVerCmd  = { (((& kubectl version --client --short).Split(' '))[2]) }
    RemoteVerCmd = { (Invoke-WebRequest "https://storage.googleapis.com/kubernetes-release/release/stable.txt").Content.Trim() }
}
$Bin += @{
    Name         = 'K9s'
    LocalVerCmd  = { "v" + (& k9s version --short | Select-String -Pattern '^Version\s+(.+)').Matches.Groups[1].Value }
    RemoteVerCmd = { (Invoke-RestMethod "https://api.github.com/repos/derailed/k9s/releases/latest").tag_name }
}
$Bin += @{
    Name         = 'Saml2aws'
    LocalVerCmd  = { "v" + (& saml2aws --version 2>&1) }
    RemoteVerCmd = { (Invoke-RestMethod "https://api.github.com/repos/versent/saml2aws/releases/latest").tag_name }
}
# $Bin += @{
#     Name         = 'Helm'
#     LocalVerCmd  = { ((((& helm version --client --short).Split(' '))[1]).Split('+'))[0] }
#     RemoteVerCmd = { (Invoke-RestMethod "https://api.github.com/repos/helm/helm/releases/latest").tag_name }
# }

Write-Host 'Check for tool updates: ' -NoNewline
Write-Host '$Bin | % { Check-BinVersion @_ }' -ForegroundColor Yellow


# --------------------------------------------------
# To do
# --------------------------------------------------

<#
Dynamic arguments with better auto-completion?
https://martin77s.wordpress.com/2014/06/09/dynamic-validateset-in-a-dynamic-parameter/
#>

# Write-Host "`n"