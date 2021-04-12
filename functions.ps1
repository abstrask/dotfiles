# --------------------------------------------------
# Init
# --------------------------------------------------

$FunctionScript = $MyInvocation.MyCommand.Source
Write-Host "Running ""$FunctionScript"" (`$FunctionScript)" -ForegroundColor DarkGray


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
        $AwsProfile = 'saml',

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
        $AwsProfile = 'saml',

        [string]
        $AwsRegion = 'eu-west-1'

    )

    kubectl drain $NodeName --ignore-daemonsets --delete-emptydir-data --grace-period=30 --timeout=2m --force
    If ($LASTEXITCODE -eq 0) {
        Set-KubernetesInstanceUnhealthy -NodeName $NodeName -AwsProfile $AwsProfile -AwsRegion $AwsRegion
    }

}


# --------------------------------------------------
# Kubernetes
# --------------------------------------------------

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


Function Set-KubeNamespaceFinalizer {

    [CmdletBinding()]
    [Alias("skf")]

    Param(
        [Parameter(Mandatory)]
        [ValidateSet([KubeNamespaces])]
        [string]$Namespace,

        [string[]]$Finalizer
    )

    If ($Finalizer.Count -gt 0) {
        $FinalizerString = "[""$(${Finalizer} -join '","')""]"
    }
    else {
        $FinalizerString = "[]"
    }

    Write-Debug "Finalizer: $Finalizer (count: $($Finalizer.Count))"
    Write-Debug "FinalizerString: $FinalizerString"

    "{""apiVersion"":""v1"",""kind"":""Namespace"",""metadata"":{""name"":""${Namespace}""},""spec"":{""finalizers"":${FinalizerString}}}" | kubectl replace --raw "/api/v1/namespaces/${Namespace}/finalize" -f -
}


Function Get-KubeFinalizer {

    [CmdletBinding()]
    [Alias("gkf")]

    Param(
        [Parameter(Mandatory)]
        [string]$ResourceType,

        [string]$ResourceName
    )

    Switch ($ResourceType) {
        { @('ns', 'namespace', 'namespaces') -contains $_ } { $FinalizerPath = '.spec.finalizers' }
        Default { $FinalizerPath = '.metadata.finalizers' }
    }

    kubectl get ${ResourceType} ${ResourceName} -o custom-columns="NAME:.metadata.name,FINALIZERS:${FinalizerPath}"

}

Function Remove-KubeFinalizer {

    [CmdletBinding()]
    [Alias("rkf")]

    Param(
        [Parameter(Mandatory)]
        [string]$ResourceType,

        [Parameter(Mandatory)]
        [string]$ResourceName

        # [string]$Finalizer
    )

    Switch ($ResourceType) {
        { @('ns', 'namespace', 'namespaces') -contains $_ } {
            $FinalizerLocation = 'spec'
            $ApiVersion = 'v1'
            $ApiName = 'namespaces'
            $ApiKind = 'Namespace'
        }
        
        Default {
            $FinalizerLocation = 'metadata'
        }
    }

    Switch ($FinalizerLocation) {

        "spec" {
            # If ($Finalizer.Count -gt 0) {
            #     $FinalizerString = "[""$(${Finalizer} -join '","')""]"
            # }
            # else {
            #     $FinalizerString = '[]'
            # }

            # $FinalizerPath = '.spec.finalizers'
            "{""apiVersion"":""${ApiVersion}"",""kind"":""${ApiKind}"",""metadata"":{""name"":""${Namespace}""},""spec"":{""finalizers"":[]}}" | kubectl replace --raw "/api/v1/${ApiName}/${Namespace}/finalize" -f -
        }

        "metadata" {
            # If ($Finalizer.Count -gt 0) {
            #     $FinalizerString = "[""$(${Finalizer} -join '","')""]"
            # }
            # else {
            #     $FinalizerString = 'null'
            # }

            kubectl patch ${ResourceType} ${ResourceName} -p '{\"metadata\":{\"finalizers\":null}}'
            #  kubectl patch crd/MY_CRD_NAME -p '{"metadata":{"finalizers":[]}}' --type=merge
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