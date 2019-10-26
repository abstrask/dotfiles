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
        [ArgumentCompleter( { Aws-Profile -List } )]
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

Function Assume-AWSRole {

    [CmdletBinding(DefaultParameterSetName = 'NotARN')]
    [Alias("awr")]

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
        [ArgumentCompleter( { Kube-Context -List -NameOnly } )]
        [string]$Context,

        [Parameter(ParameterSetName = 'Unset', Mandatory = $False)]
        [switch]$Unset,

        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$List,
    
        [Parameter(ParameterSetName = 'List', Mandatory = $False)]
        [switch]$NameOnly

    )

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

Function Kube-Namespace {

    [CmdletBinding(DefaultParameterSetName = "List")]
    [Alias("kubens", "kns")]

    Param(

        [Parameter(
            ParameterSetName = 'Set',
            Mandatory = $True,
            Position = 0
        )]
        [ArgumentCompleter( { Kube-Namespace -List -NameOnly } )]
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
            kubectl.exe config set-context (kubectl.exe config current-context) --namespace $Namespace
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
    $RunningInstances | % { New-Variable -Name $_.Split()[0] -Value $_.Split()[1] -Force -Scope Global}

    Write-Host "`nConnect with:"
    Get-Variable "k8s-sandbox-*" | ForEach {
        Write-Host "ssh -i ~/.ssh/id_rsa_ec2_eu-central-1 ubuntu@`${$($_.Name)}" -ForegroundColor White
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
    } else {
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
    Catch {Throw "$($Error[0].Exception.Message)"}

    Return [PSCustomObject]@{
        Name = $Name
        Value = $Value
        Scope = $Scope
    }

}


# --------------------------------------------------
# Misc
# --------------------------------------------------

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


# --------------------------------------------------
# Aliases
# --------------------------------------------------

. (Join-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent) -ChildPath 'alias.ps1')


# --------------------------------------------------
# To do
# --------------------------------------------------

<#
Dynamic arguments with better auto-completion?
https://martin77s.wordpress.com/2014/06/09/dynamic-validateset-in-a-dynamic-parameter/
#>

Write-Host "`n"