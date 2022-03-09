# --------------------------------------------------
# Classes
# --------------------------------------------------

Class AwsProfiles : System.Management.Automation.IValidateSetValuesGenerator {
    [String[]] GetValidValues() {
        $AwsProfiles = Aws-Profile -List
        return [String[]] $AwsProfiles
    }
}


# --------------------------------------------------
# Enable auto-complete for AWS CLI
# --------------------------------------------------

# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-completion.html#cli-command-completion-windows

Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $env:COMP_LINE = $wordToComplete
    $env:COMP_POINT = $cursorPosition
    aws_completer.exe | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
    Remove-Item Env:\COMP_LINE
    Remove-Item Env:\COMP_POINT
}


# --------------------------------------------------
# Functions
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
        $Region = Get-AWSRegion | Where { $_.Region -notlike '*-iso*' } | Select-Object -Expand Region | Sort
    }
    Write-Verbose "Querying $($Region.Count) region(s)" -Verbose

    ForEach ($Reg in $Region) {
        Write-Verbose "Querying $Reg region"
        Try { Get-EC2Instance -Region $Reg | Select -Expand Instances | Select <#InstanceId, PrivateDnsName,#> InstanceType, LaunchTime, State, @{N = 'Region'; E = { $Reg } } }
        Catch { <#Write-Warning "$_"#> }

    }

}


function Get-AwsEksImage ([string]$KubernetesVersion = '*', [int]$Latest = 10) {
    #Requires -Module @{ ModuleName = 'AWS.Tools.Common'; ModuleVersion = '4.1.5.0' }
    #Requires -Module @{ ModuleName = 'AWS.Tools.EC2'; ModuleVersion = '4.1.5.0' }
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


Function Get-KubeConfigFromSSM {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory)]
        [string]
        $ClusterName
    )

    Get-SSMParameter -Name "/eks/${ClusterName}/deploy_user" -WithDecryption $true | Select -Expand Value | Out-FileUnix "~/.kube/${ClusterName}.config"

}