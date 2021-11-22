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


# --------------------------------------------------
# Aliases
# --------------------------------------------------

New-Alias k kubectl.exe -Force


# --------------------------------------------------
#
# --------------------------------------------------

Function Refresh-Kubeconfig {

    If (Test-Path ~/.kube -PathType Container) {
        $env:KUBECONFIG = (gci ~/.kube/*.config).FullName -join ';'
    }

}
Refresh-Kubeconfig


# --------------------------------------------------
# Functions
# --------------------------------------------------

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


Function Get-KubeIngress {

    $ingresses = k get ingress -A -o json | ConvertFrom-Json -Depth 12
    $ingresses.items | select @{N = 'namespace'; E = { $_.metadata.namespace } }, @{N = 'name'; E = { $_.metadata.name } }, @{N = 'host'; E = { $_.spec.rules.host } }, @{N = 'path'; E = { $_.spec.rules.http.paths.path } }

}


Function Kind {

    $KindKubeconfig = Join-Path -Path (Resolve-Path ~) -ChildPath '.kube/kind.config'

    $KubeconfigCmds = @(
        'create'
        'delete'
        'export'
    )

    if ($KubeconfigCmds -contains $args[0] -and $args[1] -ne 'logs') {
        kind.exe --kubeconfig $KindKubeconfig @args
        Refresh-Kubeconfig
    }
    else {
        kind.exe @args
    }

}
