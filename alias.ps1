# --------------------------------------------------
# Init
# --------------------------------------------------

$AliasScript = $MyInvocation.MyCommand.Source
Write-Host "Running ""$AliasScript"" (`$AliasScript)" -ForegroundColor DarkGray


# --------------------------------------------------
# Kubernetes
# --------------------------------------------------

If (Test-Path ~/.kube -PathType Container) {
    $env:KUBECONFIG = (gci ~/.kube/*.config).FullName -join ';'
} 


# --------------------------------------------------
# Aliases
# --------------------------------------------------

New-Alias -Name k -Value kubectl.exe -Force
New-Alias -Name g -Value git.exe -Force


# --------------------------------------------------
# Git
# --------------------------------------------------

# git.exe update-index --chmod=+x