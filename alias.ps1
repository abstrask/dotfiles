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

New-Alias grep Select-String -Force
New-Alias k kubectl.exe -Force
New-Alias g git.exe -Force
New-Alias m multipass.exe -Force


# --------------------------------------------------
# Git
# --------------------------------------------------

# git.exe update-index --chmod=+x