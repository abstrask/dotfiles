# --------------------------------------------------
# Init
# --------------------------------------------------

$AutorunScript = $MyInvocation.MyCommand.Source
Write-Host "Running ""$AutorunScript"" (`$AutorunScript)" -ForegroundColor DarkGray
$PathSeparator = [System.IO.Path]::PathSeparator
$DirSeparator = [System.IO.Path]::DirectorySeparatorChar
$MyDocsPath = [Environment]::GetFolderPath('MyDocuments')
$DotfilesPath = Split-Path -Path $AutorunScript


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
# PSModulePath
# --------------------------------------------------

# It seems PowerShell/AWS Tools installer does not respect removing Documents from the per-user modules path. FFS!

# PSModules path
# $ModulesPath = "C:\Users\${env:USERNAME}\.powershell\Modules"
# New-Item $ModulesPath -ItemType Directory -Force | Out-Null
# [Environment]::SetEnvironmentVariable("PSModulePath", $ModulesPath, "User")

# Remove Documents entry from module path
# $MyDocsPath = [Environment]::GetFolderPath('MyDocuments')
# $env:PSModulePath = ($env:PSModulePath -split $PathSeparator | Where-Object { $_ -ne "${MyDocsPath}\PowerShell\Modules" }) -join $PathSeparator


# --------------------------------------------------
# Load functions
# --------------------------------------------------

Get-ChildItem -Path $DotfilesPath -Filter _*.ps1 | ForEach {
    Write-Host "Running ""$($_.FullName)""" -ForegroundColor DarkGray
    . $_.FullName
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

If (Get-Module oh-my-posh -ListAvailable) {
    Import-Module oh-my-posh
    Set-PoshPrompt aliens
}
Else {
    Write-Warning "oh-my-posh module not found, skipping theming"
}

# Invoke-Expression (&starship init powershell)


# --------------------------------------------------
# Other customisations
# --------------------------------------------------

$ErrorView = "ConciseView"


# --------------------------------------------------
# Aliases
# --------------------------------------------------

New-Alias grep Select-String -Force
New-Alias g git.exe -Force
New-Alias m multipass.exe -Force
New-Alias python3 python.exe -Force
New-Alias notepad++ 'C:\Program Files\Notepad++\notepad++.exe' -Force


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
    LocalVerCmd  = { (& k9s version --short | Select-String -Pattern '^Version\s+(.+)').Matches.Groups[1].Value }
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