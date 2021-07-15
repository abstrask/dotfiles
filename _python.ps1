Function New-PythonProject {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Path
    )

    If ($Path) {
        If (!(Test-Path -Path $Path -PathType Container)) {
            New-Item -Path $Path -ItemType Container | Out-Null
        }
        Set-Location -Path $Path
    }

    poetry init --no-interaction
    poetry add --dev flake8 black pylint mypy

}