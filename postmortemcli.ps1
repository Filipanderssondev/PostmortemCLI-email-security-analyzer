# for windows use/test
# Run with: postmortemcli start

param(
    [string]$Command
)

$IMAGE = "postmortem"
$PROJECT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
# Split-Path = gets the folder where this script lives
# Same as $(dirname "$0") in bash

switch ($Command) {
    "start" {
        podman run -it --rm `
            -v "${PROJECT_ROOT}:/data" `
            $IMAGE `
            bash
        # backtick ` = line continuation in PowerShell (same as \ in bash)
    }
    default {
        Write-Host ""
        Write-Host "Usage: postmortemcli start"
        Write-Host ""
    }
}