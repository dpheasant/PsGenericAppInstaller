$here = Split-Path -Parent $MyInvocation.MyCommand.Path
import-module -Force (resolve-path "$here/genericAppInstaller.psd1")
$inputParentPath = 'C:\scripts\bootstrap\'
$results = start-installation `
        -targetsFile (Join-Path $inputParentPath -ChildPath 'lab_targets.csv') `
        -sitesFile   (Join-Path $inputParentPath -ChildPath 'lab_sites.csv') `
        -siteCommandsFile (Join-Path $inputParentPath -ChildPath 'lab_siteCommands.csv') `
        -installScript "$here\clientInstall_bootstrap.ps1"
        

$results | Write-StatusReport -Filename 'results.csv'
