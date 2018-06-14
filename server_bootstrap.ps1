$here = Split-Path -Parent $MyInvocation.MyCommand.Path
import-module -Force (resolve-path "$here/genericAppInstaller.psd1")
write-host (resolve-path "$here/genericAppInstaller.psd1")
$results = start-installation `
        -targetsFile 'C:\scripts\bootstrap\lab_targets.csv' `
        -sitesFile   'C:\scripts\bootstrap\lab_sites.csv' `
        -siteCommandsFile 'C:\scripts\bootstrap\lab_siteCommands.csv' `
        -installScript 'C:\scripts\PsGenericAppInstaller\clientInstall_bootstrap.ps1'

$results | Write-StatusReport -Filename 'results.csv'
