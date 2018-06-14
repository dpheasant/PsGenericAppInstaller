$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut  = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.psm1'

import-module -Force (resolve-path "$here/$sut")

$results = start-installation `
        -targetsFile './modules/inputHandlers/test_targets.csv' `
        -sitesFile   './modules/inputHandlers/test_sites.csv' `
        -siteCommandsFile './modules/inputHandlers/test_siteCommands.csv' `
        -installScript 'clientInstall_bootstrap.ps1'

$results | Write-StatusReport -Filename 'results.csv'