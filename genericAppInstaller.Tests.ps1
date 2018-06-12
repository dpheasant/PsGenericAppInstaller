$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.psm1'
import-module -Force (resolve-path "$here/$sut")

Describe "GenericAppInstaller: Start-Installation" {

    $results = start-installation `
        -targets './modules/inputHandlers/test_targets.csv' `
        -sites   './modules/inputHandlers/test_sites.csv' `
        -siteCommands './modules/inputHandlers/test_siteCommands.csv' `
        -installScript 'test_deploymentScript.ps1'

    It "correctly runs 50 jobs" {
        $results.completed | Should -Be 50
    }
}