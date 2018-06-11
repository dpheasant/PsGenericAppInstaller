$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.psm1'
import-module -Force (resolve-path "$here/$sut")

Describe "GenericAppInstaller: Start-Installation" {


    start-installation -targets ./modules/inputHandlers/test_targets.csv -sites ./modules/inputHandlers/test_sites.csv -siteCommands ./modules/inputHandlers/test_siteCommands.csv

    It "does something" {
        $true| Should -Be $false
    }

}