$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.'
import-module -Force "$here"

Describe "InputHandlers: Get-Targets" {
    It "throws FileNotFoundException when an input file does not exist" {
        { import-targets -targetsFile fake.csv -sitesFile ./test_sites.csv -siteCommandsFile ./test_siteCommands.csv } | Should -throw -ExceptionType ([System.IO.FileNotFoundException])
    }

    $targets = import-targets -targetsFile ./test_targets.csv -sitesFile ./test_sites.csv -siteCommandsFile ./test_siteCommands.csv
    
    It "returns a list of all 50 targets" {
        $targets.count | Should -Be 50
    }

    It "properly correlates site1 client target to site1" {
        $target = $targets | where-object {$_.fqdn -eq 'client1.site1.domain.com'}
        $target.siteId | should -be 'site1'
    }

    It "properly correlates site2 client target to site2" {
        $target = $targets | where-object {$_.fqdn -eq 'client4.site2.domain.com'}
        $target.siteId | should -be 'site2'
    }

}
