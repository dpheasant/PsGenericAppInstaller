$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.psm1'
import-module "$here\$sut"

Describe "InputHandlers: Get-Targets" {
    It "throws an error when the file does not exist" {
        $true | Should -Be $false
    }

    It "throws an error when the file is formatted incorrectly" {
        $true | Should -Be $false
    }

    It "returns a list of targets" {
        $true | Should -Be $false
    }
}
