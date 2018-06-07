$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', ''
import-module "$here\$sut"

Describe "inputHandlers" {
    It "does something useful" {
        $true | Should -Be $false
    }
}
