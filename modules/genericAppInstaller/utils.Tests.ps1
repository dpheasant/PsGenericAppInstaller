$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', ''
import-module "$here\$sut"

Describe "utils: Test-CidrMembership" {
    It "returns true when specified address is in the CIDR block" {
        $true | Should -Be $false
    }

    It "returns false when specified address is not in the CIDR block" {
        $true | Should -Be $false
    }

    It "throws an error when the CIDR block is specified incorrectly" {
        $true | Should -Be $false
    }
}

Describe "utils: Get-SubnetMaskFromCIDRPrefix" {
    It "returns 255.255.255.0 for the /24 prefix" {
        $true | Should -Be $false
    }

    It "returns 255.255.252.0 for the /22 prefix" {
        $true | Should -Be $false
    }

    It "throws an error when the CIDR prefix is out of range" {
        $true | Should -Be $false
    }
}