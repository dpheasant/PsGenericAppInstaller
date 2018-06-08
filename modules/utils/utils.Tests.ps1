$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.ps1', '.'
import-module -Force "$here"

Describe "utils: Test-CidrMembership" {
    It "returns true when specified address is in the CIDR block" {
        Test-CidrMembership '192.168.1.1' '192.168.1.0/24' | Should -Be $true
    }

    It "returns false when specified address is not in the CIDR block" {
        Test-CidrMembership '192.168.1.254' '192.168.1.0/25' | Should -Be $false
    }

    It "throws an error when the CIDR block is specified incorrectly" {
        {Test-CidrMembership '192.168.1.254' '192.168.1.0'} | Should -Throw
    }
}

Describe "utils: Get-SubnetMaskFromCIDRPrefix" {
    It "returns 255.255.255.0 for the /24 prefix" {
        Get-SubnetMaskFromCIDRPrefix 24 | Should -Be '255.255.255.0'
    }

    It "returns 255.255.252.0 for the /22 prefix" {
        Get-SubnetMaskFromCIDRPrefix 22 | Should -Be '255.255.252.0'
    }

    It "throws an error when the CIDR prefix is out of range" {
        { Get-SubnetMaskFromCIDRPrefix 34 } | Should -Throw
    }
}