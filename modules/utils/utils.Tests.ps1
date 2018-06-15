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

Describe "utils: Copy-ObjectProperty" {

    $sourceObj = New-Object -type PSObject -Property @{
        prop1 = 'value1'
        prop2 = @(1,2,3,4)
        prop3 = @{a='a'; b='b'; c='c'}
        prop4 = New-Object -type PSObject -Property @{subprop1='sub-property value 1'}
    }

    $sourceProps = $sourceObj | Get-Member -type Properties | Select-Object -ExpandProperty Name

    It "copies all properties to object" {
        $destObj = new-object -type psobject
        $destObj | Copy-ObjectProperty -SourceObject $sourceObj
        $destProps = $destObj | Get-Member -type Properties | Select-Object -ExpandProperty Name

        $sourceProps | ?{$destProps -notcontains $_} | Should -Be @()
    }

    It "excludes properties from copy" {
        $destObj = new-object -type psobject
        $destObj | Copy-ObjectProperty -SourceObject $sourceObj -ExcludeProperties 'prop1'
        $destProps = $destObj | Get-Member -type Properties | Select-Object -ExpandProperty Name

        $sourceProps | ?{$destProps -notcontains $_} | Should -Be @('prop1')
    }

    It "clobbers properties during copy" {
        $destObj = new-object -type psobject -Property @{prop1="Clobber me!"}
        $destObj | Copy-ObjectProperty -SourceObject $sourceObj
        
        $destObj.prop1 | Should -Be "value1"
    }

    It "doesn't clobber properties during copy" {
        $destObj = new-object -type psobject -Property @{prop1="Don't clobber me!"}
        $destObj | Copy-ObjectProperty -SourceObject $sourceObj -NoClobber
        
        $destObj.prop1 | Should -Be "Don't clobber me!"
    }

}