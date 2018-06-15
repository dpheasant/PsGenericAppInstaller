function Test-CidrMembership {
    Param(
        [IPAddress] $ip,
        [String]    $cidrAddress
    )

    ## split in slash
    $tokens = $cidrAddress.split('/')

    if($tokens.length -ne 2) {
        throw "Invalid CIDR address specified. Must be in format x.x.x.x/xx"
    }

    $subnet = [IPAddress] $tokens[0]
    $mask   = Get-SubnetMaskFromCIDRPrefix $tokens[1]

    return $(($ip.address -band $mask.address) -eq ($subnet.address -band $mask.address))
}

function Get-SubnetMaskFromCIDRPrefix {
    Param(
        [int] $prefix
    )

    if($prefix -gt 32) {
        throw "CIDR prefix is out of range. Expected value between 0 and 32. Got $prefix"
    }

    $maskBytes = [BitConverter]::GetBytes([uint32]::MaxValue -shl $(32 - $prefix))
    [Array]::Reverse($maskBytes) # Convert byte array to network order (most->least sigficant)
    return [IPAddress]$maskBytes
}

function Copy-ObjectProperty {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object] $InputObject,

        [Parameter(Mandatory=$true)]
        [object] $SourceObject,

        [Parameter(Mandatory=$false)]
        [string[]] $IncludeProperties,

        [Parameter(Mandatory=$false)]
        [string[]] $ExcludeProperties,

        [Parameter(Mandatory=$false)]
        [switch] $NoClobber
    )

    begin {
        ## build a list of property names to copy
        if($IncludeProperties) {
            $properties = $IncludeProperties
        } else {
            $properties = $sourceObject | Get-Member -type Properties | Select-Object -ExpandProperty Name
        }

        ## filter excluded properties
        $properties = $properties | ?{$ExcludeProperties -notcontains $_}
    }

    process {
        ## list InputObject's existing properties
        $inputProperties = $InputObject | Get-Member -type Properties | Select-Object -ExpandProperty Name

        ## copy/add SourceObject properties to InputObject
        foreach($property in $properties) {
            if(($inputProperties -contains $property) -and (-not $NoClobber)) {
                $InputObject."$property" = $sourceObject."$property"
            } elseif($inputProperties -notcontains $property) {
                $InputObject | add-member -type NoteProperty -Name $property -Value $sourceObject."$property"
            }
        }
    }
}