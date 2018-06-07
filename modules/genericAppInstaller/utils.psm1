function Test-CidrMembership {
    Param(
        [IPAddress] $ip,
        [String]    $cidrAddress
    )

    ## split 
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

    $maskBytes = [BitConverter]::GetBytes([uint32]::MaxValue -shl $(32 - $prefix))
    [Array]::Reverse($maskBytes) # Convert byte array to network order (most->least sigficant)
    return [IPAddress]$maskBytes
}
