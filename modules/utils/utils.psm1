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
