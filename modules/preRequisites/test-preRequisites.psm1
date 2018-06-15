$logOutPutType = "CSV"
$logShowLevel  = "info"
$logOutputPath = $env:TEMP
New-Alias log write-log -Force



<#
.Synopsis
   This function will test the server side pre-requisites for successful client application istallation. This includes dns name resolution,
   layer 3 network connectivity, remote powershell listener, and smb test (defaults to administrative c share).
.EXAMPLE
   "server1.company.local" | test-preRequistes

    clientFqdn     : server1.company.local
    dnsTest        : True
    connectionTest : True
    remotePsTest   : True
    smbTest        : True

    This example passes a fqdn to the function. The function uses the defaults of no specified dns server, A records only, PS remote port 5985,
    smb port 445, and default administrative share of \\server1.company.local\c$. The returned result is a custom ps object.
.EXAMPLE
    "server1.company.local" | test-preRequistes -dnsServer companydc01.company.local -noSmbTest

    clientFqdn     : server1.company.local
    dnsTest        : True
    connectionTest : True
    remotePsTest   : True
    smbTest        : Not Tested

    This example is the same as the previous with the exception that it specifies a DNS server to use by name and does not test the client for
    valid smb shares.

.PARAMETER clientFQDN
    This parameter is the fully qualified domain name (fqdn) of the client to test. It must be a fqdn or the dns test will fail.
.PARAMETER dnsServer
    This parameter specifies a dns server to use for the dns test. If no server is specified then it will use the primary dns server on the host running
    the function.
.PARAMETER dnsRecordType
    This parameter is the DNS record type to check for a response. Currently only A records are fully supported for use with this function.
.PARAMETER remotePsPort
    This parameter specifies the wsMan port for remote powershell connections.
.PARAMETER noSmbTest
    This parameter will prevent the SMB tests from executing.
.PARAMETER smbPort
    This parameter specifies the client listening port for the SMB protocol.
.PARAMETER smbShareName
    This parameter specifies the share name to test the SMB protocol with. It should not contain any backslashes or hostnames.  
#>

function test-preRequisites () {
    [cmdletBinding()]
    [OutputType([psObject])]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN,
        [string]$dnsServer,
        [validateSet("A","AAAA")]
        [string]$dnsRecordType = "A",
        [int]$remotePsPort = 5985,
        [switch]$noSmbTest,
        [int]$smbPort = 445,
        [string]$smbShareName = 'c$'
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
        $testPreReqResult = "" | Select-Object "clientFqdn","dnsTest","connectionTest","remotePsTest","smbTest"
        "Test Result psObject created." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        "Starting pre-requisites test for client: $clientFQDN" | log
        $testPreReqResult.clientFqdn = $clientFQDN
        "Client FQDN set." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}

        "Starting dns test for $clientFQDN." | log
        $dnsTestParams = @{ clientFqdn = $clientFQDN }
        if ($dnsServer) {$dnsTestParams.Add("dnsServer",$dnsServer); "$clientFQDN using dns server: $dnsServer" | log}
        "DNS test parameter block complete" | log -l 6 -cf @{'dnsParams' = $dnsTestParams}
        $testPreReqResult.dnsTest = test-dns @dnsTestParams
        if ($testPreReqResult.dnsTest) {
            "DNS check complete: $($testPreReqResult.dnsTest)" | log
        } else {
            "DNS check complete: $($testPreReqResult.dnsTest)" | log -l 3
        }
        "DNS check for $clientFQDN set." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}

        "Starting connection test for $clientFQDN." | log
        $connectionTestParams = @{ clientFqdn = $clientFQDN }
        "Connection test parameter block for $clientFQDN complete" | log -l 6 -cf @{'connectionTestParams' = $connectionTestParams}
        $testPreReqResult.connectionTest = test-connection @connectionTestParams
        if ($testPreReqResult.connectionTest) {
            "Connection test check for $clientFQDN complete: $($testPreReqResult.connectionTest)" | log
        } else {
            "Connection test check for $clientFQDN complete: $($testPreReqResult.connectionTest)" | log -l 3
        }
        "Connection check for $clientFQDN set." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}

        "Starting remotePs test for $clientFQDN." | log
        $remotePsTestParams = @{  
            clientFqdn   = $clientFQDN
            wsManPort = $remotePsPort
        }
        "Remote PS test parameter block for $clientFQDN complete" | log -l 6 -cf @{'remotePSTestParams' = $remotePsTestParams}
        $testPreReqResult.remotePsTest = test-remotePs @remotePsTestParams
        if ($testPreReqResult.remotePsTest) {
            "Remote PS test for $clientFQDN check complete: $($testPreReqResult.remotePsTest)" | log
        } else {
            "Remote PS test for $clientFQDN check complete: $($testPreReqResult.remotePsTest)" | log -l 3
        }
        "Remote PS check for $clientFQDN set." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}

        if (!$noSmbTest) {
            "Starting SMB test for $clientFQDN." | log
            if (!$smbShareName) {Throw "Must provide smbShareName if testing SMB!"}
            $smbTestParams = @{  
                clientFqdn      = $clientFQDN
                smbPort         = $smbPort
                clientShareName = $smbShareName
            }
            "SMB test parameter block for $clientFQDN complete" | log -l 6 -cf @{'smbTestParams' = $smbTestParams}
            $testPreReqResult.smbTest = test-smb @smbTestParams
            if ($testPreReqResult.smbTest) {
                "SMB test check for $clientFQDN complete: $($testPreReqResult.smbTest)" | log
            } else {
                "SMB PS test check for $clientFQDN complete: $($testPreReqResult.smbTest)" | log -l 3
            }
        } else {
            $testPreReqResult.smbTest = "Not Tested"
            "SMB test flag for $clientFQDN set to not test. Skipped SMB test." | log
        }
        "SMB check set." | log -l 6 -cf @{'testPreReqResult' = $testPreReqResult}
    }

    end {
        "Pre-Requisite check for client $clientFQDN complete." | log
        return $testPreReqResult
    }
}

function test-dns () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN,
        [string]$dnsServer,
        [validateSet("A","AAAA")]
        [string]$dnsRecordType = "A"
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
        $dnsTestResult = $false
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        $dnsParams = @{
            name         = $clientFQDN
            type         = $dnsRecordType
            dnsOnly      = $true
            noHostsFile  = $true
            quickTimeout = $true
        }
        if ($dnsServer) {
            $dnsParams.Add("server",$dnsServer)
        }
        try {
            $dnsQuery = Resolve-DnsName @dnsParams -ErrorAction Stop
        } catch {}

        if ($dnsQuery) {
            $dnsTestResult = $true
        }
    }
    end {
        return $dnsTestResult
    }  
}

function test-connection () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        $connectionParams = @{
            computerName     = $clientFQDN
            informationLevel = "Quiet"
            warningAction    = "silentlyContinue"
        }
        try {
            $global:ProgressPreference=’SilentlyContinue’
            $connectionTest = Test-NetConnection @connectionParams -ErrorAction Stop
            $global:ProgressPreference=’Continue’
        } catch {}
    }

    end {
        return $connectionTest
    }  
}

function test-tcpPort () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN,
        [parameter(mandatory = $true)]
        [int]$port
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        $tcpPortParams = @{
            computerName     = $clientFQDN
            informationLevel = "Quiet"
            port             = $port
            warningAction    = "silentlyContinue"
        }
        try {
            $global:ProgressPreference=’SilentlyContinue’
            $tcpPortTest = Test-NetConnection @tcpPortParams -ErrorAction Stop
            $global:ProgressPreference=’Continue’
        } catch {}
    }

    end {
        return $tcpPortTest
    }  
}

function test-smb () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN,
        [parameter(mandatory = $true)]
        [string]$clientShareName,
        [int]$smbPort = 445
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
        $smbTest = $false
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        $tcpPortParams = @{
            clientFqdn       = $clientFQDN
            port             = $smbPort
        }
        $smbPortTest = test-tcpPort @tcpPortParams
        if ($smbPortTest) {
            $smbString = "\\$clientFQDN\$clientShareName"
            $smbPathTest = Test-Path -Path $smbString
            if ($smbPathTest) {
                $smbTest = $true
            }
        }
    }

    end {
        return $smbTest
    }
}

function test-remotePs () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [string]$clientFQDN,
        [int]$wsManPort = 5985
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
        $remotePsTest = $false
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientFQDN)
        $tcpPortParams = @{
            clientFqdn       = $clientFQDN
            port             = $wsManPort
        }
        $wsManPortTest = test-tcpPort @tcpPortParams
        if ($wsManPortTest) {
            try{
                $testWsMan = Test-WSMan -ComputerName $clientFQDN -ErrorAction Stop
            } catch {}

            if ($testWsMan) {
                $remotePsTest = $true
            }
        }
    }

    end {
        return $remotePsTest
    }
}

Export-ModuleMember -Function test-preRequisites