$logOutPutType = "CSV"
$logShowLevel  = "debug"
New-Alias log write-log -Force

$clientDataSample = New-Object -Type psObject -Property @{
    'fqdn'                = 'mgmt01.lab2.qtr.ad'
    'siteId'              = 'Site1'
    'logFileRegEx'        = 'Client installation completed SUCCESSFULLY'
    'logFileSearchScript' = ''
    'logFileLocation'     = "$env:TEMP\LogFileExample.txt"
    'executionCmdLine'    = 'msiexec /I AdaptivaP2PClientInstaller.msi /q SERVERNAME=c0004513.corp.ds.fedex.com SOURCEUNCPATH=\\c0005280.corp.ds.fedex.com\source$\adaptiva\AdaptivaClientSetup.exe WAITFORCOMPLETION=1'
    'packageLocation'     = '\\c0005280.corp.ds.fedex.com\source$\adaptiva\'
    'packageID'           = 'B57097EF-5F38-348C-8081-4D0F0B78757E'
    'detectionScript'     = 'Test-Path HKLM:\SYSTEM\Software\'
}

function start-clientIntallTasks () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [psObject]$clientData,
        [string]$serverStagingPath = $env:TEMP,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [psCredential]$sessionCredential,
        [ValidateSet("Basic","Credssp","Default","Digest","Kerberos","Negotiate","NegotiateWithImplicitCredential")]
        [string]$sessionAuth
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
        "Starting client install tasks." | log
        $clientStatusObject = New-Object -Type psObject
        "Client output status object created." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
    }

    process {
        "Starting client pre-requisite checks." | log
        $testPreRequisites = $clientData.fqdn | test-preRequisites
        "Client pre-requisite checks complete." | log
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name clientFqdn -Value $testPreRequisites.clientFqdn
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name dnsTest -Value $testPreRequisites.dnsTest
        if (!$clientStatusObject.dnsTest) {
            $message = "DNS Test for $($testPreRequisites.clientFqdn) is False! Ending job."
            $message | log -l 2
            Throw $message
        }
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name connectionTest -Value $testPreRequisites.connectionTest
         if (!$clientStatusObject.connectionTest) {
            $message = "Connection (ping) Test for $($testPreRequisites.clientFqdn) is False! Ending job."
            $message | log -l 2
            Throw $message
        }
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name remotePsTest -Value $testPreRequisites.remotePsTest
         if (!$clientStatusObject.remotePsTest) {
            $message = "Remote PowerShell Test for $($testPreRequisites.clientFqdn) is False! Ending job."
            $message | log -l 2
            Throw $message
        }
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name smbTest -Value $testPreRequisites.smbTest
         if (!$clientStatusObject.dnsTest) {
            "SMB Test for $($testPreRequisites.clientFqdn) is False!" | log -l 3
        }
        "Added pre-requsite checks to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
        Write-Output $clientStatusObject
        "All pre-requisite checks for $($testPreRequisites.clientFqdn) suceeded! Continuing installation." | log

        "Establishing powershell session to $($testPreRequisites.clientFqdn)." | log
        $newPsSessionParams = @{
            clientData             = $clientData
            removeExistingSessions = $true
        }
        if ($sessionCredential) {$newPsSessionParams.Add('sessionCredential',$sessionCredential)}
        if ($sessionAuth) {$newPsSessionParams.Add('sessionAuth',$sessionAuth)}
        "PS Session parameters created for $($testPreRequisites.clientFqdn)." | log -l 6 -cf @{'psSessionParams' = $newPsSessionParams}
        $clientPsSession = new-clientPsSession @newPsSessionParams
        "New PowerShell Session to $($testPreRequisites.clientFqdn) estabished." | log
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'psSessionId' -Value $clientPsSession.id
        Write-Output $clientStatusObject
        "PowerShell session properties: " | log -l 6 -cf @{'psSessionProperties' = $clientPsSession}

        "Testing package install state on $($testPreRequisites.clientFqdn)." | log
        $packageInstallScriptBlock = (Get-Command test-packageInstalled).ScriptBlock
        $invokeCmdParams = @{
            session      = $clientPsSession
            scriptBlock  = $packageInstallScriptBlock
            argumentList = $clientData.packageID
        }
        $testPackageInstall = Invoke-Command @invokeCmdParams

        "Setting environment on $($testPreRequisites.clientFqdn)." | log
        $setEnvParams = @{
            clientPSSession = $clientPsSession
            force           = $true
        }
        "Set Environment parameters created for $($testPreRequisites.clientFqdn)." | log -l 6 -cf @{'psSessionParams' = $setEnvParams}
        $setClientEnv = set-clientEnvironment @setEnvParams
        "Environment set on $($testPreRequisites.clientFqdn)." | log
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'remoteDirectory' -Value $setClientEnv
        Write-Output $clientStatusObject 

    }

    end {
        return $clientStatusObject
    }
}

function set-clientEnvironment () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        $clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [switch]$force
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $cmdInvokeParams = @{
            session     = $clientPSSession
            scriptBlock = [scriptBlock]::Create("Test-Path -Path $clientInstallLocation")
        }
        $clientLocationExists = Invoke-Command @cmdInvokeParams

        if ($clientLocationExists -and $force) {
            do {
                $cmdInvokeParams.scriptBlock = [scriptBlock]::Create("Remove-Item -Recurse -Force -Path $clientInstallLocation -ea 'silentlyContinue'")
                $removeDir = Invoke-Command @cmdInvokeParams
                Start-Sleep -Seconds 1
                $cmdInvokeParams.scriptBlock = [scriptBlock]::Create("Test-Path -Path $clientInstallLocation")
                $clientLocationExists = Invoke-Command @cmdInvokeParams
            } until (!$clientLocationExists)
        }

        if (!$clientLocationExists) {
            do {
                $cmdInvokeParams.scriptBlock = [scriptBlock]::Create("New-Item -ItemType Directory -Path $clientInstallLocation -ea 'silentlyContinue'")
                $makeDir = Invoke-Command @cmdInvokeParams
                Start-Sleep -Seconds 1
                $cmdInvokeParams.scriptBlock = [scriptBlock]::Create("Test-Path -Path $clientInstallLocation")
                $clientLocationExists = Invoke-Command @cmdInvokeParams
            } until ($clientLocationExists)
        }
    }

    end {
        return $clientInstallLocation
    }
}

function copy-installConfigFile () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [psObject]$clientData,
        [parameter(mandatory = $true)]
        [psSession]$clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [string]$fileStagingLocation = $env:TEMP,
        [string]$fileName = "clientInstallConfig"
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
        $fileNameWithExt = "$fileName.json"
        $stagingFilePath = Join-Path $fileStagingLocation -ChildPath $fileNameWithExt
        $clientFilePath  = Join-Path $clientInstallLocation -ChildPath $fileNameWithExt
    }

    process {
        $clientDataJson = $clientData | ConvertTo-Json 
        $jsonFileParams = @{
            filePath = $stagingFilePath
            encoding = "utf8"
            force    = $true
        }
        $createFileStaging = $clientDataJson | Out-File @jsonFileParams

        $copyItemParams = @{
            path        = $stagingFilePath
            destination = $clientFilePath
            toSession   = $clientPSSession
            force       = $true
            errorAction = "silentlyContinue"
        }
        <#
            The reason for the silently continue was a bug introduced in V5.x with the addition of copy-item -tosession functionality. Fortunately this only affects copying to a V2 remote session. 
            The reason for this bug is that the one helper function copied to the remote session uses a script feature that is not available in PowerShell V2 
            (the ability to use '[0]' to select the first element on an non-array type). This is in the PSValidatePathDefinition function:

                    # Get the root path using Get-Item
                    $item = Microsoft.PowerShell.Management\Get-Item $pathToValidate -ea SilentlyContinue
                    if (($item -ne $null) -and ($item[0].PSProvider.Name -eq 'FileSystem'))
                    {
            ...
            $item[0] results in the "Unable to index into an object of type System.IO.DirectoryInfo." error. The file copy still works because fortunately there is 
            enough information returned to continue with the copy operation.

            The additional path validation should account for other errors missed as a result of the modified error action.
        #>
        $fileCopy = Copy-Item @copyItemParams
        $scriptBlock = [scriptBlock]::Create("Test-Path -Path $clientFilePath")
        $copyValidation = Invoke-Command -Session $clientPSSession -ScriptBlock $scriptBlock
        if (!$copyValidation) {
            Throw "Did not successfully copy file `"$stagingFilePath`" to `"$clientFilePath`" over PsSession Id $($clientPSSession.Id)"
        }
        $removeStaging = Remove-Item -Path $stagingFilePath -Force
    }

    end {
        $returnObj = @{
            source      = $stagingFilePath
            destination = $clientFilePath
            psSessionId = $clientPSSession.name

        }
        return $returnObj
    }
}

function copy-installScript () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [psObject]$clientData,
        [parameter(mandatory = $true)]
        [string]$functionName,
        [parameter(mandatory = $true)]
        [psSession]$clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [string]$fileStagingLocation = $env:TEMP
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
        $fileNameWithExt = "$functionName.ps1"
        $stagingFilePath = Join-Path $fileStagingLocation -ChildPath $fileNameWithExt
        $clientFilePath  = Join-Path $clientInstallLocation -ChildPath $fileNameWithExt
    }

    process {
        $functionCode = (Get-Command -Name $functionName).definition
        $functionFileParams = @{
            filePath = $stagingFilePath
            encoding = "utf8"
            force    = $true
        }
        $createFileStaging = $functionCode | Out-File @functionFileParams

        $copyItemParams = @{
            path        = $stagingFilePath
            destination = $clientFilePath
            toSession   = $clientPSSession
            force       = $true
            errorAction = "silentlyContinue"
        }
        <#
            The reason for the silently continue was a bug introduced in V5.x with the addition of copy-item -tosession functionality. Fortunately this only affects copying to a V2 remote session. 
            The reason for this bug is that the one helper function copied to the remote session uses a script feature that is not available in PowerShell V2 
            (the ability to use '[0]' to select the first element on an non-array type). This is in the PSValidatePathDefinition function:

                    # Get the root path using Get-Item
                    $item = Microsoft.PowerShell.Management\Get-Item $pathToValidate -ea SilentlyContinue
                    if (($item -ne $null) -and ($item[0].PSProvider.Name -eq 'FileSystem'))
                    {
            ...
            $item[0] results in the "Unable to index into an object of type System.IO.DirectoryInfo." error. The file copy still works because fortunately there is 
            enough information returned to continue with the copy operation.

            The additional path validation should account for other errors missed as a result of the modified error action.
        #>
        $fileCopy = Copy-Item @copyItemParams
        $scriptBlock = [scriptBlock]::Create("Test-Path -Path $clientFilePath")
        $copyValidation = Invoke-Command -Session $clientPSSession -ScriptBlock $scriptBlock
        if (!$copyValidation) {
            Throw "Did not successfully copy file `"$stagingFilePath`" to `"$clientFilePath`" over PsSession Id $($clientPSSession.Id)"
        }
        $removeStaging = Remove-Item -Path $stagingFilePath -Force
    }

    end {
        $returnObj = @{
            source      = $stagingFilePath
            destination = $clientFilePath
            psSessionId = $clientPSSession.name

        }
        return $returnObj
    }
}

function new-clientPsSession () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [psObject]$clientData,
        [psCredential]$sessionCredential,
        [ValidateSet("Basic","Credssp","Default","Digest","Kerberos","Negotiate","NegotiateWithImplicitCredential")]
        [string]$sessionAuth,
        [switch]$removeExistingSessions
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        if ($removeExistingSessions) {
            $currentSessions = Get-PSSession
            $currentSessions = $currentSessions | Where-Object {$_.computerName -eq $clientData.fqdn}
            if ($currentSessions) {
                $currentSessions | ForEach-Object {$_ | Remove-PSSession}
            }
        }

        $psSessionParams = @{
            computerName = $clientData.fqdn
        }
        if ($sessionCredential) {$psSessionParams.Add("credential",$sessionCredential)}
        if ($sessionAuth) {$psSessionParams.Add("authentication",$sessionAuth)}
        $psSession = New-PSSession @psSessionParams
    }

    end {
        return $psSession
    }
}

function test-installProcessRunning ([string]$executionCmdLine) { 
    $processes = Get-WmiObject Win32_Process
    $matchingProcess = $processes.commandLine | Where-Object {$_ -eq $executionCmdLine}
    if ($matchingProcess) {
        return $true
    } else {
        return $false
    }
}

function test-packageInstalled ([string]$packageID,[scriptBlock]$detectionScript) {
    $packageIDResult = $false
    if ($packageID) {
        $packageIDs = Get-WmiObject Win32_Product | Select-Object Name, IdentifyingNumber
        $matches = $packageIDs | Where-Object {$_.identifyingNumber -match $packageID}
        if ($matches) {
            $packageIDResult = $true
        }
    }

    $detectionScriptResult = $false
    if ($detectionScript) {
        $detectionScriptResult =  Invoke-Command -ScriptBlock $detectionScript
    }

    if (($packageID -and $packageIDResult) -and ($detectionScript -and $detectionScriptResult)) {
        $installed = $true
    } elseif (!$packageID -and ($detectionScript -and $detectionScriptResult)) {
        $installed = $true
    } elseif (($packageID -and $packageIDResult) -and !$detectionScript) {
        $installed = $true
    } else {
        $installed = $false
    }

    return $installed
}

function new-clientScheduledTask ([string]$taskName,[string]$scriptPath) {

    $taskCommand = 'powerShell'
    $taskArg = $scriptPath
 
    $service = New-Object -ComObject("Schedule.Service")

    $service.Connect()
    $rootFolder                               = $service.GetFolder("\")
    $taskDefinition                           = $service.newTask(0) 
    $taskDefinition.settings.enabled          = $true
    $taskDefinition.settings.allowDemandStart = $true
 
    $action           = $taskDefinition.actions.Create(0)
    $action.path      = "$taskCommand"
    $action.Arguments = "$taskArg"
 
    $register = $rootFolder.registerTaskDefinition("$taskName",$taskDefinition,6,"System",$null,5)

    return $register
}

function get-scheduledTaskStatus ([string]$taskPath) {
    $taskStatusLine = schtasks /query /tn $taskPath /fo list | Select-String "Status:"
    $status         = (([regex]'(?<=\:        ).*$').matches($taskStatusLine)).value
    return $status
}

function remove-clientScheduledTask ([string]$taskPath) {
    $removeTask = schtasks /delete /tn $taskPath /f
}

function new-installerCopyScript ([string]$sourcePath,[string]$destinationPath,[string]$stagingPath) {
    $copyString = "Copy-Item -Path $sourcePath -Destination $destinationPath"
    $fileName   = Join-Path $stagingPath -ChildPath "clientInstallerCopy.ps1"
    $copyString | Out-File -FilePath $fileName -Encoding utf8 -Force
    return $fileName
}

function install-clientPackage () {
    Write-Output "Installing..."
}

function get-clientData () {

}

function test01 () {
    $objArray = @()
    $number = 1
    while (1) {
        $obj = New-Object -Type psobject -Property @{
            "data1" = $number
            "data2" = $number+1
            "data3" = $number +2
        }
        $objArray += $obj
        $number++
        Write-Output $obj
        Start-Sleep -Seconds 1
    }
}