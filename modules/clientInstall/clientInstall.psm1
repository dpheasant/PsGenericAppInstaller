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
    'packageID'           = '715E251E-9134-3D1D-BE19-1C6EE18F8D24'
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
        [string]$sessionAuth,
        [switch]$noLogSearch,
        [int]$installTestWaitInterval = 10,
        [int]$installRunningTestWaitInterval = 10,
        [int]$maxInstallTestCount = 9999,
        [string]$smbValidationTaskName = "smbValidate",
        [int]$scheduledTaskCheckWaitInterval = 10,
        [int]$maxScheduledTaskMonitorCount = 9999
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}
        
    }
    process {
        "Starting client install tasks." | log
        $clientStatusObject = New-Object -Type psObject
        $clientStatusObject = $clientData
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name '_TYPE' -Value 'data'
        "Added _TYPE property with data flag to output object." | log
        "Client output status object created with input client data." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}

        "Starting client pre-requisite checks." | log
        $testPreRequisites = $clientData.fqdn | test-preRequisites
        "Client pre-requisite checks complete." | log
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
         if (!$clientStatusObject.smbTest) {
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
        "Added psSessionId to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
        Write-Output $clientStatusObject
        "PowerShell session properties: " | log -l 6 -cf @{'psSessionProperties' = $clientPsSession}

        "Gathering client data for $($clientData.fqdn)." | log
        $clientDataScriptBlock = (Get-Command get-clientData).ScriptBlock
        $invokeCmdParams = @{
            session      = $clientPsSession
            scriptBlock  = $clientData
            argumentList = ""
        }
        $clientData = Invoke-Command @invokeCmdParams
        "Client data gathering complete." | log
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'clientData' -Value $clientData
        "Added client data to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
        Write-Output $clientStatusObject

        $testCount = 1
        while ($testCount -le $maxInstallTestCount) {
            "Testing for running install process with input command line." | log -cf @{cmdLine = $clientData.executionCmdLine}
            $installRunningScriptBlock = (Get-Command test-installProcessRunning).ScriptBlock
            $invokeCmdParams = @{
                session      = $clientPsSession
                scriptBlock  = $installRunningScriptBlock
                argumentList = $clientData.executionCmdLine
            }
            $installRunningTest = Invoke-Command @invokeCmdParams
            "Package Install running test complete." | log
            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'installRunning' -Value $installRunningTest -Force
            "Added package install running test result to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
            Write-Output $clientStatusObject
            if ($installRunningTest) {
                "Package Installation with command `"$($clientData.executionCmdLine)`" currently running. Waiting for $installRunningTestWaitInterval seconds." | log
                Start-Sleep -Seconds $installRunningTestWaitInterval
                "Wait interval completed. Contuing test loop with test count $testCount (of $maxInstallTestCount)." | log
                $testCount++
                if (!$noLogSearch) {
                    "Evaulating `"$($clientData.logFileLocation)`" against provided search script and regEx parameters." | log
                    $logSearchScriptBlock = (Get-Command get-logSearchResults).ScriptBlock
                    $searchScriptBlock    = [scriptBlock]::Create("$($clientData.logFileSearchScript)")
                    $invokeCmdParams = @{
                        session      = $clientPsSession
                        scriptBlock  = $logSearchScriptBlock
                        argumentList = $clientData.logFileLocation,$clientData.logFileRegEx,$clientData.logFileSearchScript
                    }
                    "Log Search parameters created." | log -l 6 -cf @{logSearchParams = $invokeCmdParams}
                    $logSearch = Invoke-Command @invokeCmdParams
                    "Log search complete." | log
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchRegExResults' -Value $logSearch.regExMatch -Force
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchScriptResults' -Value $logSearch.scriptMatch -Force
                    "Added log search results to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    Write-Output $clientStatusObject
                }
                Continue
            }
            
            "Testing package install state on $($testPreRequisites.clientFqdn)." | log
            $packageInstallScriptBlock = (Get-Command test-packageInstalled).ScriptBlock
            $invokeCmdParams = @{
                session      = $clientPsSession
                scriptBlock  = $packageInstallScriptBlock
                argumentList = $clientData.packageID,$clientData.detectionScript
            }
            $testPackageInstall = Invoke-Command @invokeCmdParams
            "Completed test package install state on $($testPreRequisites.clientFqdn). Result: $testPackageInstall" | log
            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'packageInstallTest' -Value $testPackageInstall -Force
            "Added package install test result to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
            Write-Output $clientStatusObject

            if ($testPackageInstall) {
                "Package installed! Breaking out of test." | log
                if (!$noLogSearch) {
                    "Evaulating `"$($clientData.logFileLocation)`" against provided search script and regEx parameters." | log
                    $logSearchScriptBlock = (Get-Command get-logSearchResults).ScriptBlock
                    $searchScriptBlock    = [scriptBlock]::Create("$($clientData.logFileSearchScript)")
                    $invokeCmdParams = @{
                        session      = $clientPsSession
                        scriptBlock  = $logSearchScriptBlock
                        argumentList = $clientData.logFileLocation,$clientData.logFileRegEx,$clientData.logFileSearchScript
                    }
                    "Log Search parameters created." | log -l 6 -cf @{logSearchParams = $invokeCmdParams}
                    $logSearch = Invoke-Command @invokeCmdParams
                    "Log search complete." | log
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchRegExResults' -Value $logSearch.regExMatch -Force
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchScriptResults' -Value $logSearch.scriptMatch -Force
                    "Added log search results to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    Write-Output $clientStatusObject
                }
                Break
            } else {
                "Setting environment on $($testPreRequisites.clientFqdn)." | log
                $setEnvParams = @{
                    clientPSSession = $clientPsSession
                    force           = $false
                }
                "Set Environment parameters created for $($testPreRequisites.clientFqdn)." | log -l 6 -cf @{'psSessionParams' = $setEnvParams}
                $setClientEnv = set-clientEnvironment @setEnvParams
                "Environment set on $($testPreRequisites.clientFqdn)." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'remoteDirectory' -Value $setClientEnv
                Write-Output $clientStatusObject

                "Validating UNC path `"$($clientData.packageLocation)`" from client." | log
                $validateSmbLogPath = Join-Path $clientInstallLocation -ChildPath "smbValidateLog.txt"
                $validateSMBParams = @{
                    uncPath     = $clientData.packageLocation
                    logFilePath = $validateSmbLogPath
                }
                $clientScript = new-validateSMBScriptString @validateSMBParams
                "Writing client smb validation script to  to client." | log
                $copyScriptParams = @{
                    scriptString          = $clientScript
                    fileName              = "smbValidate.ps1"
                    clientPSSession       = $clientPsSession
                    clientInstallLocation = $clientInstallLocation
                    fileStagingLocation   = $serverStagingPath
                }
                "Copy client script parameters created." | log -l 6 -cf @{copyScriptParams = $copyScriptParams}
                $writeScript = copy-clientInstallScript @copyScriptParams
                "Copied SMB validation script to remote client." | log
                "Creating scheduled task on client to run smb validation script as local system." | log
                $schedTaskCreateScriptBlock = (Get-Command new-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskCreateScriptBlock
                    argumentList = $smbValidationTaskName,$writeScript.destination
                }
                $createSchedTask = Invoke-Command @invokeCmdParams
                "Completed create smb validation task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Created" -Force
                "Added smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                Write-Output $clientStatusObject
                "Running scheduled task `"$smbValidationTaskName`" on remote client." | log
                $schedTaskRunScriptBlock = (Get-Command start-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRunScriptBlock
                    argumentList = "/$smbValidationTaskName"
                }
                $runSchedTask = Invoke-Command @invokeCmdParams
                "Completed run smb validation task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Started" -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                Write-Output $clientStatusObject
                "Preparing to monitor scheduled task `"$smbValidationTaskName`" on remote client." | log
                $schedTaskMonitorScriptBlock = (Get-Command get-scheduledTaskStatus).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskMonitorScriptBlock
                    argumentList = "/$smbValidationTaskName"
                }
                $monitorCount = 1
                do {
                    "Monitoring scheduled task `"$smbValidationTaskName`" on remote client." | log
                    $monitorSchedTask = Invoke-Command @invokeCmdParams
                    "Scheduled task `"$smbValidationTaskName`" current status: $monitorSchedTask." | log
                    "Completed monitor `"$smbValidationTaskName`" task number $monitorCount (of $maxScheduledTaskMonitorCount) on remote client." | log
                    $monitorCount++
                    switch ($monitorSchedTask) {
                        "Running" {
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Running" -Force
                            "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                        "Ready" {
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Complete" -Force
                            "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                        default {
                            "Scheduled task `"$smbValidationTaskName`" run failed. Cannot confirm if client can connect to $($clientData.packageLocation)." | log -l 3
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Failed" -Force
                            "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                    }
                    Write-Output $clientStatusObject
                    "Starting sleep for $scheduledTaskCheckWaitInterval seconds before re-checking scheduled task $smbValidationTaskName." | log
                    Start-Sleep -Seconds $scheduledTaskCheckWaitInterval
                } until ($monitorSchedTask -eq "Ready" -or ($monitorCount -eq $maxScheduledTaskMonitorCount))
                "Removing scheduled task `"$smbValidationTaskName`"." | log
                $schedTaskRemoveScriptBlock = (Get-Command remove-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRemoveScriptBlock
                    argumentList = "/$smbValidationTaskName"
                }
                $removeSchedTask = Invoke-Command @invokeCmdParams
                "Completed remove `"$smbValidationTaskName`" task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Removed" -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                Write-Output $clientStatusObject
                "Evaluating scheduled task `"$smbValidationTaskName`"result." | log
                $smbTaskEvaluateScriptblock = [scriptBlock]::Create("Get-Content -Path $validateSmbLogPath")
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $smbTaskEvaluateScriptblock
                }
                $evalSchedTask = Invoke-Command @invokeCmdParams
                "Completed evaluate task `"$smbValidationTaskName`" task on remote client. Result: $evalSchedTask" | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationResult' -Value $evalSchedTask -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                switch ($evalSchedTask) {
                    "True" {
                        "SMB validation from remote client to $($clientData.packageLocation) suceeded!" | log
                        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidation' -Value $true -Force
                        "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    }
                    "False" {
                        "SMB validation from remote client to $($clientData.packageLocation) failed! Client cannot install package" | log -l 2
                        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidation' -Value $false -Force
                        "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        Write-Output $clientStatusObject
                        Throw "SMB validation from remote client to $($clientData.packageLocation) failed! Client cannot install package"
                    }
                    default {
                        "Unable to validate remote client connectivity to $($clientData.packageLocation)." | log -l 3
                        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidation' -Value 'Unknown' -Force
                        "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    }
                }
                Write-Output $clientStatusObject
                


            }       
        }

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

function copy-clientInstallScript () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string[]]$scriptString,
        [parameter(mandatory = $true)]
        [string]$fileName,
        [parameter(mandatory = $true)]
        [psSession]$clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [string]$fileStagingLocation = $env:TEMP
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType}

        $stagingFilePath = Join-Path $fileStagingLocation -ChildPath $fileName
        $clientFilePath  = Join-Path $clientInstallLocation -ChildPath $fileName
    }

    process {
        $scriptFileParams = @{
            filePath    = $stagingFilePath
            encoding    = "utf8"
            force       = $true
            inputObject = $scriptString
        }
        $createFileStaging = Out-File @scriptFileParams

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

function start-clientScheduledTask ([string]$taskPath) {
    $startTask = schtasks /run /tn $taskPath
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

function get-logSearchResults ([string]$logFilePath,[string]$logRegEx,[scriptBlock]$logFileSearchScript) {
    $matches = @{
        regExMatch  = $null
        scriptMatch = $null
    }
    $pathTest = Test-Path $logFilePath
    if ($pathTest) {
        if ($logRegEx) {
            $regExmatch = (([regex]$logRegEx).matches((Get-Content -Path $logFilePath))).value
            $matches.regExMatch = $regExmatch
        }
        if ($logFileSearchScript) {
            $scriptMatch = Invoke-Command -ScriptBlock $logFileSearchScript
            $matches.scriptMatch = $scriptMatch
        }
    } else {
        "Path to $logFilePath not valid!" | log -l 3
    }
    return $matches
}

function new-validateSMBScriptString ([string]$uncPath,[string]$logFilePath) {
    [string[]]$testSMBString = "`$testUncPath = Test-Path `"$uncPath`""
    $testSMBString += "`$testUncPath | Out-File -FilePath $logFilePath -Encoding utf8 -Force"
    
    return $testSMBString
}

# i.    Time
# ii.   Date
# iii.  System Name
# iv.   IP address
# v.    Pending Reboot Status
# vi.   Disk Space
# vii.  Network info
# viii. Limited Installed Program list (TBD)

function get-clientData () {

    $dateTime = Get-Date
    $system   = get-wmiobject win32_computersystem
    $fqdn     = ("{0}.{1}" -f $system.name,$system.domain)

    $rebootStatus  = Get-PendingReboot
    $pendingReboot = $false
    if($rebootStatus.rebootPending -and (-not ($rebootStatus.PendComputerRename -or $rebootStatus.PendFileRename))){
        $pendingReboot = $true
    }

    $diskInfo    = (Get-WmiObject Win32_LogicalDisk -Filter 'driveType = 3' | select-object  -Property DeviceId,FreeSpace,Size)
    $networkInfo = (Get-WmiObject win32_networkadapterconfiguration -Filter 'ipenabled = "true"').ipaddress | ?{$_ -like '*.*.*.*'}
    $installedPrograms = get-wmiobject win32_product  | select-object -Property Name,IdentifyingNumber,version

    $data = new-object -type PSObject -Property @{
        timestamp     = $dateTime
        fqdn          = $fqdn
        pendingReboot = $pendingReboot
        diskInfo      = $diskInfo
        networkInfo   = $networkInfo
        installedPrograms = $installedPrograms
    }

    return $data
}

Function Get-PendingReboot 
{ 
<# 
.SYNOPSIS 
    Gets the pending reboot status on a local or remote computer. 
 
.DESCRIPTION 
    This function will query the registry on a local or remote computer and determine if the 
    system is pending a reboot, from either Microsoft Patching or a Software Installation. 
    For Windows 2008+ the function will query the CBS registry key as another factor in determining 
    pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed 
    as being consistant across Windows Server 2003 & 2008. 
   
    CBServicing = Component Based Servicing (Windows 2008) 
    WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008) 
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value 
    PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008) 
 
.PARAMETER ComputerName 
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME). 
 
.PARAMETER ErrorLog 
    A single path to send error data to a log file. 
 
.EXAMPLE 
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize 
   
    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending 
    -------- ----------- ------------- ------------ -------------- -------------- ------------- 
    DC01     False   False           False      False 
    DC02     False   False           False      False 
    FS01     False   False           False      False 
 
    This example will capture the contents of C:\ServerList.txt and query the pending reboot 
    information from the systems contained in the file and display the output in a table. The 
    null values are by design, since these systems do not have the SCCM 2012 client installed, 
    nor was the PendingFileRenameOperations value populated. 
 
.EXAMPLE 
    PS C:\> Get-PendingReboot 
   
    Computer     : WKS01 
    CBServicing  : False 
    WindowsUpdate      : True 
    CCMClient    : False 
    PendComputerRename : False 
    PendFileRename     : False 
    PendFileRenVal     :  
    RebootPending      : True 
   
    This example will query the local machine for pending reboot information. 
   
.EXAMPLE 
    PS C:\> $Servers = Get-Content C:\Servers.txt 
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation 
   
    This example will create a report that contains pending reboot information. 
 
.LINK 
    Component-Based Servicing: 
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx 
   
    PendingFileRename/Auto Update: 
    http://support.microsoft.com/kb/2723674 
    http://technet.microsoft.com/en-us/library/cc960241.aspx 
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx 
 
    SCCM 2012/CCM_ClientSDK: 
    http://msdn.microsoft.com/en-us/library/jj902723.aspx 
 
.NOTES 
    Author:  Brian Wilhite 
    Email:   bcwilhite (at) live.com 
    Date:    29AUG2012 
    PSVer:   2.0/3.0/4.0/5.0 
    Updated: 01DEC2014 
    UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only 
       Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter 
       Removed $Data variable from the PSObject - it is not needed 
       Bug with the way CCMClientSDK returned null value if it was false 
       Removed unneeded variables 
       Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry 
       Removed .Net Registry connection, replaced with WMI StdRegProv 
       Added ComputerPendingRename 
#> 
 
[CmdletBinding()] 
param( 
  [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
  [Alias("CN","Computer")] 
  [String[]]$ComputerName="$env:COMPUTERNAME", 
  [String]$ErrorLog 
  ) 
 
Begin {  }## End Begin Script Block 
Process { 
  Foreach ($Computer in $ComputerName) { 
  Try { 
      ## Setting pending values to false to cut down on the number of else statements 
      $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false 
       
      ## Setting CBSRebootPend to null since not all versions of Windows has this value 
      $CBSRebootPend = $null 
             
      ## Querying WMI for build version 
      $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop 
 
      ## Making registry connection to the local/remote computer 
      $HKLM = [UInt32] "0x80000002" 
      $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv" 
             
      ## If Vista/2008 & Above query the CBS Reg Key 
      If ([Int32]$WMI_OS.BuildNumber -ge 6001) { 
        $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\") 
        $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"     
      } 
               
      ## Query WUAU from the registry 
      $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
      $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired" 
             
      ## Query PendingFileRenameOperations from the registry 
      $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations") 
      $RegValuePFRO = $RegSubKeySM.sValue 
 
      ## Query ComputerName and ActiveComputerName from the registry 
      $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")       
      $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName") 
      If ($ActCompNm -ne $CompNm) { 
    $CompPendRen = $true 
      } 
             
      ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true 
      If ($RegValuePFRO) { 
        $PendFileRename = $true 
      } 
 
      ## Determine SCCM 2012 Client Reboot Pending Status 
      ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0 
      $CCMClientSDK = $null 
      $CCMSplat = @{ 
    NameSpace='ROOT\ccm\ClientSDK' 
    Class='CCM_ClientUtilities' 
    Name='DetermineIfRebootPending' 
    ComputerName=$Computer 
    ErrorAction='Stop' 
      } 
      ## Try CCMClientSDK 
      Try { 
    $CCMClientSDK = Invoke-WmiMethod @CCMSplat 
      } Catch [System.UnauthorizedAccessException] { 
    $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue 
    If ($CcmStatus.Status -ne 'Running') { 
        Write-Warning "$Computer`: Error - CcmExec service is not running." 
        $CCMClientSDK = $null 
    } 
      } Catch { 
    $CCMClientSDK = $null 
      } 
 
      If ($CCMClientSDK) { 
    If ($CCMClientSDK.ReturnValue -ne 0) { 
      Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"     
        } 
        If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) { 
      $SCCM = $true 
        } 
      } 
       
      Else { 
    $SCCM = $null 
      } 
 
      ## Creating Custom PSObject and Select-Object Splat 
      $SelectSplat = @{ 
    Property=( 
        'Computer', 
        'CBServicing', 
        'WindowsUpdate', 
        'CCMClientSDK', 
        'PendComputerRename', 
        'PendFileRename', 
        'PendFileRenVal', 
        'RebootPending' 
    )} 
      New-Object -TypeName PSObject -Property @{ 
    Computer=$WMI_OS.CSName 
    CBServicing=$CBSRebootPend 
    WindowsUpdate=$WUAURebootReq 
    CCMClientSDK=$SCCM 
    PendComputerRename=$CompPendRen 
    PendFileRename=$PendFileRename 
    PendFileRenVal=$RegValuePFRO 
    RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename) 
      } | Select-Object @SelectSplat 
 
  } Catch { 
      Write-Warning "$Computer`: $_" 
      ## If $ErrorLog, log the file to a user specified location/path 
      If ($ErrorLog) { 
    Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append 
      }         
  }       
  }## End Foreach ($Computer in $ComputerName)       
}## End Process 
 
End {  }## End End 
 
}## End Function Get-PendingReboot  

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