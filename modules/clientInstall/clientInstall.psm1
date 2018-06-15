$logOutPutType = "CSV"
$logShowLevel  = "debug"
$logOutPutPath = $env:TEMP
New-Alias log write-log -Force

$clientDataSample = $null
$clientDataSample = New-Object -Type psObject -Property @{
    'fqdn'                = 'ws04.lab2.qtr.ad'
    'siteId'              = 'Site1'
    'logFileRegEx'        = 'Client installation completed SUCCESSFULLY'
    'logFileSearchScript' = ''
    'logFileLocation'     = "$env:TEMP\AdaptivaClientSetup.LOG"
    'executionCmdLine'    = 'msiexec /i \\file01\share02\msi\npp.msi /q /norestart'
    'packageLocation'     = '\\file01\share02\msi\'
    'packageID'           = '622E78B5-9B2F-412D-86CD-FDD72A3154BA'
    'detectionScript'     = 'Test-Path HKLM:\SYSTEM\Software\'
    'outputPath'          = 'C:\scripts\output'
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
        [string]$msiInstallTaskName = "msiInstall",
        [int]$scheduledTaskCheckWaitInterval = 10,
        [int]$maxScheduledTaskMonitorCount = 200,
        [int]$maxRandomDelayWaitTimer = 30,
        [switch]$doNotKillMsiProcessOnTimeout
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputType'     = $logOutPutType
                                      'log:outputFilePath' = $logOutputPath
                                      'write-clientOutput:passThru' = $true}
        
    }
    process {
        $pSDefaultParameterValues.Add('log:tag',$clientData.fqdn)
        "Starting client install tasks." | log
        $clientStatusObject = New-Object -Type psObject
        $clientStatusObject = $clientData
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
        $clientStatusObject | write-clientOutput | Write-Output
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
        $clientStatusObject | write-clientOutput | Write-Output
        "PowerShell session properties: " | log -l 6 -cf @{'psSessionProperties' = $clientPsSession}
        
        "Gathering client data for $($clientData.fqdn)." | log
        $clientDataScriptBlock = (Get-Command get-clientData).ScriptBlock
        $invokeCmdParams = @{
            session      = $clientPsSession
            scriptBlock  = $clientDataScriptBlock
        }
        $clientPollingData = Invoke-Command @invokeCmdParams
        "Client data gathering complete." | log
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'clientData_networkInfo' -Value $clientPollingData.networkInfo
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'clientData_installedPrograms' -Value $clientPollingData.installedPrograms
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'clientData_diskInfo' -Value $clientPollingData.diskInfo
        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'clientData_pendingReboot' -Value $clientPollingData.pendingReboot
        "Added client data to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
        $clientStatusObject | write-clientOutput | Write-Output
        
        $testCount = 1
        while ($testCount -le $maxInstallTestCount) {
            "Testing for running install process with input command line." | log -cf @{cmdLine = $clientData.executionCmdLine}
            $installRunningScriptBlock = (Get-Command test-installProcessRunning).scriptBlock
            $invokeCmdParams = @{
                session      = $clientPsSession
                scriptBlock  = $installRunningScriptBlock
                argumentList = $clientData.executionCmdLine
            }
            $installRunningTest = Invoke-Command @invokeCmdParams
            "Package Install running test complete." | log
            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'installRunning' -Value $installRunningTest -Force
            "Added package install running test result to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
            $clientStatusObject | write-clientOutput | Write-Output
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
                    "Log search regex results: $($logSearch.regExMatch). Log search script results: $($logSearch.scriptMatch)." | log -l 6 -cf @{logSearch = $logSearch}
                    "Log search complete." | log
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchRegExResults' -Value $logSearch.regExMatch -Force
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchScriptResults' -Value $logSearch.scriptMatch -Force
                    "Added log search results to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    $clientStatusObject | write-clientOutput | Write-Output
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
            $clientStatusObject | write-clientOutput | Write-Output

            if ($testPackageInstall) {
                "Package installed! Breaking out of test." | log
                if (!$noLogSearch) {
                    "Evaulating `"$($clientData.logFileLocation)`" against provided search script and regEx parameters." | log
                    $logSearchScriptBlock = (Get-Command get-logSearchResults).ScriptBlock
                    $invokeCmdParams = @{
                        session      = $clientPsSession
                        scriptBlock  = $logSearchScriptBlock
                        argumentList = $clientData.logFileLocation,$clientData.logFileRegEx,$clientData.logFileSearchScript
                    }
                    "Log Search parameters created." | log -l 6 -cf @{logSearchParams = $invokeCmdParams}
                    $logSearch = Invoke-Command @invokeCmdParams
                    "Log search regex results: $($logSearch.regExMatch). Log search script results: $($logSearch.scriptMatch)." | log -l 6 -cf @{logSearch = $logSearch}
                    "Log search complete." | log
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchRegExResults' -Value $logSearch.regExMatch -Force
                    $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'logSearchScriptResults' -Value $logSearch.scriptMatch -Force
                    "Added log search results to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    $clientStatusObject | write-clientOutput | Write-Output
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
                $clientStatusObject | write-clientOutput | Write-Output

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
                    argumentList = $smbValidationTaskName,"powerShell",$writeScript.destination
                }
                "Create scheduled task $smbValidationTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $createSchedTask = Invoke-Command @invokeCmdParams
                "Completed create smb validation task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Created" -Force
                "Added smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Running scheduled task `"$smbValidationTaskName`" on remote client." | log
                $schedTaskRunScriptBlock = (Get-Command start-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRunScriptBlock
                    argumentList = "\$smbValidationTaskName"
                }
                "Run scheduled task $smbValidationTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $runSchedTask = Invoke-Command @invokeCmdParams
                "Completed run smb validation task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Started" -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Preparing to monitor scheduled task `"$smbValidationTaskName`" on remote client." | log
                $schedTaskMonitorScriptBlock = (Get-Command get-scheduledTaskStatus).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskMonitorScriptBlock
                    argumentList = "\$smbValidationTaskName"
                }
                "Monitor scheduled task $smbValidationTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
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
                    $clientStatusObject | write-clientOutput | Write-Output
                    "Starting sleep for $scheduledTaskCheckWaitInterval seconds before re-checking scheduled task $smbValidationTaskName." | log
                    Start-Sleep -Seconds $scheduledTaskCheckWaitInterval
                } until ($monitorSchedTask -eq "Ready" -or ($monitorCount -eq $maxScheduledTaskMonitorCount))
                "Removing scheduled task `"$smbValidationTaskName`"." | log
                $schedTaskRemoveScriptBlock = (Get-Command remove-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRemoveScriptBlock
                    argumentList = "\$smbValidationTaskName"
                }
                "Remove scheduled task $smbValidationTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $removeSchedTask = Invoke-Command @invokeCmdParams
                "Completed remove `"$smbValidationTaskName`" task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidationStatus' -Value "Task Removed" -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Evaluating scheduled task `"$smbValidationTaskName`"result." | log
                $smbTaskEvaluateScriptblock = [scriptBlock]::Create("Get-Content -Path $validateSmbLogPath")
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $smbTaskEvaluateScriptblock
                }
                "Evaluate scheduled task $smbValidationTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
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
                        $clientStatusObject | write-clientOutput | Write-Output
                        Throw "SMB validation from remote client to $($clientData.packageLocation) failed! Client cannot install package"
                    }
                    default {
                        "Unable to validate remote client connectivity to $($clientData.packageLocation)." | log -l 3
                        $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'smbValidation' -Value 'Unknown' -Force
                        "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                    }
                }
                $clientStatusObject | write-clientOutput | Write-Output

                "Executing msi install for $($clientData.fqdn)." | log
                "Creating scheduled task on client to run msi install script as local system." | log
                $schedTaskCreateScriptBlock = (Get-Command new-clientScheduledTask).scriptBlock
                $msiExecArgs = ($clientData.executionCmdLine) -replace ('msiexec ','')
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskCreateScriptBlock
                    argumentList = $msiInstallTaskName,'msiexec.exe',$msiExecArgs
                }
                "Create scheduled task $msiInstallTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $createSchedTask = Invoke-Command @invokeCmdParams
                "Completed create msi install scheduled task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Created" -Force
                "Added msi install task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Starting random delay timer between 1 and $maxRandomDelayWaitTimer seconds before running job." | log
                $randomDelaySec = Get-Random -Maximum  $maxRandomDelayWaitTimer -Minimum 1
                "Starting random delay wait time of $randomDelaySec seconds..." | log
                Start-Sleep -Seconds $randomDelaySec
                "Running scheduled task `"$msiInstallTaskName`" on remote client." | log
                $schedTaskRunScriptBlock = (Get-Command start-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRunScriptBlock
                    argumentList = "\$msiInstallTaskName"
                }
                "Run scheduled task $msiInstallTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $runSchedTask = Invoke-Command @invokeCmdParams
                "Completed run msi install task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Started" -Force
                "Updated msi install task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Preparing to monitor scheduled task `"$msiInstallTaskName`" on remote client." | log
                $schedTaskMonitorScriptBlock = (Get-Command get-scheduledTaskStatus).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskMonitorScriptBlock
                    argumentList = "\$msiInstallTaskName"
                }
                "Monitor scheduled task $msiInstallTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $monitorCount = 1
                do {
                    "Monitoring scheduled task `"$msiInstallTaskName`" on remote client." | log
                    $monitorSchedTask = Invoke-Command @invokeCmdParams
                    "Scheduled task `"$msiInstallTaskName`" current status: $monitorSchedTask." | log
                    "Completed monitor `"$msiInstallTaskName`" task number $monitorCount (of $maxScheduledTaskMonitorCount) on remote client." | log
                    $monitorCount++
                    switch ($monitorSchedTask) {
                        "Running" {
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Running" -Force
                            "Updated msi install task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                        "Ready" {
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Complete" -Force
                            "Updated msi install task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                        default {
                            "Scheduled task `"$msiInstallTaskName`" run failed. Cannot confirm if client can execute `"$($clientData.executionCmdLine)`"." | log -l 3
                            $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Failed" -Force
                            "Updated msi install task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                        }
                    }
                    $clientStatusObject | write-clientOutput | Write-Output
                    "Starting sleep for $scheduledTaskCheckWaitInterval seconds before re-checking scheduled task $msiInstallTaskName." | log
                    Start-Sleep -Seconds $scheduledTaskCheckWaitInterval
                    if (!$doNotKillMsiProcessOnTimeout -and ($monitorCount -eq $maxScheduledTaskMonitorCount)) {
                        "Max check attempts of $maxScheduledTaskMonitorCount reached! Attempting to kill process associated with `"$($clientData.executionCmdLine)`"..." | log
                        $findProcessScriptBlock = [scriptBlock]::Create("(Get-WmiObject win32_process | Where-Object {`$_.commandLine -like `"*msiexec.exe $msiExecArgs*`"}).processId")
                        $invokeCmdParams = @{
                            session      = $clientPsSession
                            scriptBlock  = $findProcessScriptBlock
                        }
                        "Find process parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                        $findProcess = Invoke-Command @invokeCmdParams
                        if ($findProcess -or ($findProcess.length -gt 1)) {
                            "Process found with Id $findProcess. Killing process..." | log
                            $killProcessScriptBlock = [scriptBlock]::Create("taskKill /pid $findProcess /f")
                            $invokeCmdParams = @{
                                session      = $clientPsSession
                                scriptBlock  = $killProcessScriptBlock
                            }
                            "Kill process parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                            $killProcess = Invoke-Command @invokeCmdParams
                            "Process with PID $findProcess killed!" | log
                        } else {
                            "No or multiple processes matching `"$($clientData.executionCmdLine)`". Will not stop process." | log -l 3
                        }
                    }
                } until ($monitorSchedTask -eq "Ready" -or ($monitorCount -eq $maxScheduledTaskMonitorCount))
                "Removing scheduled task `"$smbValidationTaskName`"." | log
                $schedTaskRemoveScriptBlock = (Get-Command remove-clientScheduledTask).scriptBlock
                $invokeCmdParams = @{
                    session      = $clientPsSession
                    scriptBlock  = $schedTaskRemoveScriptBlock
                    argumentList = "\$msiInstallTaskName"
                }
                "Remove scheduled task $msiInstallTaskName parameters defined." | log -l 6 -cf @{invokeCmdParams = $invokeCmdParams}
                $removeSchedTask = Invoke-Command @invokeCmdParams
                "Completed remove `"$msiInstallTaskName`" task on remote client." | log
                $clientStatusObject | Add-Member -MemberType NoteProperty -Name 'msiInstallStatus' -Value "Task Removed" -Force
                "Updated smb validation task status to client status object." | log -l 6 -cf @{'clientStatusObject' = $clientStatusObject}
                $clientStatusObject | write-clientOutput | Write-Output
                "Completed msi install command task on $($clientData.fqdn)." | log
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
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientPSSession.computerName)
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
        [psObject]$clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [string]$fileStagingLocation = $env:TEMP,
        [string]$fileName = "clientInstallConfig"
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
        $fileNameWithExt = "$fileName.json"
        $stagingFilePath = Join-Path $fileStagingLocation -ChildPath $fileNameWithExt
        $clientFilePath  = Join-Path $clientInstallLocation -ChildPath $fileNameWithExt
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientData.fqdn)
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
        [psObject]$clientPSSession,
        [string]$clientInstallLocation = "$env:TEMP\clientInstall\",
        [string]$fileStagingLocation = $env:TEMP
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}

        $stagingFilePath = Join-Path $fileStagingLocation -ChildPath $fileName
        $clientFilePath  = Join-Path $clientInstallLocation -ChildPath $fileName
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientPSSession.computerName)
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
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientData.fqdn)
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
        $psSession = New-PSSession @psSessionParams -ErrorAction Stop
    }

    end {
        return $psSession
    }
}

function write-clientOutput () {
    [cmdletBinding()]
    param (
        [parameter(mandatory = $true, valueFromPipeline = $true, position = 0)]
        [psObject]$clientOutputData,
        [switch]$passThru
    )

    begin {
        $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                      'log:logShowLevel'   = $logShowLevel
                                      'log:outputFilePath' = $logOutputPath
                                      'log:outputType'     = $logOutPutType}
    }

    process {
        $pSDefaultParameterValues.Add('log:tag',$clientOutputData.fqdn)
        $fileName = "$((($clientOutputData.fqdn).split('.'))[0]).csv"
        $fullOutputPath = Join-Path $clientOutputData.outputPath -ChildPath $fileName
        if (Test-Path $fullOutputPath) {
            try {
                Remove-Item -Path $fullOutputPath -Force -ErrorAction Stop
            } catch {
                "Unable to delete and overwrite file `"$fullOutputPath`". Make sure file is not in use." | log -l 3
            }
        }
        $clientOutputData | Export-Csv -Path $fullOutputPath -NoTypeInformation
    }

    end {
        if ($passThru) {
            return $clientOutputData
        }
    }
}

function test-installProcessRunning ([string]$executionCmdLine) { 
    $processes = Get-WmiObject Win32_Process
    $matchingProcess = $processes.commandLine | Where-Object {$_ -like "*$executionCmdLine*"}
    if ($matchingProcess) {
        return $true
    } else {
        return $false
    }
}

function test-packageInstalled ([string]$packageID,[string[]]$detectionScript) {
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
        $detectionScriptBlock = [scriptBlock]::Create($detectionScript)
        $detectionScriptResult =  Invoke-Command -ScriptBlock $detectionScriptBlock
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

function new-clientScheduledTask ([string]$taskName,[string]$taskCommand,[string]$taskArg) {
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
    $taskStatusLine = schtasks /query /tn "$taskPath" /fo list | Select-String "Status:"
    $statusValue    = ([regex]'(?<=\:        ).*$').matches($taskStatusLine) | Select-Object value
    $status         = $statusValue.value
    return $status
}

function start-clientScheduledTask ([string]$taskPath) {
    $startTask = schtasks /run /tn "$taskPath"
}

function remove-clientScheduledTask ([string]$taskPath) {
    $removeTask = schtasks /delete /tn "$taskPath" /f
}

function new-installerCopyScript ([string]$sourcePath,[string]$destinationPath,[string]$stagingPath) {
    $copyString = "Copy-Item -Path $sourcePath -Destination $destinationPath"
    $fileName   = Join-Path $stagingPath -ChildPath "clientInstallerCopy.ps1"
    $copyString | Out-File -FilePath $fileName -Encoding utf8 -Force
    return $fileName
}

function get-logSearchResults ([string]$logFilePath,[string]$logRegEx,[string[]]$logFileSearchScript) {
    $matches = @{
        regExMatch  = $null
        scriptMatch = $null
    }
    $pathTest = Test-Path "$logFilePath"
    if ($pathTest) {
        if ($logRegEx) {
            $regExmatch = ([regex]"$logRegEx").matches((Get-Content -Path $logFilePath)) | Select-Object value
            $matches.regExMatch = $regExmatch
        }
        if ($logFileSearchScript) {
            $logFileSearchScriptBlock = [scriptBlock]::Create($logFileSearchScript)
            $scriptMatch = Invoke-Command -ScriptBlock $logFileSearchScriptBlock
            $matches.scriptMatch = $scriptMatch
        }
    } else {
       $matches.regExMatch = "Path Failed"
       $matches.scriptMatch = "Path Failed"
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

    function Get-PendingReboot { 
    [CmdletBinding()] 
    param( 
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
        [Alias("CN","Computer")] 
        [String[]]$ComputerName="$env:COMPUTERNAME", 
        [String]$ErrorLog 
    ) 
 
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
 
}

    $rebootStatus  = Get-PendingReboot
    $pendingReboot = $false
    if($rebootStatus.rebootPending -and (-not ($rebootStatus.PendComputerRename -or $rebootStatus.PendFileRename))){
        $pendingReboot = $true
    }

    $diskInfo    = (Get-WmiObject Win32_LogicalDisk -Filter 'driveType = 3' | select-object  -Property DeviceId,FreeSpace,Size)
    $networkInfo = (Get-WmiObject win32_networkadapterconfiguration -Filter 'ipenabled = "true"').ipaddress | ?{$_ -like '*.*.*.*' -and $_ -notlike '169.*.*.*'}
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


