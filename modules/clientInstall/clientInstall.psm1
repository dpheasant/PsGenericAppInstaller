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