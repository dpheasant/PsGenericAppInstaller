#region VARIABLES

#endregion

#region INSTALL

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
import-module -Force (resolve-path "$here/modules/inputHandlers")

<#
    Function will take in paths for 3 input CSVs: FQDN, network map, site commands
    Will import CSVs in PSObjects
#>
function start-installation {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $targetsFile,

        [Parameter(Mandatory=$true)]
        $sitesFile,

        [Parameter(Mandatory=$true)]
        $siteCommandsFile,

        [Parameter(Mandatory=$true)]
        $installScript,

        $parallelism = 10,
        $statefile = 'job_state.psxml'
    )

    ## import the list of targets
    $targets   = import-targets -targetsFile $targetsFile -sitesFile $sitesFile -siteCommandsFile $siteCommandsFile
    $jobStates = @{}

    ## build a queue of targets
    $targetQueue = New-Object System.Collections.Queue -ArgumentList @(,$targets)

    ## initialize some counters and enter main processing loop    
    $shouldRun     = $true
    $completedJobs = 0
    $failedJobs    = 0
    while($shouldRun) {
        ## initalize counters
        $runningJobs = 0

        ## process completed/running/failed jobs
        foreach($job in (get-job -Name 'InstallJob:*')) {
            switch ($job.State) {
                "Running" {
                    write-host ("{0} {1}" -f $job.name,$job.state)
                    Receive-Job $job | %{
                        $jobStates[$job.name] = $_
                    }
                    $runningJobs++
                }

                "Completed" {
                    write-host ("{0} {1}" -f $job.name,$job.state)
                    $completedJobs++
                    $jobStates.remove($job.name)
                    remove-job $job
                }

                "Failed" {
                    write-host ("{0} {1}" -f $job.name,$job.state)
                    $failedJobs++
                    $jobStates.remove($job.name)
                    remove-job $job
                }
            }
        }

        ## start new jobs
        while($runningJobs -lt $parallelism -and $targetQueue.count -gt 0) {
            write-host ("starting job {0}" -f $target.fqdn)
            $target = $targetQueue.Dequeue()
            $job = ($target | start-job -name ('InstallJob:{0}' -f $target.fqdn) -FilePath $installScript)
            $jobStates.add($job.name, 'Installation script started...')
            $runningJobs++
        }

        ## buile state object
        $state = @{
            progress  = (($failedJobs + $completedJobs)/$targets.count)*100
            jobs      = $jobStates
            running   = $runningJobs
            failed    = $failedJobs
            completed = $completedJobs
            remaining = $targetQueue.Count
        }

        ## save job state to stateFile
        $state | Export-Clixml $statefile
        
        ## print status
        write-host ("Job Status: {0} running, {1} failed, {2} completed, {3} queued ({4}% complete) " -f
            $state.running,`
            $state.failed,`
            $state.completed,`
            $state.remaining,`
            $state.progress)

        ## if there are remaining jobs, sleep; otherwise we're finished
        if($runningJobs -gt 0) {
            start-sleep -m 500
        } else {
            $shouldRun = $false
        }
    }

    return $state
}

function Start-StatusMonitor {
    [cmdletBinding()]
    param(
        [string] $stateFile = 'job_state.psxml',
        [int] $interval = 1
    )

    $shouldRun = $true
    while($shouldRun) {
        clear-host

        if(-not (test-path $stateFile)) {
            Write-Host "No statefile found..."
            start-sleep -Seconds $interval
            continue
        }

        try {
            $state = Import-Clixml $stateFile

            if($state.jobs.count -eq 0) {
                write-host "No job information found in statefile..."
                start-sleep -Seconds $interval
                continue
            }

            write-host ("Job Status: {0} running, {1} failed, {2} completed, {3} queued ({4}% complete) " -f
            $state.running,`
            $state.failed,`
            $state.completed,`
            $state.remaining,`
            $state.progress)

            foreach($jobName in $state.jobs.keys) {
                write-host ("{0}: {1}" -f $jobName,$state.jobs[$jobName].message)
            }

            start-sleep -Seconds $interval
        }
        catch {}
    }
}
#endregion

#region MONITORING

function start-installationMonitoring {

}

function get-installJobs {
    
}

#endregion

#region REMOTE

function copy-installer {

}

function copy-gatherData {

}

function new-remoteStatusFile {

}

function get-remoteData {

}

function start-installer {

}

function update-statusFile {

}

#endregion