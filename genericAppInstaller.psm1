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

    ## state object to store/manage job states and overall status info
    $state = new-object -type PSObject -Property @{
        progress  = 0
        running   = 0
        failed    = 0
        completed = 0
        remaining = 0
        jobs      = @{}
    }

    ## build a queue of targets
    $targetQueue = New-Object System.Collections.Queue -ArgumentList @(,$targets)

    ## main processing loop    
    $shouldRun     = $true
    while($shouldRun) {
        ## initalize/zero counters
        $state.running = 0

        ## process completed/running/failed jobs
        foreach($job in (get-job -Name 'InstallJob:*')) {
            
            Receive-Job $job | %{
                $state.jobs[$job.name].output += $_
            }

            ## see if job state changed
            if($state.jobs[$job.name].status -ne $job.State){
                $oldState = $state.jobs[$job.name].status
                $newState = $job.State
                write-host ("{0} changed state from {1} to {2}" -f $job.name,$oldState,$newState)
            }

            ## update job state
            $state.jobs[$job.name].status = $job.State

            switch ($job.State) {
                "Running" {
                    $state.jobs[$job.name].message = ('Script {0} running...' -f $installScript)
                    $state.running++
                }

                "Completed" {
                    $state.completed++
                    $state.jobs[$job.name].message = ('Execution of {0} succeeded...' -f $installScript)
                    remove-job $job
                }

                "Failed" {
                    $state.failed++
                    $state.jobs[$job.name].message = ('Execution of {0} failed...' -f $installScript)
                    remove-job $job
                }
            }
        }

        ## start new jobs
        while($state.running -lt $parallelism -and $targetQueue.count -gt 0) {
            write-host ("starting job {0}" -f $target.fqdn)
            $target = $targetQueue.Dequeue()

            $job = ($target | start-job -name ('InstallJob:{0}' -f $target.fqdn) -FilePath $installScript)

            $state.jobs[$job.name] = new-object -type PSObject -Property @{
                target  = $target.fqdn
                status  = $job.state
                message = 'Installation script started...'
                output  = @()
            }

            $state.running++
        }

        ## update state object
        $state.progress  = (($state.failed+ $state.completed)/$targets.count)*100
        $state.remaining = $targetQueue.Count

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
        if($state.running -gt 0) {
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

Function Write-StatusReport {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        $results,
        [Parameter(Mandatory=$true)]
        [string] $filename
    )

    $InputObject.jobs.values | select-object target,status | Export-Csv $filename
}