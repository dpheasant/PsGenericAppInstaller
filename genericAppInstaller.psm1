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
        $targetsFile,
        $sitesFile,
        $siteCommandsFile, 
        $parallelism = 10
    )

    ## import the list of targets
    $targets = import-targets -targetsFile $targetsFile -sitesFile $sitesFile -siteCommandsFile $siteCommandsFile

    ## result will be an object that looks like this:
    ##   - FQDN
    ##   - IP (?)
    ##   - Site NAME/ID
    ##   - Installation Command
    ##   - etc... (basically any other columns from above files)

    ## perform pre-req checks
    foreach($target in $targets) {
        ## temporarily add a random 'sleepTime' value to each target as a mockup
        ## for job management
        $sleepTime = get-random -min 10 -max 120
        $target | add-member -type NoteProperty -name sleepTime -value $sleepTime
    }

    ## build a queue of targets
    $targetQueue = New-Object System.Collections.Queue -ArgumentList @(,$targets)

    ## initialize some counters and enter main processing loop    
    $shouldRun     = $true
    $completedJobs = 0
    $failedJobs    = 0
    while($shouldRun) {
        ## get all jobs
        $jobs = get-job -Name 'InstallJob:*'
        $runningJobs = 0

        ## process completed/running/failed jobs
        foreach($job in $jobs) {
            switch($job.State) {
                ## clean up any completed jobs
                "Completed" {
                    write-host ("job {0} {1}" -f $job.name,$job.state)
                    remove-job $job
                    $completedJobs = $completedJobs + 1
                }
                
                ## update job statuses
                "Running" {
                    write-host ("job {0} {1}" -f $job.name,$job.state)
                    $runningJobs = $runningJobs + 1
                }

                "Failed" {
                    write-host ("job {0} {1}" -f $job.name,$job.state)
                    remove-job $job
                    $failedJobs = $failedJobs + 1
                }
            }
        }

        ## start new jobs
        while($runningJobs -lt $parallelism -and $targetQueue.count -gt 0) {
            write-host ("starting job {0}" -f $target.fqdn)
            $target = $targetQueue.Dequeue()
            $target | start-job -name ('InstallJob:{0}' -f $target.fqdn) -FilePath './test_deploymentScript.ps1'
            $runningJobs = $runningJobs + 1
        }

        ## report job state

        ## save job state to stateFile
        write-host ("job count {0}"   -f $jobs.count)
        write-host ("running job count {0}"     -f $runningJobs)
        write-host ("completed job count {0}"   -f $completedJobs)
        write-host ("failed job count {0}"      -f $failedJobs)
        write-host ("parallelism {0}" -f $parallelism)
        write-host ("Queue Size {0}"  -f $targetQueue.Count)
        
        ## if there are remaining jobs, sleep; otherwise we're finished
        if($runningJobs -gt 0) {
            start-sleep -m 500
        } else {
            $shouldRun = $false
        }
    }
}

#endregion

#region MONITORING

function start-installationMonitoring {

}

function get-installJobs {
    
}

function update-jobStatus {

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