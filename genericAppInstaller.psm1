#region VARIABLES



#endregion

#region INSTALL

import-module $(join-path "modules" "inputHandlers")

<#
    Function will take in paths for 3 input CSVs: FQDN, network map, site commands
    Will import CSVs in PSObjects
#>
function start-installation {
    [cmdletBinding()]
    param(
        $targets,
        $sites,
        $siteCommands, 
        $parallelism = 150
    )

    ## import the list of targets
    $targets = import-targets -targetsFile $targets -sitesFile $sites -siteCommandsFile $siteCommands

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

    ## build the job queue
    $jobQueue = New-Object System.Collections.Queue -ArgumentList $targets

    ## start the jobs
    while(test-jobSlotFree) {
        ## clean up any completed jobs

        ## start new jobs

        ## sleep

    }

    ## loop until done

    ## cleanup/reporting

    ## done.
}

function import-targets {
    
}

function import-sites {

}

function import-siteCommands {

}

function get-networkSite {

}

function new-installJob {

}

function test-jobSlotFree {

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