

    ## import the list of targets
    $targets = import-targets -targets $targetsFile

    ## import the list of sites and map each target to it's site
    $targets = import-sites -targets $targets -sites $sitesFile

    ## import the list of site commands and map to each target
    $targets = import-siteCommands -targets $targets -siteCommands $siteCommandsFile

    ## $targets will be a collection of $target objects that look like:
    ##   - FQDN
    ##   - IP (?)
    ##   - Site NAME/ID
    ##   - Installation Command
    ##   - etc... (basically any other columns from above files)

    $queuedInstallations = ## [System.Collections.Queue]
    ## reconcile $targets with output
    if(test-file $outputFile) {
        $completedInstallations =....
        foreach ($target in $targets) {
            if ($target -notin $completedInstallations) {
                $queuedInstallations.enque($target)
            }
        } 
    }

    ## main job loop
    while(test-shouldRun) {
        if(test-installSlotFree) {
            ## start a new installation job
            new-installJob -target $targetQueue.dequeue()
        }

        ## check for completed jobs

        ## update status/state

        ## sleep 5sec
    }

    

    ## perform pre-req checks

    ## start initial jobs

    ## loop until done

    ## cleanup/reporting

    ## done.


function test-shouldRun {

    ## if queue is not empty return true

    ## if queue is empty but jobs still running return true

    ## if queue is empty and jobs are all complete return false

}