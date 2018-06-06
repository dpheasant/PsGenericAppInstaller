#region VARIABLES



#endregion

#region INSTALL

<#
    Function will take in paths for 3 input CSVs: FQDN, network map, site commands
    Will import CSVs in PSObjects

#>
function start-installation {
    [cmdletBinding()]
    param(
        $targets,
        $sites,
        $siteCommands
    )

    ## import the list of targets

    ## import the list of sites and map each target to it's site

    ## import the list of site commands and map to each target

    ## result will be an object that looks like this:
    ##   - FQDN
    ##   - IP (?)
    ##   - Site NAME/ID
    ##   - Installation Command
    ##   - etc... (basically any other columns from above files)

    ## perform pre-req checks

    ## start initial jobs

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