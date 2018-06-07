<#
    Read a csv containing a list of targets and return them as PSObjects
#>
function Get-Targets {
    Param(
        [String] $filename
    )

    try {
        $targets = get-content $filename | ConvertFrom-Csv
    }
    catch {
        throw $Error[0]
    }

}

function Get-Sites {

}

function Get-SiteCommands {

}