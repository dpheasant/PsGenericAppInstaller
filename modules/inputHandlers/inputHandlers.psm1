## import dependencies
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
import-module -Force (resolve-path "$here/../utils")

## map object/powershell property names to the CSV columns
$TARGET_PROPERTY_MAP = @(
    @{Name="ip"   ; Expression = {$_."ip"}},
    @{Name="fqdn" ; Expression = {$_."fqdn"}},
    "siteId",
    "siteCidr",
    "executionCmdLine",
    "outputPath"
)

$SITE_PROPERTY_MAP = @(
    @{Name="id"         ; Expression = {$_."Site ID"}},
    @{Name="networkCidr"; Expression = {$_."Network CIDR"}}
)

$SITE_COMMANDS_PROPERTY_MAP = @(
    @{Name="siteId"  ; Expression = {$_."Site ID"}},
    @{Name="logfileRegex"    ; Expression = {$_."Logfile Regex"}},
    @{Name="logFileSearchScript"   ; Expression = {$_."Logfile Search Script"}},
    @{Name="packageLocation" ; Expression = {$_."Package Location"}},
    @{Name="executionCmdLine" ; Expression = {$_."Execution Command Line"}},
    @{Name="logFileLocation" ; Expression = {$_."Installed Logfile Location"}}
    @{Name="packageID" ; Expression = {$_."Package ID"}}
    @{Name="detectionScript" ; Expression = {$_."Detection Script"}}
    @{Name="outputPath" ; Expression = {$_."Output File Location"}}
)

<#
    Read a csv containing a list of targets and return them as PSObjects
#>
function Import-Targets {
    Param(
        [Parameter(Mandatory=$true)]
        [String] $targetsFile,

        [Parameter(Mandatory=$true)]
        [String] $sitesFile,

        [Parameter(Mandatory=$true)]
        [String] $siteCommandsFile
    )

    try {
        ## import the data from CSV and rename/standardize the columns/properties
        $targets = Import-Csv $targetsFile | select-object $TARGET_PROPERTY_MAP
        $sites   = Import-Csv $sitesFile   | select-object $SITE_PROPERTY_MAP
        $siteCommands = Import-Csv $siteCommandsFile | select-object $SITE_COMMANDS_PROPERTY_MAP

        ## loop through targets and merge data from sites and site-commands
        foreach($target in $targets) {
            ## look up the target's site ID by matching it's ip to the site's CIDR address
            $site = $sites | where-object { Test-CidrMembership $target.ip $_.networkCidr }
            if($site) {
                $target.siteId   = $site.id
                $target.siteCidr = $site.networkCidr
            } else {
                throw ("Unable to find site for target {0}({1})." -f $target.fqdn,$target.ip)
            }

            $siteCommand = $siteCommands | Where-Object { $target.siteId -eq $_.siteId }
            if($siteCommand) {
                $target.executionCmdLine = $siteCommand

                $target.siteId              = $siteCommand.siteId
                $target.logfileRegex        = $siteCommand.logfileRegex
                $target.logFileSearchScript = $siteCommand.logFileSearchScript
                $target.packageLocation     = $siteCommand.packageLocation
                $target.executionCmdLine    = $siteCommand.executionCmdLine
                $target.logFileLocation     = $siteCommand.logFileLocation
                $target.packageID           = $siteCommand.packageID
                $target.detectionScript     = $siteCommand.detectionScript
                $target.outputPath          = $siteCommand.outputPath

            } else {
                throw ("Unable to find site command for site {0}." -f $target.siteId)
            }
        }
        return $targets
    }
    catch {
        throw $_
    }
}