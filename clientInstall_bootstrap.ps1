Param(
    [Parameter(ValueFromPipeline=$true)]
    $InputObject
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
import-module -Force (resolve-path "$here/modules/clientInstall")

## modify line below to start client-side install script
#$InputObject | start-clientIntallTasks 
