Param(
    [Parameter(ValueFromPipeline=$true)]
    $InputObject
)

$here = "C:\scripts\PsGenericAppInstaller"

import-module -Force (resolve-path "$here/modules/clientInstall/clientinstall.psm1")
import-module -Force (resolve-path "$here/modules/logging/write-log.psm1")
import-module -Force (resolve-path "$here/modules/preRequisites/test-prerequisites.psm1")

## modify line below to start client-side install script
$InputObject | start-clientIntallTasks
