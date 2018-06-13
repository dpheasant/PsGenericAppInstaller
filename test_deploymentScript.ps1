Param(
    [Parameter(ValueFromPipeline=$true)]
    $InputObject
)

## creates a status object
function new-status {
    Param(
        [string] $state,
        [string] $message,
        [int]    $iteration,
        [object] $InputObject
    )

    $status = new-object -type PSObject -Property @{
        state     = $state
        message   = $message
        iteration = $iteration
        inputObject = $InputObject
    }

    return $status
}

$iterations = get-random -min 2 -max 5

foreach($i in 1..$iterations) {
    new-status -state 'looping' -message "I'm loopin' heeah..." -iteration $i -InputObject $InputObject

    start-sleep -Seconds 1
}

write-host "Done."