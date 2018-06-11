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

$iterations = get-random -min 2 -max 20

write-host ("STATUS: Sleeping for 1 sec {0} times." -f $iterations)

foreach($i in 1..$iterations) {   
    write-host ("STATUS: iteration {0}" -f $i)

    new-status -state 'looping' -message "I'm looping heeah..." -iteration $i -InputObject $InputObject

    start-sleep -Seconds 1
}

write-host "Done."