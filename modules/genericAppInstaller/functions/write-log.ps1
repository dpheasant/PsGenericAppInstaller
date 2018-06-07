function write-log () {
    [cmdletBinding()]
    param (
        [parameter(valueFromPipeline=$true,position=1)]
        [alias('m')]
        [string]$message,
        [parameter(position=0)]
        [alias('l')]
        [int]$level = 4,
        [alias('in')]
        $invocationName,
        [alias('cf')]
        [hashtable]$customField,
        [validateSet("none","psObject","CSV","JSON")]
        [string]$outputType = "JSON",
        [string]$outputFilePath = $env:TEMP,
        [string]$outputFileName = "$(Get-Date -Format FileDateUniversal)",
        [bool]$showConsole = $true,
        [bool]$outputFile = $true,
        [switch]$passThru,
        [string]$logShowLevel = "info",
        [hashtable]$levelMap = @{
            6 = "debug"
            4 = "info"
            3 = "warning"
            2 = "error"
        },
        [hashtable]$colorMap = @{
            6 = "cyan"
            4 = "green"
            3 = "yellow"
            2 = "red"
        }
    )
    process {
        if (!$message -or ($outputType -eq "none")) {break}
        if ($level -le ($levelMap.keys | ?{$levelMap[$_] -eq $logShowLevel})) {
            $output = "" | Select-Object "timestamp","level","function","message"
            $output.timestamp = (Get-Date).DateTime
            $output.level     = $($levelMap[$level])
            $output.function  = $invocationName
            $output.message   = $message

            if ($customField) {
                $customField.keys.forEach({
                    $memberParams = @{
                        memberType = "NoteProperty"
                        name       = $_
                        value      = $customField[$_]
                    }
                    $output | Add-Member @memberParams
                })
            }

            $consoleOutput = "$($output.timestamp)`t$($output.level)`t$($output.function)`t$($output.message)`t"
            switch ($outputType) {
                "JSON" {
                    $output = $output | ConvertTo-Json -Depth 100
                    if ($outputFile) {
                        $jsonParams = @{
                            filePath = Join-Path $outputFilePath -ChildPath "$outputFileName.json"
                            append   = $true
                            encoding = "utf8"
                        }
                        $output | Out-File @jsonParams
                    }
                }
                "CSV" {
                    if ($outputFile) {
                        $csvParams = @{
                            path              = Join-Path $outputFilePath -ChildPath "$outputFileName.csv"
                            noTypeInformation = $true
                            append            = $true
                        }
                        $output = $output | Export-Csv @csvParams
                    }
                }
                "psObject" {
                    if ($outputFile) {
                        $txtParams = @{
                            filePath = Join-Path $outputFilePath -ChildPath "$outputFileName.log"
                            append   = $true
                            encoding = "utf8"
                        }
                        $consoleOutput | Out-File @txtParams
                    }
                }
            }

            if ($showConsole) {
                $consoleOutput | Write-Host -ForegroundColor $colorMap[$level]
            }
            
        }
    }
    end {
        if ($passThru) {
            return $output
        }
    }
}