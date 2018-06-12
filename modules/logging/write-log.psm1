<#
.Synopsis
   This cmdlet is as a log wrapper that will take a message and redirect to a number of different outputs and filters.
.DESCRIPTION
   Long description
.EXAMPLE
   New-Alias -Name log write-log
   function test-function () {
       $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName}
       "Log Message" | log
   }
   test-function

   Thursday, June 7, 2018 10:50:06 AM	info	test-function	Log Message

   This example first shortens the full name to 'log' as an alias for convienience when calling repeatedly. It then calls the logging function inside a test function
   to highlight the use of the invocation name parameter. All other parameters are left at default. The output seen is the console output but this function also writes 
   JSON output to $env:Temp\20180607Z.json which appears in the file as:

   {
    "timestamp":  "Thursday, June 7, 2018 10:50:06 AM",
    "level":  "info",
    "function":  "test-function",
    "message":  "Log Message"
    }

.EXAMPLE
   New-Alias -Name log write-log
   function test-function () {
       $pSDefaultParameterValues = @{'log:invocationName' = $myInvocation.invocationName
                                     'log:outputType'     = 'CSV'}
       $testValue = "1"
       "Log Message" | log -l 2 -cf @{"Example" = $testValue}
   }
   test-function

   Thursday, June 7, 2018 11:09:24 AM	error	test-function	Log Message	Example = 1

   This example changes the output type to csv, adds a custom output field and and sets the log level to 2 (error). The above shows the console output.
   Below is the CSV output:

   "timestamp","level","function","message","Example"
    "Thursday, June 7, 2018 11:14:00 AM","error","test-function","Log Message","1"

.INPUTS

.PARAMETER message
    This is the log message string.
.PARAMETER level
    This is log level, or importance, of the message string. The text description of the numerical level can be found in the level map.
.PARAMETER invocationName
    This is the name of the invoking function generating the log message. Best used with the $myInvocation.invocationName powershell automatic variable.
    For convienience this can be set as a default parameter value in the parent script or module.
.PARAMETER customField
    This is used for adding custom values for log entries in the form of hashtables. Useful for recording the value of variables in the log without needing
    to parse message strings.
.PARAMETER outputType
    This is how the log message and other fields will be output. Can be JSON, CSV, psObject, or none. This is separate from console functionality.
.PARAMETER outputFilePath
    This is the PARENT path where any log output files will be written to.
.PARAMETER showConsole
    This is a switch to either display or not display output to the console.
.PARAMETER outputFile
    This is a switch to append the log output to a file or not.
.PARAMETER passThru
    This is a switch to send the log object (format determined by outputType) to stdout for the function.
.PARAMETER logShowLevel
    This is a filter for which level of logging to display. Function will record any log at or below the level specified in this parameter (level names in level map).
.PARAMETER levelMap
    This is a hastable that defines the log level numbers and their associated descriptions.
.PARAMETER colorMap
    This is a hashtable that defines what colors will be displayed on console for per log level.
#>

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
            $consoleOutput = "$($output.timestamp)`t$($output.level)`t$($output.function)`t$($output.message)"

            if ($customField) {
                $customField.keys.forEach({
                    $memberParams = @{
                        memberType = "NoteProperty"
                        name       = $_
                        value      = $customField[$_]
                    }
                    $output | Add-Member @memberParams
                    $consoleOutput += "`t$_ = $($customField[$_] | Out-String)"
                })
            }

            
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
                            force             = $true
                        }
                        $output | Export-Csv @csvParams
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