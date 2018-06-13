# PsGenericAppInstaller
This powershell module is intended to provide a generic platform for running powershell (installation) scripts against a large number of clients (targets).

## Architecture
This module is itself modularized so that components may easily be replaced/enhanced without affecting other portions of the script.

Sub-Modules:
- InputHandlers: This module is responsible for parsing the input files and returning an object that will eventually be passed to the main installation script. Essentially, this object should contain all the information necessary for the installation script to operate.

## High-Level operation
After importing the module itself, the installation process is started by calling `start-installation`. For example:
```
start-installation `
        -targets 'targets.csv' `
        -sites   'sites.csv' `
        -siteCommands 'site_commands.csv' `
        -installScript 'deploymentScript.ps1' `
        -parallelism 120
```
When this command is run, the script will read the 3 input files and create a PSObject which will be passed to the installScript. The script will start 120 installation jobs, running in parallel. The script will print some status information while running:
```
InstallJob:client6.site4.domain.com Running
InstallJob:client7.site4.domain.com Running
InstallJob:client9.site4.domain.com Running
InstallJob:client10.site4.domain.com Running
InstallJob:client1.site5.domain.com Running
InstallJob:client2.site5.domain.com Running
InstallJob:client3.site5.domain.com Running
InstallJob:client4.site5.domain.com Running
InstallJob:client5.site5.domain.com Running
InstallJob:client6.site5.domain.com Running
Job Status: 10 running, 0 failed, 36 completed, 4 queued (72% complete)
```

## Input files
Input files are expected to be in CSV format. The columns indicated below are for the defailt configuration but can be easily modified by changing the appropraite `*_PROPERTY_MAP` in `modules/inputHandlers/inputHandlers.psm1`
- Targets (targets.csv)
    - ip
    - fqdn
- Sites (sites.csv)
    - id: the name/id of the site
    - Network CIDR (the network CIDR)
- SiteCommands (site_commands.csv)
    - siteId (must match id specified in 'sites' file)
    - logfileRegex
    - logfileParser
    - packageLocation
    - command
    - logfile

## Troubleshooting
1. Script errors with `RuntimeException: Unable to find site command for site <site>`
    Double check the column names in the targets and sites input files match what the inputHandler is expecting.