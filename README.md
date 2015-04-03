# POSH-HPICsp

Prerequisites:
 Microsoft .NET Framework 4.0
 Microsoft PowerShell 3.0

How to Install:
 Copy the bindings files into a directory on you system, for example C:\bindings\modules\hpicsp. Add the directory
 the module is in to the PSModulePath environment variable to make it available to PowerShell. Using the previous
 example the PSModulePath environment variable is modifed to include the new path:
 PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules\;c:\bindings\modules\

How to Use:
 In a PowerShell command line shell enter the command "Import-Module hpicsp". This will load the Insight Control
 server provisioning module and make the functions available to perform REST commands to the appliance in a CLI manner.
 The bindings can also be used in scripts and three examples are included:

Add_Server.ps1 - logs in to the Insight Control server provisioning appliance, adds a new server, deploys an OS
   build plan to the server, and then configures the network on the deployed server. The new-HPICServer command
   will need to be customized with the appropriate server information to point to an actual server.

Backup_Content.ps1 - does a scripted backup of the content of the appliance.

MasterSlave_Synchronization.ps1 - synchronizes two Insight Control server provisioning appliances with a "master"
   Insight Control server provisioning appliance.

 In all cases these scripts will need to be customized with the ip addresses and credentials for your environment to operate correctly.

Help:
 To get a list of the available CMDLETs in this library, type: Get-Help HPIC
 To get help for a specific command, type: Get-Help  verb-HPICnoun
 To get extended help for a specific command, type: Get-Help  verb-HPICnoun -full

 The Insight Control server provisioning REST API specification, available at
 http://h17007.www1.hp.com/docs/enterprise/servers/icsp/7.4/api_reference/index.html,
 documents the REST APIs behind these bindings and contains the detailed information
 about the data returned by them.



