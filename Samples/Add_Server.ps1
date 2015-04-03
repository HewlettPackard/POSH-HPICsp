##############################################################################
# Add_Server.ps1
# - Example script to add a server through its iLO credentials, 
#   run an OS Build Plan on it and do some post network configuration.
#
#   VERSION 1.00
#
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
##############################################################################
<#
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>
##############################################################################
Import-Module HPICsp

# First connect to the Appliance
if (!$global:myAppliance) {
    $global:myAppliance = Read-Host "HP Insight Control server provisioning Appliance hostname or IP address"
    }
Write-Host "Connecting to" $global:myAppliance
Connect-HPICMgmt -appliance $global:myAppliance

#Monitor the addition of a server
$result = New-HPICServer | Watch-Job

#Parse output to get the new Server ID and create a JSON body containing its URI
$serverID = ($result.jobResult[0].jobResultLogDetails -split 'ServerRef:')[1].split(')')[0]
$jobBody = @{osbpUris=@("/rest/os-deployment-build-plans/720001");serverData=@(@{serverUri="/rest/os-deployment-servers/" + $serverID})}

#Run Red Hat 6.4 Install Build Plan on the newly added server.
New-HPICJob $jobBody | Watch-Job

#Generate a JSON body for some post network configuration.
$networkConfig = @{serverData=@(@{serverUri="/rest/os-deployment-servers/" + $serverID;personalityData=@{hostName="hostName";displayName="Example"}})}

#Start a job to configure the server's network data.
New-HPICJob $networkConfig | Watch-Job

Disconnect-HPICMgmt