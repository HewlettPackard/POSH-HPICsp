##############################################################################
# MasterSlave_Synchronization.ps1
# - Example script that connects to a master appliance and some amount of slave appliances. 
#   Exports the master content and synchronizes it amongst the slaves.
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

#Connect and download to the master appliance
Connect-HPICMgmt -appliance 192.168.0.1 -User Master -password password

Export-HPICContent -location C:\temp -fileName tempExport.zip

Disconnect-HPICMgmt

#Connect and upload to the first appliance
Connect-HPICMgmt -appliance 10.1.1.7 -User Slave1 -password password

Import-HPICContent  -File C:\temp\tempExport.zip

Disconnect-HPICMgmt

#Connect and upload to the second appliance
Connect-HPICMgmt -appliance 10.1.1.7 -User Slave2 -password password

Import-HPICContent  -File C:\temp\tempExport.zip

Disconnect-HPICMgmt

#Delete the exported content
Remove-Item C:\temp\tempExport.zip