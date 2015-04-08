##############################################################################
# HP Insight Control server provisioning PowerShell Library
##############################################################################
##############################################################################
## (C) Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
##############################################################################

#Set HPICsp POSH Library Version
$script:scriptVersion = "1.01"

# Default handle self-signed certs
$script:SSLCheckFlag = $False

#If the PKI.HPInsightControl.SslCertificate Class is not currently loaded, load it
#This is to fix a limitation in the .Net CLR, where PowerShell maintains a single AppDomain context. Custom Classes loaded cannot be unloaded without
#terminating the existing PowerShell console session.
if (! ("PKI.HPInsightControl.SslCertificate" -as [type])) {

    add-type @"
    using System;
    using System.Collections;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;


        // Namespace PKI.HPInsightControl used for SSL Certificate handling
        namespace PKI {
                namespace HPInsightControl {
                        public class SslCertificate {
                                public Uri OriginalURi;
                                public Uri ReturnedURi;
                                public X509Certificate2 Certificate;
                                public string Issuer;
                                public string Subject;
                                public string[] SubjectAlternativeNames;
                                public bool CertificateIsValid;
                                public string[] ErrorInformation;
                                public HttpWebResponse Response;
                        }
        }
    }

    //Define the [System.Net.ServicePointManager]::CertificatePolicy for the library
    public class HPInsightControlIgnoreCertPolicy : ICertificatePolicy {
        public HPInsightControlIgnoreCertPolicy() {}
        public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb)
            {
                        return true;
                }
    }
"@
}

$debugMode = $False

#Note: Set $debugPreference to control debug logging
If ($debugmode) {
    $debugPreference = "Continue"         # Display requests and responses
    $VerbosePreference = "Continue"
}
#Else{ $debugPreference = "SilentlyContinue" } # Hide debug messages

$script:HPICAppliance = $null
$global:cimgmtICspSessionId = $null
$script:lastWebResponse = $null
$script:defaultTimeout = New-TimeSpan -Minutes 20

$script:loginSessionsUri = "/rest/login-sessions"
$script:applXApiVersion = "/rest/version"
$script:applVersion = "/rest/appliance/version"

$script:server = "/rest/os-deployment-servers"
$script:buildplan = "/rest/os-deployment-build-plans"
$script:serverScript = "/rest/os-deployment-server-scripts"
$script:ogfsScript= "/rest/os-deployment-ogfs-scripts"
$script:cfg="/rest/os-deployment-install-cfgfiles"
$script:settings= "/rest/os-deployment-settings"
$script:package = "/rest/os-deployment-install-zips"
$script:job = "/rest/os-deployment-jobs"
$script:ilo = "/rest/os-deployment-ilos"
$script:facility = "/rest/os-deployment-facility"
$script:deviceGroup = "/rest/os-deployment-device-groups"
$script:apx = "/rest/os-deployment-apxs"
$script:apxbuild="/rest/os-deployment-apxs/runosbps"
$script:DHCPconfig="/rest/os-deployment-settings/OsdDhcpConfig"
$script:WinPE="/rest/os-deployment-settings/WinPE"
$script:importContent="/rest/os-deployment-settings/importContent"
$script:exportContent="/rest/os-deployment-settings/exportContent"
$script:tools="/rest/os-deployment-settings/file/"
$script:personalizeserver="/rest/os-deployment-apxs/personalizeserver"
#######################################################
# Basic Support Functions
#

function verify-auth {

    <#
        .SYNOPSIS
        Verify user is authenticated.

        .DESCRIPTION
        Internal module helper function to assist with verifying the user is authencticated to an appliance.  Will generate terminating error if not.

        .PARAMETER uri
        Optional.  The uri that identifies the required resource on the appliance.

        .EXAMPLE
        Add the following to your cmdlet:

            Begin {
                verify-auth "[verb]-HPIC[noun]"
                < Code to pre-process >
            }

            Process {
                < Your code >
            }

    #>

    [CmdletBinding()]
    Param (
         [parameter(Mandatory=$true,HelpMessage="Provide the source CMDLET name")]
         [ValidateNotNullOrEmpty()]
         [string]$cmdlet

    )

    Process {

        If (!$global:cimgmtICspSessionId){
                        Write-Error -Message "You are not connected to an appliance. Recommended Action: Please use Connect-HPICmgmt to connect to your appliance." -Category AuthenticationError -CategoryTargetName $cmdlet -CategoryReason "Not connected" -RecommendedAction "Please use Connect-HPICmgmt to connect to your appliance."
                        break
                }
    }
}

function Send-HPICRequest {
    <#
        .SYNOPSIS
        Sends a request to the appliance

        .DESCRIPTION
        Receives the request input, properly constructs and formats the request header and body and sends the request to the management appliance.  This is the main cmdlet that interacts with the appliance.

                The message body can contain valid JSON data, with the correct URI and accepted HTTP method accepted by the target resource manager.

        .PARAMETER uri
        The uri that identifies the required resource on the appliance.

        .PARAMETER method
        Optional. The request HTTP Method.

            • "GET" (default) to get a resource from the appliance (read)
            • "POST" to create a new resource
            • "PUT" to modify a resource (write)
            • "DELETE" to delete a resource

        .PARAMETER body
        Optional. Body for the request.  Required if the method is POST or PUT.

        .PARAMETER start
        Optional. For GETs on resource collections (implemented for OGFS/Server Scripts), this specifies the starting index in the collection.
        If not specified, collection members starting from the beginning are returned.

        .PARAMETER count
        Optional. For GETs on resource collections (implemented for OGFS/Server Scripts), this specifies the number of collection members to return.
        If not specified, all members of the collection are returned from this function.

        .INPUTS
        None. You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Array
            If collection of resources $thing(.i.e. GET /rest/os-deployment-servers)

        System.ObjectSystem.Management.Automation.PSCustomObject

            Single object returned from appliance

        .LINK
        Connect-HPICmgmt

        .EXAMPLE
        PS C:\> Send-HPICRequest "/rest/os-deployment-servers"

        Returns all the server objects managed by the appliance.

        .EXAMPLE
        PS C:\> $e = Send-HPICRequest "/rest/os-deployment-servers/210001"
        PS C:\> $e.name = "New Name"
        PS C:\> Send-HPICRequest $e.uri "PUT" $e

        Updates the name of the server object specified by the uri.

    #>

    [CmdletBinding()]
    Param (
         [parameter(Mandatory=$true,HelpMessage="Enter the resource URI (ex. /rest/os-deployment-servers)")]
         [ValidateNotNullOrEmpty()]
         [string]$uri,

         [parameter(Mandatory=$false)]
         [string]$method="GET",

         [parameter(Mandatory=$false)]
         [object]$body=$null,

         [parameter(Mandatory=$false)]
         [int]$start=0,

         [parameter(Mandatory=$false)]
         [int]$count=0


    )

    Begin {


        #Check how to handle SSL Certificates
        if (! $script:SSLCheckFlag) {



            #Out-Host is IMPORTANT, otherwise, the Certificate Details will NOT display when called from Connect-HPICMgmt, or any other cmdlet for that matter.
            Show-HPICSSLCertificate | Out-Host

            #If cert is untrusted, set ServicePointManager to ignore cert checking
            if ($global:icspCertTrusted -eq $False) { [System.Net.ServicePointManager]::CertificatePolicy = new-object HPInsightControlIgnoreCertPolicy }

            $script:SSLCheckFlag = $True
        }

        #Need to check for authenticated session when the URI passed is not value of $script:loginSessionsUri
        Write-Verbose "[SEND-HPICREQUEST] Requested URI: $($uri)"
        If ((!$global:cimgmtICspSessionId ) -and ($uri -ine $script:loginSessionsUri)) {
            write-verbose "[SEND-HPICREQUEST] We have reached the URI Whitelist condition block"

            #URI Whitelist
            if ($uri -eq $script:applUpdateMonitor) { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            elseif ($uri -eq $script:applXApiVersion) { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            elseif ($uri -eq "/ui-js/pages/") { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            elseif ($uri -eq $applEulaStatus) { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            elseif ($uri -eq $applEulaSave) { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            elseif ($uri -eq ($usersUri + "/changePassword")) { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request
            #elseif ($uri -eq "/startstop/rest/component?fields=status") { Write-Verbose "[SEND-HPICREQUEST] Unauth request allowed." } #Allow the unauthenticated request

            #Else, require authentication
            else {
                    Write-Verbose "[SEND-HPICREQUEST] Checking auth."
                    verify-auth "Send-HPICRequest"
                    break
            }
        }
    }

    Process {

        Write-Verbose "[SEND-HPICREQUEST] Requested URI: $($uri)"


        #Pagination handling:
        [PSCustomObject]$allMembers = @();

        #See if the caller specified a count, either in the URI or as a param
        #(if so, we will let them handle pagination manually)
        [bool]$manualPaging=$false

        if ($uri.ToLower().Contains("count=") -or $uri.ToLower().Contains("count =")) {

            $manualPaging=$true

        }
        elseif ($count -gt 0) {

            $manualPaging=$true

            #add start & count params to the URI
            if (-not ($uri -contains "?")) {

                $uri += "?"

            }

            $uri += ("start=" + $start + "&")

            $uri += ("count=" + $count)
        }
        elseif ($start -gt 0) {

            #start specified, but no count -- just set the start param & auto-page from there on:
            $manualPaging = $false

            if (-not ($uri -contains "?")) {

                $uri += "?"

            }

            $uri += ("start=" + $start)
        }

        do {

            $req = [System.Net.WebRequest]::Create("https://" + $script:HPICAppliance + $uri)
            $req.Method = $method
            $req.ContentType = "application/json"
            $req.Accept = "application/json"
                $req.Headers.Item("X-API-Version") = $MaxXAPIVersion
            $req.Headers.Item("accept-language") = "en"
            $req.Headers.Item("accept-encoding") = "gzip, deflate"

            if ($global:cimgmtICspSessionId) {

                $req.Headers.Item("auth") = $global:cimgmtICspSessionId.sessionID

            }

            #Send the request with a messege
            if ($body) {

                write-Verbose "[SEND-HPICREQUEST] Body object found. Converting to JSON."

                if ($method -eq "PUT") {

                    #Handle eTags from connection manager
                    $req.Headers.Item("If-match") = $body.etag

                }

                #Create a new stream writer to write the json to the request stream.
                        $js = $body | ConvertTo-Json -Depth 99 -Compress

                if ($body.GetType().ToString() -eq "System.Object[]") {
                                $js = "[" + $js + "]"
                }

                        write-verbose "[SEND-HPICREQUEST] Request Body: $($js)"

                #Send the message
                        $stream = New-Object IO.StreamWriter $req.GetRequestStream()
                        $stream.AutoFlush = $True
                        $stream.WriteLine($js)
                        $stream.Close()
            }

            Write-Verbose "[SEND-HPICREQUEST] Request: $($method) https://$($script:HPICAppliance)$($uri)"

            #Write Verbose the headers if needed
            $i = 0
            foreach ($h in $req.Headers) { Write-Verbose "[SEND-HPICREQUEST] Request Header: $($h) = $($req.Headers[$i])"; $i++ }

            try {
                $i = 0
                #just to be sure this is cleared, if an exception is thrown
                $script:lastWebResponse = $null

                #Get response from appliance
                $script:lastWebResponse = $req.GetResponse()

                #Display the response status if verbose output is requested
                Write-Verbose "[SEND-HPICREQUEST] Response Status: $([int]$script:lastWebResponse.StatusCode) $($script:lastWebResponse.StatusDescription)"
                foreach ($h in $script:lastWebResponse.Headers) { Write-Verbose "[SEND-HPICREQUEST] Response Header: $($h) = $($script:lastWebResponse.Headers[$i])"; $i++ }

                #Decompress the response if encoded
                switch ($script:lastWebResponse.Headers.Item("Content-Encoding")) {

                    "gzip"    { $decompress = New-Object System.IO.Compression.GZipStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                    "deflate" { $decompress = New-Object System.IO.Compression.DeflateStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                    default   { $decompress = $script:lastWebResponse.GetResponseStream() }

                }

                #Read the response
                $reader = New-Object System.IO.StreamReader($decompress)
                $responseJson = $reader.ReadToEnd()
                $decompress.Close();
                $reader.Close();

                Write-Verbose "[SEND-HPICREQUEST] Response: $($responseJson | ConvertFrom-Json | out-string)"
                $resp = ConvertFrom-json $responseJson


                #Handle multi-page result sets
                if ($resp.members -and (-not $manualPaging)) {

                    $allMembers += $resp.members

                    if ($resp.nextPageUri) {

                        $uri = $resp.nextPageUri

                    }
                    else {

                        $allResults=@{members=$allMembers; count=$allMembers.Count; category=$resp.category}

                        return $allResults
                    }
                }

                #If asynchronous (HTTP status=202), make sure we return a Task object:
                elseif ([int]$script:lastWebResponse.StatusCode -eq 202) {

                    Write-Verbose "[SEND-HPICREQUEST] Async Task Received"

                    #Asynchronous operation -- in some cases we get the Task object returned in the body.
                    #In other cases, we only get the Task URI in the Location header.
                    #In either case, return a Task object with as much information as we know
                    if ($script:lastWebResponse.Headers.Item('Location') -and (!$resp)) {

                        #Only have the Task URI - generate a Task object to be returned:
                        [string]$taskUri = $script:lastWebResponse.Headers.Item('Location')

                        #First, make sure the task URI is relative:
                        $pos = $taskUri.IndexOf("/rest/")

                        if ($pos -gt 0) {

                            $taskUri = $taskUri.Substring($pos)

                        }

                        #Create the Task object to return
                        $resp = @{
                            uri = $taskUri;
                            category = "tasks";
                            type = "TaskResourceV2";
                            taskState = "New"}

                    }
                    elseif (!$resp) {

                        #Error (REST API issue) -- asynch op with no Task object or Task URI returned!
                        Write-Error "REST API ERROR: The operation is asynchronous, but neither a Task resource or URI was returned!" -Category InvalidResult -CategoryTargetName "Send-HPICRequest"
                        Break

                    }

                    return $resp

                }

                else {

                    return $resp

                }

           }

            catch [Net.WebException] {
                Write-Verbose "[SEND-HPICREQUEST] Net.WebException Error caught"

                #write-host $_.Exception.Message -ForegroundColor Red
                if ($_.Exception.InnerException) {

                    if ($_.Exception.InnerException.Response) {

                        $script:lastWebResponse = $_.Exception.InnerException.Response

                    }

                    else {

                        Write-Error $_.Exception.InnerException.Message

                    }

                }

                else {

                    if ($_.Exception.Response) {

                        $script:lastWebResponse = $_.Exception.Response

                    }

                    else {

                        Write-Error $_.Exception.Message

                    }
                }

                if ($script:lastWebResponse) {

                    #Decompress the response if encoded
                    switch ($script:lastWebResponse.Headers.Item("Content-Encoding")) {

                        "gzip"    { $decompress = New-Object System.IO.Compression.GZipStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                        "deflate" { $decompress = New-Object System.IO.Compression.DeflateStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                        default   { $decompress = $script:lastWebResponse.GetResponseStream() }
                    }

                    $reader = New-Object System.IO.StreamReader($decompress)
                    $responseJson = $reader.ReadToEnd()

                    Write-Verbose "[SEND-HPICREQUEST] ERROR RESPONSE: $($responseJson | ConvertFrom-Json | out-string)"
                    Write-Verbose "[SEND-HPICREQUEST] Response Status: HTTP_$([int]$script:lastWebResponse.StatusCode) $($script:lastWebResponse.StatusDescription)"
                    foreach ($h in $script:lastWebResponse.Headers) { Write-Verbose "[SEND-HPICREQUEST] Response Header: $($h) = $($script:lastWebResponse.Headers[$i])"; $i++ }

                    $resp = $responseJson | ConvertFrom-Json
                    $resp | Add-Member -MemberType NoteProperty -Name statusCode -Value ([int]$script:lastWebResponse.StatusCode) -Force

                     #user is authorized
                    if ([int]$script:lastWebResponse.StatusCode -eq 401) {

                        Write-Error "Your session has timed out or is not valid. Please use Connect-HPICMgmt to authenticate to your appliance." -Category AuthenticationError -CategoryReason "Unauthorized or Authentication timeout."
                        $script:HPICAppliance = $null
                        $Script:PromptApplianceHostname = "Not Connected"
                        $Appliance = $null
                        $global:cimgmtICspSessionId = $null

                    }

                    #Wait for appliance startup here by calling Wait-HPICApplianceStart
                    if (([int]$script:lastWebResponse.StatusCode -eq 503) -or ([int]$script:lastWebResponse.StatusCode -eq 0)) {
                        Wait-HPICApplianceStart
                        return (Send-HPICRequest $uri $method $body)
                    }

                    return $resp

                }

                else {
                    Write-Verbose "[SEND-HPICREQUEST] Returning Null"
                    return $null

                }
            }

        } while($resp.nextPageUri)
    }

    End {

        # handle self-signed certs
        #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $Null }

    }
}

function Wait-HPICApplianceStart {

    <#

        .SYNOPSIS
        Process to wait for Appliance Web Services to start.

        .DESCRIPTION
        Internal module helper function to wait for the appliance services to start.  This helper function will be called by Send-HPICRequest
        when the [System.Net.WebRequest] GetResponse() client generates an [Net.WebException] exception.  Then, this function will be called
        to provide the caller with an indication that the appliance is starting its services.  This will display two prompts:

            1. An initial text-based progress bar while the System.Net.WebRequest is able to access Apache on the appliance to begin polling
               for service startup status.
            2. Write-Progress indicator displaying the overall service startup.

        If any service fails to startup, this function will cause a terminating error, informing the caller to go visit the appliance kiosk
        console to get more information about the startup error.

        When the appliance successfully starts, this function will return back to Send-HPICRequest, and will call Send-HPICRequest with the
        original request, which should only be from Connect-HPICMgmt.

        .Input
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUT
        None.

        .Links
        Connect-HPICMgmt

        .LINKS
        Send-HPICRequest

    #>


    Begin { $flag = $false <# Used to control displaying either output messages #> }

    Process {

        do {

            $req = [System.Net.WebRequest]::Create("https://" + $script:HPICAppliance + "/startstop/rest/component?fields=status")
            $req.Method = "GET"
            $req.ContentType = "application/json"
            $req.Accept = "application/json"
            $req.Headers.Item("accept-language") = "en"
            $req.Headers.Item("accept-encoding") = "gzip, deflate"

            #just to be sure this is cleared, if an exception is thrown
            $script:lastWebResponse = $null
            try {

                #Get response from appliance
                $script:lastWebResponse = $req.GetResponse()
                #write-verbose "$([int]$script:lastWebResponse.StatusCode)"

                #This will trigger when the GetResponse() does not generate an HTTP Error Code and get trapped by the Catch clause below
                If ($flag) {

                    write-host "]"
                }

                #Decompress the response if encoded
                switch ($script:lastWebResponse.Headers.Item("Content-Encoding")) {

                    "gzip"    { $decompress = New-Object System.IO.Compression.GZipStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                    "deflate" { $decompress = New-Object System.IO.Compression.DeflateStream ($script:lastWebResponse.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
                    default   { $decompress = $script:lastWebResponse.GetResponseStream() }

                }

                #Read the response
                $reader = New-Object System.IO.StreamReader($decompress)
                $responseJson = $reader.ReadToEnd()
                $decompress.Close();
                $reader.Close();

                $resp = ConvertFrom-json $responseJson

                #Will keep track of the number of services in RUNNING
                $serviceCount = ($resp.members.status | Where-Object {$_ -eq "RUNNING"} | measure).Count

                #Check to see if any of the services entered a FAILED state.
                if ($resp.members.status | Where-Object { $_ -eq "FAILED" }) {

                    #If so, terminate.
                    write-error "One or more services failed to start. Please visit the console to get a support dump and contact your support representative." -Category OperationStopped -CategoryTargetName "Wait-HPICApplianceStart"
                    Break
                }

                if ($serviceCount -lt $resp.total) {
                    Write-Progress -activity "Appliance starting" -percentComplete (($serviceCount / $resp.total) * 100)

                    #Sleep for 2 seconds, so we do not generate a ton of HTTP calls to the appliance.
                    start-sleep -s 2

                }
            }

            #Catch if we haven't received HTTP 200, as we should display a nice message stating services are still beginning to start
            catch [Net.WebException] {

                write-verbose "$([int]$script:lastWebResponse.StatusCode)"

                #Only want to display this message once.
                if (! $flag) {
                    Write-host "Waiting for services to begin starting [" -nonewline
                }

                if (! [int]$script:lastWebResponse.StatusCode -eq 200) {

                    Write-host "*" -nonewline -ForegroundColor Green
                    $flag = $true
                    start-sleep -s 5
                }
            }

        } until (($serviceCount -eq $resp.total) -and ([int]$script:lastWebResponse.StatusCode -eq 200))

        Write-Verbose "Web Services have started successfully"

    }
}

function Connect-HPICMgmt {

    <#
        .SYNOPSIS
        Initiate a connection to an HP Insight Control server provisioning appliance.

        .DESCRIPTION
        Establish a connection with the specified HP Insight Control server provisioning appliance.  Logs the user into the appliance and establishes a session for use with subsequent requests.  Prompts will be displayed for any omitted values.

                Appliance hostname or IP can include an alternate TCP port number.  While the appliance does not allow the default TCP port 443 to be changed, the appliance could reside behind a firewall, which is redirecting an alternate TCP port number.

        .PARAMETER appliance
        The hostname or IP address of the appliance.

                .PARAMETER User
                Alias [-u]
                User name to authenticate.

                .PARAMETER Password
                Alias [-p]
                Password to log into the appliance.

        .PARAMETER authProvider
        The Directory Name for LDAP/Active Directory authentication, or LOCAL for appliance internal user accounts.  Default is LOCAL.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        None.

            On successful auth, command prompt will display [username]@[appliance].

        System.Management.Automation.PSCustomObject

            On error, appliance response is returned.

        .LINK
        Disconnect-HPICMgmt

        .EXAMPLE
        PS C:\> Connect-HPICMgmt -appliance myappliance.acme.com
        Connect to a specific appliance FQDN.  The user will be prompted for authentication provider, user name and password.

        .EXAMPLE
        PS C:\> Connect-HPICMgmt -appliance myappliance.acme.com:11223
        Connect to a specific appliance, where the target TCP port isn't the default.  The user will be prompted for authentication provider, user name and password.

    #>

    [CmdletBinding()]
    Param(
         [parameter(Mandatory=$true,
         HelpMessage="Enter the appliance DNS name or IP",Position=0)]
         [ValidateNotNullOrEmpty()]
         [string] $appliance,

         [parameter(Mandatory=$false,
         HelpMessage="Enter the authentication domain",Position=3)]
         [ValidateNotNullOrEmpty()]
         [string] $authProvider="LOCAL",

         [parameter(Mandatory=$true,
         HelpMessage="Enter the user name",Position=1)]
         [ValidateNotNullOrEmpty()]
         [alias("u")]
         [string] $User,

         [parameter(Mandatory=$false,
         HelpMessage="Enter the password:",Position=2)]
         [alias("p")]
         [ValidateNotNullOrEmpty()]
         [String]$password
    )

    Begin {

        $script:HPICAppliance = $Appliance

        #Check for the Max X-API Version the appliance supports
        $script:MaxXAPIVersion = (Send-HPICRequest $script:applXApiVersion).currentVersion

        #Lock X-API-Version to no greater than version 102 as bindings were developed for use with API version 102
        if ($script:MaxXAPIVersion -gt 102) { $script:MaxXAPIVersion = 102 }

    }

    Process {
        if (!$password){
            [SecureString]$password=read-host -AsSecureString "Password"
            $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        }
        else {
            $decryptPassword = $password
        }
        $authinfo = @{userName=$user; password=$decryptPassword; authLoginDomain=$authProvider}

        try {

            write-verbose "[CONNECT-HPICMGMT] Sending auth request"

            $resp = Send-HPICRequest $script:loginSessionsUri POST $authinfo
            $global:er = $resp
            Write-Verbose "[CONNECT-HPICMGMT] RESP: $($resp)"
            #If a sessionID is returned, then the user has authenticated
            if ($resp.sessionID) {



                write-verbose "[CONNECT-HPICMGMT] Session token received: $($resp.sessionID)"

                #Change the prompt to display the hostname value, which will replace the string "Not Connected"
                $Script:PromptApplianceHostname = $Appliance
                write-verbose "[CONNECT-HPICMGMT] Setting PromptApplianceHostname to: $($Appliance)"

                #Store the entire auth request for later deletion when issuing Disconnect-HPICmgmt
                $global:cimgmtICspSessionId = $resp

                #Add the Appliance Name to the cimgmtICspSessionId PsCustomObject
                $global:cimgmtICspSessionId | add-member -MemberType NoteProperty -name Appliance -value $script:HPICAppliance

                #Used for the custom display prompt
                            $script:userName = $User

                #used for the Show-HPICAppliance CMDLET
                $script:applianceConnectedTo = [pscustomobject]@{User = $User; Domain = $authProvider; Appliance = $Appliance}

                $newconnection = New-Object PsObject

                $global:cimgmtICspSessionId.psobject.properties | % {
                    $newconnection | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value
                }

                $newconnection | Add-Member -MemberType NoteProperty -Name User -Value $User
                $newconnection | Add-Member -MemberType NoteProperty -Name authProvider -Value $authProvider

                return $newconnection

            }

            else {

            return $resp

            }
        }

        catch [Net.WebException] {
            Write-Verbose "[CONNECT-HPICMGMT] Response: $($resp)"
            write-Error "The appliance at $Appliance is not responding on the network." -Category ConnectionError -CategoryTargetName "Connect-HPICMgmt"
            $global:cimgmtICspSessionId = $Null
            $script:userName = $Null
            $script:HPICAppliance = $Null
            $Script:PromptApplianceHostname = "[Not Connected]"
        }
    }
}

function Set-HPICConnection {
    <#
        .SYNOPSIS
        Changes the global connection to one saved in a variable

        .DESCRIPTION
        If a user plans to make multiple connections and keep the sessions running, it is recommended that all connections returned from Connect-HPICMgmt be saved as variables.
        Call this cmdlet with those saved connections to set the current global appliance connection.

        .PARAMETER appliance
        An appliance connection object

        .Input
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUT
        None.
    #>

    [CmdletBinding()]
    Param(

         [parameter(Mandatory=$true,
         HelpMessage="Enter the appliance connection variable",Position=0)]
         [ValidateNotNullOrEmpty()]
         [ValidateScript({$_.Appliance})]
         [ValidateScript({$_.sessionID})]
         [object] $appliance
    )


    Process {

        $script:HPICAppliance = $appliance.Appliance

        #Change the prompt to display the hostname value, which will replace the string "Not Connected"
        $Script:PromptApplianceHostname = $appliance.Appliance
        write-verbose "[Set-HPICConnection] Setting PromptApplianceHostname to: $($appliance.Appliance)"

        #Store the auth as a global
        $global:cimgmtICspSessionId = $appliance

        #Add the Appliance Name to the cimgmtICspSessionId PsCustomObject
        $global:cimgmtICspSessionId.Appliance = $appliance.Appliance

        #Used for the custom display prompt
                $script:userName = $appliance.User

        #used for the Show-HPICAppliance CMDLET
        $script:applianceConnectedTo = [pscustomobject]@{User = $appliance.User; Domain = $appliance.authProvider; Appliance = $appliance.Appliance}

        $script:SSLCheckFlag = $False

    }
}

function Show-HPICAppliance {


    <#
        .SYNOPSIS
        Display the HP Insight Control server provisioning connected to.

        .DESCRIPTION
        Shows the active session's User, Domain, and Appliance.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Object
            With a valid session ID, the Connected To appliance information is displayed.

        .LINK
        Connect-HPICMgmt


        .EXAMPLE
        PS C:\> Show-HPICAppliance

        User      : administrator
        Appliance : example.admin.com

        Display what appliance the library is connected to.

    #>

    [CmdletBinding()]
    Param()

    Begin {

        verify-auth "Show-HPICAppliance"

    }

    Process {


        if ($script:applianceConnectedTo) {

            #Change the color to Green to show good status
            $originalFGColor = [System.Console]::ForegroundColor
            [System.Console]::ForegroundColor = [System.ConsoleColor]::Green
            $script:applianceConnectedTo | format-list

            #Restore the console ForegroundColor
            [System.Console]::ForegroundColor = [System.ConsoleColor]::$originalFGColor

        }

        else {

            Write-Host -Foregroundcolor Red "Not connected"

        }

    }

}

function Disconnect-HPICMgmt {
    <#
        .SYNOPSIS
        Disconnect from the appliance.

        .DESCRIPTION
        Close the connection with the current appliance

        .INPUTS
        None. You cannot pipe objects to this cmdlet.

        .OUTPUTS
        None.

        .LINK
        Connect-HPICMgmt

        .EXAMPLE
        PS C:\>  Disconnect-HPICMgmt

    #>

    [CmdletBinding()]
    Param()

    Begin {
        If (!$global:cimgmtICspSessionId) {
            Write-Warning "Not connected"
            Break
        }
    }

    Process {

        Write-Verbose "[DISCONNECT-HPICMGMT] Sending Delete Session ID request"
        Send-HPICRequest $loginSessionsUri DELETE $global:cimgmtICspSessionId

        if ([int]$script:lastWebResponse.StatusCode -eq 204) {

            Write-Verbose "[DISCONNECT-HPICMGMT] Successfully logged off"
            $script:SSLCheckFlag = $False
            $script:HPICAppliance = $null
            $Script:PromptApplianceHostname = "Not Connected"
            $Appliance = $null
            $global:cimgmtICspSessionId = $null
        }
        else {
            Write-Verbose "[DISCONNECT-HPICMGMT] Logoff request failed. Response code: $([int]$script:lastWebResponse.StatusCode)"
            Write-Error "Unable to logoff.  Please verify connectivity to appliance and retry command." -Category InvalidResult -CategoryTargetName "Disconnect-HPICMgmt"
            Break

        }
    }
}

function New-HPICResource {
    <#
        .SYNOPSIS
        Create a new resource.

        .DESCRIPTION
        Create a new resource by passing the URI and the resource details in the form of a PowerShell hashtable.

        .PARAMETER uri
        The location where the new object is to be created, using the HTTP POST method.

        .PARAMETER resource
        The new resource that is to be created

        .INPUTS
        None. You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Management.Automation.PSCustomObject
            The newly created resource, or async task.

        .LINK
        Send-HPICRequest

        .LINK
        Set-HPICResource

        .LINK
        Remove-HPICResource

    #>

    [CmdletBinding()]
    Param
        (
         [parameter(Mandatory=$true,
         HelpMessage="Enter the URI string of the resource type to be created")]
         [ValidateNotNullOrEmpty()]
         [string] $uri,

         [parameter(Mandatory=$true,
         HelpMessage="Enter the resource object definition")]
         [ValidateNotNullOrEmpty()]
         [object] $resource

    )

    Begin {

        verify-auth "New-HPICResource"

    }

    Process {

        Send-HPICRequest $uri POST $resource

    }
}

function Set-HPICResource {
    <#
        .SYNOPSIS
        Update an existing resource.

        .DESCRIPTION
        Update an existing resource, using PUT
        The resource should first be read with a "Get-HPICxxx" request
        The PowerShell resource may then be modified followed by this "Set-HPICResource" call.

        .PARAMETER resource
        The modified resource that is to be updated

        .INPUTS
        System.Management.Automation.PSCustomObject
            Resource Object to modify by either using Send-HPICRequest with the resource URI, or the resource GET CMDLET.

        .OUTPUTS
        System.Management.Automation.PSCustomObject
            The modified resource or async task depending on the resource being modified.

        .LINK
        Send-HPICRequest

        .LINK
        New-HPICResource

        .LINK
        Remove-HPICResource

    #>
    [CmdletBinding()]
    Param (
         [parameter(Mandatory=$true, ValueFromPipeline = $true,
         HelpMessage="Enter the resource object that has been modifed")]
         [ValidateNotNullOrEmpty()]
         [ValidateScript({$_.Uri})]
         [object]$resource
    )

    Begin {

        verify-auth "Set-HPICResource"

    }

    Process {

        $uri = $resource.uri

        Send-HPICRequest $uri PUT $resource

    }
}

function Remove-HPICResource {
 <#
        .SYNOPSIS
        Remove a resource from the appliance.

        .DESCRIPTION
        Removes a resource identified by either the resource uri or a resource object.
        Remove-HPICResource can be called with either -nameOrUri or -resource.

        .PARAMETER resource
        A resource object to be deleted. The resource object should first be retrieved
        by a call to a Get-HPICxxx call.

        .PARAMETER nameOruri
        The name or uri of the resource to be deleted.

        .INPUTS
        System.Management.Automation.PSCustomObject
            A valid resource object first retrieved by a call to a Get-HPIC*** cmdlet

        .OUTPUTS
        System.Management.Automation.PSCustomObject
                    Removal async task.

        .LINK
        Send-HPICRequest

        .LINK
        New-HPICResource

        .LINK
        Set-HPICResource

    #>

    [CmdletBinding()]
    Param (
          [parameter(Mandatory = $true, ValueFromPipeline = $true,
          ParameterSetName = "resource",
          HelpMessage = "Enter the PowerShell variable name of the resource object.")]
          [ValidateScript({$_.uri})]
          [Alias("ro")]
          [object] $resource,

          [parameter(Mandatory = $true,
          ParameterSetName = "nameOrUri",
          HelpMessage = "Enter the URI of the resource.")]
          [ValidateNotNullOrEmpty()]
          [Alias("uri")]
          [Alias("name")]
          [string] $nameOruri
        )

    Begin {

        verify-auth "Remove-HPICResource"

    }

    Process {

        $deleteUri = $null
        switch ($PsCmdlet.ParameterSetName) {

            "resource"  { $deleteUri = $resource.uri }

            "nameOrUri"  {

                #nameOrUri value is a URI
                if($nameOrUri.StartsWith("/rest")){

                    $deleteUri = $nameOrUri

                }

                #It's a string value
                else {

                    #Use Index filtering to locate object
                    $resources = Send-HPICRequest ($indexUri + "?filter=name = '$nameOrUri'")

                    $resources = $resources.members #| ? {$_.name -eq $nameOrUri}

                    if($resources){

                        #Error should only be displayed if a Name was provided, and it wasn't globally unique on the appliance
                        if($resources -is [Array]){
                            Write-Error "'$nameOrUri' is not unique.  Located $($resources.count) objects with the same value." -Category LimitsExceeded -CategoryTargetName "Remove-HPICResource"
                            Break
                        }

                        else { $deleteUri = $resources.uri }
                    }

                    else {

                        Write-Error "Resource '$nameOrUri' not found" -Category ObjectNotFound -CategoryTargetName "Remove-HPICResource"
                        Break
                    }
                }
            }
        }

        if ($deleteUri) {
            Send-HPICRequest $deleteUri DELETE
        }
    }
}

#######################################################
# Appliance Configuration
#

function Show-HPICSSLCertificate {

    <#

        .SYNOPSIS
        Display appliance SSL Certificate if untrusted.

        .DESCRIPTION
        This cmdlet displays the HP Insight Control server provisioning SSL Certificate if it is untrusted.  Could also be used to verify certificate, as cert object is stored, which is stored in the [bool]PKI.Web.WebSSL.CertificateIsValid property.

        .PARAMETER Appliance
        Used to specify the appliance to connect to, if an existing connection isn't established from the Connect-HPICMgmt cmdlet.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        PKI.HPInsightControl.Certificate
            If Certificate is untrusted, the cert object will be displayed to the user.

        .EXAMPLE
        PS C:\> Show-HPICSslCertificate
        Show the appliance SSL Certificate status if untrusted.

        .LINK
        Import-HPICSslCertificate

    #>

    [CmdletBinding()]
    param(

        [parameter(Mandatory=$false)]
        [String]$Appliance = $script:HPICAppliance

    )

    Begin {

        if (! $Appliance ) {

            Write-Error "You are not connected to an appliance.  Please specify the -appliance parameter and provide the appliance FQDN, Hostname or IP Address." -Category InvalidArgument

            Break

        }

    }

    Process {

        $ConnectString = "https://$Appliance"

        $WebRequest = [Net.WebRequest]::Create($ConnectString)

        #Attempt connection to appliance.
        try { $Response = $WebRequest.GetResponse() }

        catch { write-verbose $error[-1]; write-verbose "[SHOW-HPICSSLCertificate] Error caught, likely untrusted certificate."}

        #Close the response connection, as it is no longer needed, and will cause problems if left open.
        if ($response) { write-verbose "Closing response connection"; $Response.Close() }

        if ($WebRequest.ServicePoint.Certificate -ne $null) {

            $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle

            try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
            catch {$SAN = $null}
            $chain = New-Object Security.Cryptography.X509Certificates.X509Chain

            [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
            $Status = $chain.Build($Cert)

            #$chain

            #$certObject = New-Object PKI.Web.WebSSL -Property @{
            $certObject = [PKI.HPInsightControl.SslCertificate] @{
                OriginalUri = $ConnectString;
                ReturnedUri = $Response.ResponseUri;
                Certificate = $WebRequest.ServicePoint.Certificate;
                Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
                Subject = $WebRequest.ServicePoint.Certificate.Subject;
                SubjectAlternativeNames = $SAN;
                CertificateIsValid = $Status;
                Response = $Response;
                ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
            }

            #If the certificate is NOT valid, display it and warn user
            if ((! $certObject.CertificateIsValid) -and ($certObject.ErrorInformation -eq "UntrustedRoot")) {

                write-verbose "[SHOW-HPICSSLCertificate] Cert is NOT trusted"

                #Display the certificate output in Yellow
                $originalFGColor = [System.Console]::ForegroundColor
                [System.Console]::ForegroundColor = [System.ConsoleColor]::Yellow

                #Display certificate details
                $certObject

                #Restore the console ForegroundColor
                [System.Console]::ForegroundColor = [System.ConsoleColor]::$originalFGColor

                Write-Warning "The appliance SSL Certificate is UNTRUSTED.  Use the Import-HPICSSLCertificate to import the appliance Self-Signed certificate to your user accounts local Trusted Root Certification Authorities store to not display this warning when you first connect to your appliance."

                #Value will be False, in String format, not Bool
                $global:icspCertTrusted = $certObject.CertificateIsValid

            }

            elseif ($certObject.CertificateIsValid) {

                write-verbose "[SHOW-HPICSSLCertificate] Cert is trusted"

                if ($VerbosePreference -eq "Continue") {

                    #Display the certificate output in Green
                    $originalFGColor = [System.Console]::ForegroundColor
                    [System.Console]::ForegroundColor = [System.ConsoleColor]::Green

                    #Display certificate details
                    $certObject

                    #Restore the console ForegroundColor
                    [System.Console]::ForegroundColor = [System.ConsoleColor]::$originalFGColor

                }

                $global:icspCertTrusted = $certObject.CertificateIsValid
            }

            else {
                Write-Error $Error[0]
            }


            $chain.Reset()

        }

        else {

            Write-Error $Error[0]

        }

        $certObject = $Null
        $WebRequest = $Null
    }

}

function Import-HPICSslCertificate {

    <#

        .SYNOPSIS
        Import an appliance SSL Certificate.

        .DESCRIPTION
        By default, the HP Insight Control server provisioning appliance creates a self-signed SSL Certificate for its WebUI.  There might be a desire to trust the certificate, in case the SHA-1 hash becomes invalid (either due to a certificate change or man-in-the-middle attack) and the caller would like to be notified.  This cmdlet will assist in retrieving and storing the appliance self-generated SSL Certificate into the current users Trusted Root Certification Authorities store.

        Please note that the Subject Alternate Name (SAN) must match that of the Appliance hostname you use to connect to your appliance.  If it does not, an SSL conenction failure will ocurr.  When creating a CSR on the appliance, make sure to include the additional FQDN and IP address(es) in the Alternative Name field.

        .PARAMETER Appliance
        Used to specify the applinace to connect to, if an existing connection isn't established from the Connect-HPICMgmt cmdlet.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        None.

        .EXAMPLE
        PS C:\> Import-HPICSslCertificate -appliance test.example.com
        Import the SSL certificate from the specific appliance.

        .EXAMPLE
        PS C:\> Connect-HPICMgmt test.example.com Administrator MyP@ssword
        PS C:\> Import-HPICSslCertificate
        Import the SSL Certificate from the existing connection provided by the Connect-HPICMgmt cmdlet.

        .LINK
        Show-HPICSslCertificate

    #>

        [CmdletBinding()]
    param(
        [parameter(Mandatory=$false)]
        [String]$Appliance = $script:HPICAppliance
    )

        begin {

        if (! $Appliance) {

            Write-Error "You are not connected to an appliance.  Please specify the -appliance parameter and provide the appliance FQDN, Hostname or IP Address." -Category InvalidArgument

            Break

        }

    }

        process {

        $ConnectString = "https://$Appliance"

        $WebRequest = [Net.WebRequest]::Create($ConnectString)

        try {$Response = $WebRequest.GetResponse()}
        catch [Net.WebException] {

            if ( !($WebRequest.Connection) -and ([int]$Response.StatusCode -eq 0)) {

                Write-Error $_.Exception.Message -Category ObjectNotFound

            }

        }

        #Close the response connection, as it is no longer needed, and will cause problems if left open.
        if ($response) { write-verbose "Closing response connection"; $Response.Close() }

        if ($WebRequest.ServicePoint.Certificate -ne $null) {

            #Get certificate
            $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate #.Handle

            $StoreScope = "CurrentUser"
            $StoreName = "Root"

            #Save to users Trusted Root Authentication Hosts store
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try {

                $store.Add($cert)
                $store.Close()

                #Reset [System.Net.ServicePointManager]::CertificatePolicy after cert has been successfully imported.
                if (($script:SSLCheckFlag) -and ([System.Net.ServicePointManager]::CertificatePolicy)) {

                    [System.Net.ServicePointManager]::CertificatePolicy = $Null
                    $script:SSLCheckFlag = $False

                }
            }

            catch {

                Write-Error $_.Exception.Message -Category InvalidResult
                $store.Close()

            }
        }

    }

        end     { Write-Warning "Please note that the Subject Alternate Name (SAN) must match that of the Appliance hostname you use to connect to your appliance.  If it does not, an SSL conenction failure will ocurr.  When creating a CSR on the appliance, make sure to include the additional FQDN and IP address(es) in the Alternative Name field." }
}

function Upload-File {
    <#
        .SYNOPSIS
        Upload a file to the appliance.

        .DESCRIPTION
        This cmdlet will upload a file to the appliance that can accepts file uploads (WinPE, Content)

        .PARAMETER URI
        Location where to upload file to.

        .PARAMETER File
        Full path to the file to be uploaded.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        Write-Progress
            The progress of uploading the file to the appliance.

    #>
        [CmdletBinding()]
        Param (
        [parameter(Mandatory=$true,
        HelpMessage="Specify the upload URI.",
        Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('u')]
        [string]$uri,

                [parameter(Mandatory=$true,
        HelpMessage="Enter the path and file name to upload.",
        Position=1)]
        [Alias('f')]
        [ValidateScript({Test-Path $_})]
                [string]$File
        )

    Begin {

        write-verbose "[UPLOAD-FILE] Validating user is authenticated"
        verify-auth "Upload-File"
    }

    Process {
        $authinfo = $global:cimgmtICspSessionId.sessionID

        $fsmode = [System.IO.FileMode]::Open
        $fsread = [System.IO.FileAccess]::Read

        $fileObj = Get-Item -path $File

        [string]$filename = $fileObj.name

        Write-Verbose "[UPLOAD-FILE] Uploading $($filename) file to appliance, this may take a few minutes..."
        try {

            $uri = "https://" + $script:HPICAppliance + $Uri
            [System.Net.httpWebRequest]$uploadRequest = [net.webRequest]::create($uri)
            $uploadRequest.Timeout = 1000000
            $uploadRequest.method = "POST"
            $uploadRequest.accept = "application/json,text/javascript,*/*"
            $uploadRequest.Headers.Item("accept-charset") = "ISO-8859-1,utf-8"
            $uploadRequest.Headers.Item("accept-encoding") = "gzip,deflate,sdch"
            $uploadRequest.Headers.Item("accept-language") = "en_US"

            $boundary = "----------------------------bac8d687982e"
            $uploadRequest.ContentType = "multipart/form-data; boundary=----------------------------bac8d687982e"
            $uploadRequest.Headers.Item("auth") = $authinfo
            $uploadRequest.Headers.Item("uploadfilename") = $filename
            $uploadRequest.AllowWriteStreamBuffering = $false
            $uploadRequest.SendChunked = $true

            $fs = New-Object IO.FileStream ($fileObj,$fsmode, $fsread)
            $uploadRequest.ContentLength = $fs.length

            Write-Verbose "[UPLOAD-FILE] Request: POST $($uri )"

            $i=0
            foreach ($h in $uploadRequest.Headers) { Write-Verbose "[UPLOAD-FILE] Request Header $($h) : $($uploadRequest.Headers[$i])"; $i++}

            $rs = $uploadRequest.getRequestStream()
            $disposition = 'Content-Disposition: form-data; name="file"; filename="' + $fileObj.Name + '"'
            $conType = "Content-Type: application/octet-stream"

            [byte[]]$readbuffer = New-Object byte[] 1048576

            [byte[]]$BoundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("--" + $boundary + "`r`n");
            $rs.write($BoundaryBytes,0,$BoundaryBytes.Length);

            [byte[]]$contentDisp = [System.Text.Encoding]::UTF8.GetBytes($disposition + "`r`n");
            $rs.write($contentDisp,0,$contentDisp.Length);

            [byte[]]$contentType = [System.Text.Encoding]::UTF8.GetBytes($conType + "`r`n`r`n");
            $rs.write($contentType,0,$contentType.Length);

            #This is used to keep track of the file upload progress.
            $numBytesToRead = $fs.Length
            $numBytesRead = 0

            do {
                        $byteCount = $fs.Read($readbuffer,0,1048576)
                        $rs.write($readbuffer,0,$byteCount)

                        #Keep track of where we are at clear during the read operation
                        $numBytesRead += $bytecount

                        #Use the Write-Progress cmd-let to show the progress of uploading the file.
                [int]$percent = (($numBytesRead / $fs.Length) * 100)
                if ($percent -gt 100) { $percent = 100 }
                $status = "(" + $numBytesRead + " of " + $numBytesToRead + ") Completed " + $percent + "%"
                Write-Progress -activity "Upload File" -CurrentOperation "Uploading $Filename " -status $status -percentComplete $percent

            } while ($bytecount -gt 0)

            $fs.close()

            [byte[]]$endBoundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("`n`r`n--" + $boundary + "--`r`n");
            $rs.write($endBoundaryBytes,0,$endBoundaryBytes.Length);
            $rs.close()
        }

        catch [System.Exception] {

            Write-Error $_.Exception.Message -Category ConnectionError

            $uploadRequest = $Null
            $rs.close()
            $fs.close()

            break
            #Write-Host $error[0].Exception -ForegroundColor Red
            #Write-Host $_.Exception.InnerException -ForegroundColor Red
        }

        try {
            [net.httpWebResponse]$script:lastWebResponse = $uploadRequest.getResponse()
            write-Verbose "[UPLOAD-FILE] Response Status: ($([int]$script:lastWebResponse.StatusCode)) $($script:lastWebResponse.StatusDescription)"

            if (($([int]$script:lastWebResponse.StatusCode) -eq 202 ) -or ($([int]$script:lastWebResponse.StatusCode) -eq 200 )){

                Write-Host 'Upload successful.'

            }

            $uploadRequest = $Null
            $rs.close()
            $fs.close()

        }

        catch [Net.WebException] {


            $rs.close()
            $fs.close()

            Write-Error "Error Uploading"
        }
    }
}

function Download-File {
        <#
        .DESCRIPTION
        Helper function to download content or tool from appliance.

        .PARAMETER uri
        The location where the content or tool will be downloaded from

        .PARAMETER saveLocation
        The full path to where the Support Dump or backup will be saved to.  This path will not be validated in this helper function

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        Downloads the requested file using net.WebRequest

    #>

    [CmdLetBinding()]
    Param (
            [parameter(Mandatory=$true,
            HelpMessage="Specify the URI of the object to download.",
            Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$uri,

            [parameter(Mandatory=$true,
            HelpMessage="Specify the location where to save the file to.",
            Position=1)]
            [Alias("save")]
            [ValidateNotNullOrEmpty()]
            [string]$saveLocation,

            [parameter(Mandatory=$false)]
            [string]$fileName=$null


    )

    Begin {

        write-verbose "[Download-File] Validating user is authenticated"
        verify-auth "Download-File"
    }

    Process{

        $fsCreate = [System.IO.FileAccess]::Create
        $fsWrite = [System.IO.FileAccess]::Write

        if ($uri.StartsWith("https://")) {
            $downloadUri = $uri
        }
        else {
                    $downloadUri = "https://" + $script:HPICAppliance + $uri
        }
        write-Verbose "[Download-File] Download URI: $($downloadUri)"

            [System.Net.httpWebRequest]$fileDownload = [net.webRequest]::create($downloadUri)
            $fileDownload.Timeout = 1000000
            $fileDownload.method = "GET"
            $fileDownload.accept = "application/octet-stream,*/*"
                $fileDownload.Headers.Item("auth") = $global:cimgmtICspSessionId.sessionID
            $fileDownload.Headers.Item("accept-charset") = "ISO-8859-1,utf-8"
            $fileDownload.Headers.Item("accept-encoding") = "gzip,deflate,sdch"
            $fileDownload.Headers.Item("accept-language") = "en_US"

        $i=0
        foreach ($h in $fileDownload.Headers) { Write-Verbose "[Download-File] Request Header $($i): $($h) = $($fileDownload.Headers[$i])"; $i++}

        Write-Verbose "[Download-File] Request: GET $($fileDownload | out-string)"

        #Get response
        Write-Verbose "[Download-File] Getting response"
        [Net.httpWebResponse]$rs = $fileDownload.GetResponse()

        #Display the response status if verbose output is requested
        Write-Verbose "[Download-File] Response Status: $([int]$rs.StatusCode) $($rs.StatusDescription)"
        $i=0
        foreach ($h in $rs.Headers) { Write-Verbose "[Download-File] Response Header $($i): $($h) = $($rs.Headers[$i])"; $i++ }

        #Request is a redirect to download file contained in the response headers
        if (($rs.headers["Content-Disposition"]) -and ($rs.headers["Content-Disposition"].StartsWith("attachment; filename=")) -and (!$fileName)) {

            $fileName = ($rs.headers["Content-Disposition"].Substring(21)) -replace "`"",""

        }

        Write-Verbose "[Download-File] Filename: $($fileName)"
            Write-Verbose "[Download-File] Filesize:  $($rs.ContentLength)"

        #Decompress the response if encoded
            #Read from response and write to file
        switch ($rs.Headers.Item("Content-Encoding")) {

            "gzip"    { $stream = New-Object System.IO.Compression.GZipStream ($rs.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
            "deflate" { $stream = New-Object System.IO.Compression.DeflateStream ($rs.GetResponseStream()),([IO.Compression.CompressionMode]::Decompress) }
            default   { $stream = $rs.GetResponseStream() }

        }


            #Define buffer and buffer size
                [int] $bufferSize = (4096*1024)
            [byte[]]$buffer = New-Object byte[] (4096*1024)
            [int] $bytesRead = 0


        Write-Verbose "[Download-File] Saving to $($saveLocation)\$($fileName)"
        $fs = New-Object IO.FileStream ($saveLocation + "\" + $fileName),'Create','Write','Read'
            #$fs = New-Object IO.FileStream (($saveLocation + "\" + $fileName[-1]), $fsCreate, $fsWrite)
            while (($bytesRead = $stream.Read($buffer, 0, $bufferSize)) -ne 0) {
                #Write from buffer to file
                        $byteCount = $fs.Write($buffer, 0, $bytesRead);

            }

            Write-Verbose "[Download-File] File saved to $($saveLocation)"

            #Clean up our work
            $stream.Close()
            $rs.Close()
            $fs.Close()
    }
 }

function Watch-Job {
        <#
        .DESCRIPTION
        Helper function to monitor the progress of a job.

        .PARAMETER resource
        The object returned from new job or new server cmdlets

        .INPUTS
        System.Management.Automation.PSCustomObject
            Resource Object to pull a job uri from and monitor

        .OUTPUTS
        System.Management.Automation.PSCustomObject
            The output of the completed job if it finishes or an error message if it fails.

    #>
    [CmdletBinding()]
    Param (
         [parameter(Mandatory=$true, ValueFromPipeline = $true,
         HelpMessage="Enter the object containing a job Uri")]
         [ValidateNotNullOrEmpty()]
         [ValidateScript({$_.Uri})]
         [object]$resource
    )
    sleep(5)
    $status = Get-HPICJob $resource.uri

    while($status.running -eq $true){

        for($i=1 ; $i -le 50; $i++){

            Write-Progress -id 1 -Activity ($status.name + ' Executing') -PercentComplete ($i*2);
            sleep(1)
        }

        $status = Get-HPICJob $resource.uri

    }

    if($status.state -eq 'STATUS_FAILURE'){

        $log = $status.jobResult[0].jobResultLogDetails
        Write-Error ($status.name + ' failed to complete. Printing Log:' + $log)
        return

    }
    elseif($status.state -eq 'STATUS_SUCCESS') {

        Write-Host ($status.name + 'succesfully executed')

    }
    elseif($status.state -eq 'STATUS_PENDING') {

        Write-Host ($status.name + 'will execute at ' + $status.created)

    }
    else {

        Write-Error 'Unexpected Job Status'

    }

    return $status

}

#######################################################
# Servers
#

function Get-HPICServer {
   <#
                .SYNOPSIS
                List Server resources.

        .DESCRIPTION
        Obtain a collection of server resources, or a specific server with the specified URI.

        .PARAMETER name
        The URI of the server resource to be returned.  All server resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Server:  System.Management.Automation.PSCustomObject
                Multiple Servers:  System.Array

        .LINK
        Remove-HPICServer

        .EXAMPLE
        PS C:\> $servers = Get-HPICServer
        Return all the servers managed by this appliance.

        .EXAMPLE
        PS C:\> $serverA = Get-HPICServer /rest/os-deployment-servers/40001
        Return the server resource by its URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICSERVER] Verify auth"
        verify-auth "Get-HPICServer"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICSERVER] Received URI: $($name)"
            $svrs = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICSERVER] Retrieving all server objects"
            $svrs = Send-HPICRequest $server
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#               Write-Verbose "[GET-HPICSERVER] Filtering server list to include only $($name)"
#               $svrs = $svrs.members | Where-Object {$_.name -eq $name}
#                           if (!$svrs) {
#                                   Write-Error -Message "Server $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $svrs = $svrs.members
            }
       }
        return $svrs
    }
}

function Set-HPICServer {
    <#
        .SYNOPSIS
        Modify an existing server.

        .DESCRIPTION
        Modify a server

        .PARAMETER server
        The resource object of the server to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Server resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Server Resource Object.

        .LINK
        Get-HPICServer

        .LINK
        Remove-HPICServer

        .EXAMPLE
        PS C:\> $srv1 = Get-HPICServer /rest/os-deployment-servers/40001
        PS C:\> $srv1.name = 'Srv2'
        PS C:\> Set-HPICServer $net

        Set server specified by URI to be renamed as "Srv2".
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the resource object definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [alias("name","uri","serverUri")]
        [object]$resource

    )

    Begin {

        Write-Verbose "[SET-HPICSERVER] Verify auth"
        verify-auth "Set-HPICServer"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Server was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICServer" ;break }

        Set-HPICResource $resource

    }
}

function New-HPICServer {
     <#
        .SYNOPSIS
        Create a new server.

        .DESCRIPTION
        Create a new server.

        .PARAMETER iLOIP
        The iLO IP address of the server to be added.

        .PARAMETER iLOUserName
        The UserName to log in.

        .PARAMETER iLOPassword
        Password to log in.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Server resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created Server Resource Object.

        .LINK
        Get-HPICServer

        .LINK
        Set-HPICServer

        .LINK
        Remove-HPICServer

        .EXAMPLE
        PS C:\> New-HPICServer -iLOIP 192.168.1.1 -iLOUserName user -iLOPassword example

        Adds a server to the appliance with the proper credentials
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $iLOIP,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $iLOUserName,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $iLOPassword
    )

    Begin {

        Write-Verbose "[NEW-HPICSERVER] Verify auth"
        verify-auth "New-HPICServer"
    }


    Process {

        $resource = @{username=$iLOUserName;password=$iLOPassword;ipAddress=$iLOIP;port=’443’}

        New-HPICResource $server $resource

    }
}

function Remove-HPICServer {
    <#
        .SYNOPSIS
        Delete server from appliance.

        .DESCRIPTION
        Delete a server.

        .PARAMETER name
        The server URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICServer

        .EXAMPLE
        PS C:\> Remove-HPICServer /rest/os-deployment-servers/40001

        Remove the server specifed by the URI.
    #>

    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICSERVER] Verify auth"
        verify-auth "Remove-HPICServer"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICSERVER] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#           Write-Verbose "[REMOVE-HPICSERVER] Retrieving all server objects"
#           $srvrs = Send-HPICRequest $server
#           Write-Verbose "[REMOVE-HPICSERVER] Filtering server list to include only $($name)"
#           $srvrs = $srvrs.members | Where-Object {$_.name -eq $name}
#                       if (!$srvrs) {
#                               Write-Error -Message "Server resource $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#            Remove-HPICResource -nameOrUri $srvrs
        }

    }
}

#######################################################
# OS Build Plans
#

function Get-HPICBuildPlan {
   <#
                .SYNOPSIS
                List OS Build Plan resources.

        .DESCRIPTION
        Obtain a collection of OS Build Plan resources, or a specific Build Plan specified by URI.

        .PARAMETER name
        The URI of the Build Plan resource to be returned.  All Build Plan resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Build Plan:  System.Management.Automation.PSCustomObject
                Multiple Build Plans:  System.Array

        .LINK
        Remove-HPICBuildPlan

        .EXAMPLE
        PS C:\> $bps = Get-HPICBuildPlan
        Return all the build plans contained in this appliance.

        .EXAMPLE
        PS C:\> $InstallX = Get-HPICBuildPlan /rest/os-deployment-build-plans/1840001
        Return the build plan resource specified by its URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICBUILDPLAN] Verify auth"
        verify-auth "Get-HPICBuildPlan"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICBUILDPLAN] Received URI: $($name)"
            $bps = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICBUILDPLAN] Retrieving all build plan objects"
            $bps = Send-HPICRequest $buildplan
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICBUILDPLAN] Filtering build plan list to include only $($name)"
#                $bps = $bps.members | Where-Object {$_.name -eq $name}
#                           if (!$bps) {
#                                   Write-Error -Message "Build Plan $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $bps = $bps.members
            }
        }
        return $bps
    }
}

function Set-HPICBuildPlan {
    <#
        .SYNOPSIS
        Modify an existing build plan.

        .DESCRIPTION
        Modify a build plan

        .PARAMETER resource
        The resource object of the build plan to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Build Plan resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Build Plan Resource Object.

        .LINK
        Get-HPICBuildPlan

        .LINK
        New-HPICBuildPlan

        .LINK
        Remove-HPICBuildPlan

        .EXAMPLE
        PS C:\> $bp = Get-HPICBuildPlan /rest/os-deployment-build-plans/1840001
        PS C:\> $bp.name = "Install OS"
        PS C:\> Set-HPICBuildPlan $bp

        Rename a particular build plan as "Install OS".
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the resource object definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICBUILDPLAN] Verify auth"
        verify-auth "Set-HPICBuildPlan"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter build plan was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICBuildPlan" ;break }

        Set-HPICResource $resource


    }
}

function New-HPICBuildPlan {
    <#
        .SYNOPSIS
        Create a new build plan.

        .DESCRIPTION
        Create a new build plan which can be mutable.

        .PARAMETER resource
        The resource object of the build plan to be created.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Build Plan resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created Build Plan Resource Object.

        .LINK
        Get-HPICBuildPlan

        .LINK
        Set-HPICBuildPlan

        .LINK
        Remove-HPICBuildPlan

        .EXAMPLE
        PS C:\> $bp = Get-HPICBuildPlan /rest/os-deployment-build-plans/1840001
        PS C:\> New-HPICBuildPlan $bp

        Create a Mutable Copy of a Build Plan.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,
        HelpMessage="Enter the resource object definition")]
        [ValidateNotNullOrEmpty()]
        [object] $resource
    )

    Begin {

        Write-Verbose "[NEW-HPICBUILDPLAN] Verify auth"
        verify-auth "New-HPICBuildPlan"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter build plan was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "New-HPICBuildPlan" ;break }

        New-HPICResource $buildplan $resource

    }
}

function Remove-HPICBuildPlan {
  <#
        .SYNOPSIS
        Delete build plan from appliance.

        .DESCRIPTION
        Delete a build plan. Only user generated Build Plans can be removed.

        .PARAMETER name
        The build plan URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICBuildPlan

        .EXAMPLE
        PS C:\> Remove-HPICBuildPlan /rest/os-deployment-build-plans/1840001
        Remove the build plan specified by its URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICBUILDPLAN] Verify auth"
        verify-auth "Remove-HPICBuildPlan"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICBUILDPLAN] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#            Write-Verbose "[REMOVE-HPICBUILDPLAN] Retrieving all build plan objects"
#            $bps = Send-HPICRequest $buildplan
#            Write-Verbose "[REMOVE-HPICBUILDPLAN] Filtering build plan list to include only $($name)"
#            $bps = $bps.members | Where-Object {$_.name -eq $name}
#                       if (!$bps) {
#
#                               Write-Error -Message "Build Plan $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#            Remove-HPICResource -nameOrUri $bps
        }

    }
}

#######################################################
# Server Scripts
#

function Get-HPICServerScript {
   <#
                .SYNOPSIS
                List Server Script resources.

        .DESCRIPTION
        Obtain a collection of Server Script resources, or a specific Server Script by URI.

        .PARAMETER name
        The URI of the Server Script resource to be returned.  All Server Script resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Server Script:  System.Management.Automation.PSCustomObject
                Multiple Server Scripts:  System.Array

        .LINK
        Remove-HPICServerScript

        .EXAMPLE
        PS C:\> $scripts = Get-HPICServerScript
        Return all the server scripts contained in this appliance.

        .EXAMPLE
        PS C:\> $cleanDisks = Get-HPICServerScript /rest/os-deployment-server-scripts/770001
        Return the server script resource specified by URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null,

        [parameter(Mandatory=$false)]
        [int]$start=0,

        [parameter(Mandatory=$false)]
        [int]$count=0
        )

    Begin {
        Write-Verbose "[GET-HPICSERVERSCRIPT] Verify auth"
        verify-auth "Get-HPICServerScript"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICSERVERSCRIPT] Received URI: $($name)"
            $srvs = Send-HPICRequest $name -start $start -count $count
        }
        else {
            Write-Verbose "[GET-HPICSERVERSCRIPT] Retrieving all server script objects"
            $srvs = Send-HPICRequest $serverScript -start $start -count $count
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICSERVERSCRIPT] Filtering server script list to include only $($name)"
#                $srvs = $srvs.members | Where-Object {$_.name -eq $name}
#                           if (!$srvs) {
#                                   Write-Error -Message "Server Script $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $srvs = $srvs.members
            }
        }
        return $srvs
    }
}

function Set-HPICServerScript {
    <#
        .SYNOPSIS
        Modify an existing Server Script.

        .DESCRIPTION
        Modify a Server Script.

        .PARAMETER resource
        The resource object of the Server Script to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Server Script resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Server Script Resource Object.

        .LINK
        Get-HPICServerScript

        .LINK
        New-HPICServerScript

        .LINK
        Remove-HPICServerScript

        .EXAMPLE
        PS C:\> $ss = Get-HPICServerScript /rest/os-deployment-server-scripts/790001
        PS C:\> $ss.name = "Install OS"
        PS C:\> Set-HPICServerScript $ss

        Rename a particular script as "Install OS".
    #>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the resource object definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICSERVERSCRIPT] Verify auth"
        verify-auth "Set-HPICServerScript"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Server Script was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICServerScript" ;break }

        Set-HPICResource $resource


    }
}

function New-HPICServerScript {
     <#
        .SYNOPSIS
        Create a new Server Script.

        .DESCRIPTION
        Create a new Server Script which can be mutable.

        .PARAMETER resource
        The resource object of the Server Script to be created.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Server Script resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created Server Script Resource Object.

        .LINK
        Get-HPICServerScript

        .LINK
        Set-HPICServerScript

        .LINK
        Remove-HPICServerScript

        .EXAMPLE
        PS C:\> $ss = Get-HPICServerScript /rest/os-deployment-server-scripts/770001
        PS C:\> New-HPICServerScript $ss

        Create a Mutable Copy of a Server Script.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,
        HelpMessage="Enter the resource object definition")]
        [ValidateNotNullOrEmpty()]
        [object] $resource
    )

    Begin {

        Write-Verbose "[NEW-HPICSERVERSCRIPT] Verify auth"
        verify-auth "New-HPICServerScript"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Server Script was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "New-HPICServerScript" ;break }

        New-HPICResource $serverScript $resource

    }
}

function Remove-HPICServerScript {
  <#
        .SYNOPSIS
        Delete Server Script from appliance.

        .DESCRIPTION
        Delete a Server Script. Only user created scripts can be removed.

        .PARAMETER name
        The Server Script URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICServerScript

        .EXAMPLE
        PS C:\> Remove-HPICServerScript /rest/os-deployment-server-scripts/770001
        Remove the Server Script specifed by URI.

    #>

    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICSERVERSCRIPT] Verify auth"
        verify-auth "Remove-HPICServerScript"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICSERVERSCRIPT] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#            Write-Verbose "[REMOVE-HPICSERVERSCRIPT] Retrieving all server script objects"
#            $srvscripts = Send-HPICRequest $serverScript
#            Write-Verbose "[REMOVE-HPICSERVERSCRIPT] Filtering server script list to include only $($name)"
#            $srvscripts = $srvscripts.members | Where-Object {$_.name -eq $name}
#                       if (!$srvscripts) {
#                               Write-Error -Message "Server Script $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#           Remove-HPICResource -nameOrUri $srvscripts
        }

    }
}

#######################################################
# OGFS Scripts
#

function Get-HPICOgfsScript {
   <#
                .SYNOPSIS
                List OGFS Script resources.

        .DESCRIPTION
        Obtain a collection of OGFS Script resources, or a specific OGFS Script with the specified URI.

        .PARAMETER name
        The URI of the OGFS Script resource to be returned.  All OGFS Script resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single OGFS Script:  System.Management.Automation.PSCustomObject
                Multiple OGFS Scripts:  System.Array

        .LINK
        Remove-HPICOgfsScript

        .EXAMPLE
        PS C:\> $scripts = Get-HPICOgfsScript
        Return all the OGFS scripts contained in this appliance.

        .EXAMPLE
        PS C:\> $boot = Get-HPICOgfsScript /rest/os-deployment-ogfs-scripts/940001
        Return the OGFS Script resource with the specified URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null,

        [parameter(Mandatory=$false)]
        [int]$start=0,

        [parameter(Mandatory=$false)]
        [int]$count=0
        )

    Begin {
        Write-Verbose "[GET-HPICOGFSCRIPT] Verify auth"
        verify-auth "Get-HPICOgfsScript"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICOGFSSCRIPT] Received URI: $($name)"
            $ogfs = Send-HPICRequest $name -start $start -count $count
        }
        else {
            Write-Verbose "[GET-HPICOGFSSCRIPT] Retrieving all OGFS script objects"
            $ogfs = Send-HPICRequest $ogfsScript -start $start -count $count
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICOGFSSCRIPT] Filtering OGFS scripts list to include only $($name)"
#                $ogfs = $ogfs.members | Where-Object {$_.name -eq $name}
#                           if (!$ogfs) {
#                                   Write-Error -Message "OGFS Script $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $ogfs = $ogfs.members
            }
        }
        return $ogfs
    }
}

function Set-HPICOgfsScript {
    <#
        .SYNOPSIS
        Modify an existing OGFS Script.

        .DESCRIPTION
        Modify an OGFS Script.

        .PARAMETER server
        The resource object of the OGFS Script to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            OGFS Script resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified OGFS Script Resource Object.

        .LINK
        Get-HPICOgfsScript

        .LINK
        New-HPICOgfsScript

        .LINK
        Remove-HPICOgfsScript

        .EXAMPLE
        PS C:\> $ogfs = Get-HPICOgfsScript /rest/os-deployment-ogfs-scripts/940001
        PS C:\> $ogfs.name = "Install OS"
        PS C:\> Set-HPICOgfsScript $ogfs

       Rename a particular script as "Install OS".
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the object resource definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICOGFSSCRIPT] Verify auth"
        verify-auth "Set-HPICOgfsScript"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter OGFS Script was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICOgfsScript" ;break }

        Set-HPICResource $resource


    }
}

function New-HPICOgfsScript {
     <#
        .SYNOPSIS
        Create a new OGFS Script.

        .DESCRIPTION
        Create a new OGFS Script which can be mutable.

        .PARAMETER resource
        The resource object of the OGFS Script to be created.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            OGFS Script resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created OGFS Script Resource Object.

        .LINK
        Get-HPICOgfsScript

        .LINK
        Set-HPICOgfsScript

        .LINK
        Remove-HPICOgfsScript

        .EXAMPLE
        PS C:\> $ogfs = Get-HPICOgfsScript /rest/os-deployment-ogfs-scripts/940001
        PS C:\> New-HPICOgfsScript $ogfs

        Create a Mutable Copy of an OGFS Script.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,
        HelpMessage="Enter the resource object definition")]
        [ValidateNotNullOrEmpty()]
        [object] $resource
    )

    Begin {

        Write-Verbose "[NEW-HPICOGFSSCRIPT] Verify auth"
        verify-auth "New-HPICOgfsScript"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter OGFS Script was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "New-HPICOgfsScript" ;break }

        New-HPICResource $ogfsScript $resource

    }
}

function Remove-HPICOgfsScript {
  <#
        .SYNOPSIS
        Delete OGFS Script from appliance.

        .DESCRIPTION
        Delete an OGFS Script. Only user created scripts can be removed.

        .PARAMETER name
        The OGFS Script URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICOgfsScript

        .EXAMPLE
        PS C:\> Remove-HPICOgfsScript /rest/os-deployment-ogfs-scripts/940001
        Remove the OGFS Script specifed by URI

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICOGFSSCRIPT] Verify auth"
        verify-auth "Remove-HPICOgfsScript"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICOGFSSCRIPT] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#            Write-Verbose "[REMOVE-HPICOGFSSCRIPT] Retrieving all OGFS script objects"
#            $ogfs = Send-HPICRequest $ogfsScript
#            Write-Verbose "[REMOVE-HPICOGFSSCRIPT] Filtering OGFS scripts list to include only $($name)"
#            $ogfs = $ogfs.members | Where-Object {$_.name -eq $name}
#                       if (!$ogfs) {
#                               Write-Error -Message "OGFS script $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#            Remove-HPICResource -nameOrUri $ogfs
        }

    }
}

#######################################################
# Configuration Files
#

function Get-HPICCfg {
   <#
                .SYNOPSIS
                List Configuration File resources.

        .DESCRIPTION
        Obtain a collection of Configuration File resources, or a specific Configuration File with the specified URI.

        .PARAMETER name
        The URI of the Configuration File resource to be returned.  All Configuration File resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Configuration File:  System.Management.Automation.PSCustomObject
                Multiple Configuration Files:  System.Array

        .LINK
        Remove-HPICCfg

        .EXAMPLE
        PS C:\> $cfg = Get-HPICCfg
        Return all the Configuration Files contained in this appliance.

        .EXAMPLE
        PS C:\> $cfg = Get-HPICCfg /rest/os-deployment-install-cfgfiles/2130001
        Return the Configuration File resource by URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICCFG] Verify auth"
        verify-auth "Get-HPICCfg"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICCFG] Received URI: $($name)"
            $cfgfile = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICCFG] Retrieving all Configuration File objects"
            $cfgfile = Send-HPICRequest $cfg
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICCFG] Filtering Configuration File list to include only $($name)"
#                $cfgfile = $cfgfile.members | Where-Object {$_.name -eq $name}
#                           if (!$cfgfile) {
#                                   Write-Error -Message "Configuration File resource $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $cfgfile = $cfgfile.members
            }
        }
        return $cfgfile
    }
}

function Set-HPICCfg {
    <#
        .SYNOPSIS
        Modify an existing Configuration File.

        .DESCRIPTION
        Modify a Configuration File.

        .PARAMETER server
        The resource object of the Configuration File to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Configuration File resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Configuration File Resource Object.

        .LINK
        Get-HPICCfg

        .LINK
        New-HPICCfg

        .LINK
        Remove-HPICCfg

        .EXAMPLE
        PS C:\> $cfg = Get-HPICCfg /rest/os-deployment-install-cfgfiles/2130001
        PS C:\> $cfg.name = "SampleName"
        PS C:\> Set-HPICCfg $cfg

        Rename a particular CFG resource.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the object resource definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICCFG] Verify auth"
        verify-auth "Set-HPICCfg"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Configuration File resource was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICCfg" ;break }

        Set-HPICResource $resource


    }
}

function New-HPICCfg {
     <#
        .SYNOPSIS
        Create a new Configuration File.

        .DESCRIPTION
        Create a new Configuration File which can be mutable.

        .PARAMETER resource
        The resource object of the Configuration File to be created.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Configuration File resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created Configuration File Resource Object.

        .LINK
        Get-HPICCfg

        .LINK
        Set-HPICCfg

        .LINK
        Remove-HPICCfg

        .EXAMPLE
        PS C:\> $cfg = Get-HPICCfg /rest/os-deployment-install-cfgfiles/2130001
        PS C:\> New-HPICCfg $cfg

        Create a Mutable Copy of a Configuration File.
    #>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,
        HelpMessage="Enter the resource object definition")]
        [ValidateNotNullOrEmpty()]
        [object] $resource
    )

    Begin {

        Write-Verbose "[NEW-HPICCFG] Verify auth"
        verify-auth "New-HPICCfg"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Configuration File resource was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "New-HPICCfg" ;break }

        New-HPICResource $cfg $resource

    }
}

function Remove-HPICCfg {
  <#
        .SYNOPSIS
        Delete Configuration File from appliance.

        .DESCRIPTION
        Delete a Configuration File. Only user created Configuration Files can be removed.

        .PARAMETER name
        The Configuration File URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICCfg

        .EXAMPLE
        PS C:\> Remove-HPICCfg /rest/os-deployment-install-cfgfiles/2130001

        Remove the Configuration File specifed by URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICCFG] Verify auth"
        verify-auth "Remove-HPICCfg"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICCFG] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#            Write-Verbose "[REMOVE-HPICCFG] Retrieving all Configuration File objects"
#            $cfgfile = Send-HPICRequest $cfg
#            Write-Verbose "[REMOVE-HPICCFG] Filtering Configuration File list to include only $($name)"
#            $cfgfile = $cfgfile.members | Where-Object {$_.name -eq $name}
#                       if (!$cfgfile) {
#                               Write-Error -Message "Configuration File resource $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#            Remove-HPICResource -nameOrUri $cfgfile
        }

    }
}


#######################################################
# Device Groups
#

function Get-HPICDeviceGroup {
   <#
                .SYNOPSIS
                List Device Group resources.

        .DESCRIPTION
        Obtain a collection of Device Group resources, or a specific Device Group with the specified URI.

        .PARAMETER name
        The URI of the Device Group resource to be returned.  All Device Group resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Device Group:  System.Management.Automation.PSCustomObject
                Multiple Device Groups:  System.Array

        .LINK
        Remove-HPICDeviceGroup

        .EXAMPLE
        PS C:\> $devg = Get-HPICDeviceGroup
        Return all the Device Groups contained in this appliance.

        .EXAMPLE
        PS C:\> $devg = Get-HPICDeviceGroup /rest/os-deployment-device-groups/5910001
        Return the Device Group resource by URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICDEVICEGROUP] Verify auth"
        verify-auth "Get-HPICDeviceGroup"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICDEVICEGROUP] Received URI: $($name)"
            $dgroup = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICDEVICEGROUP] Retrieving all device groups"
            $dgroup = Send-HPICRequest $deviceGroup
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICDEVICEGROUP] Filtering device group list to include only $($name)"
#                $dgroup = $dgroup.members | Where-Object {$_.name -eq $name}
#                           if (!$dgroup) {
#                                   Write-Error -Message "Device group $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $dgroup = $dgroup.members
            }
        }
        return $dgroup
    }
}

function Set-HPICDeviceGroup {
    <#
        .SYNOPSIS
        Modify an existing Device Group.

        .DESCRIPTION
        Modify a Device Group.

        .PARAMETER server
        The resource object of the Device Group to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Device Group resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Device Group Resource Object.

        .LINK
        Get-HPICDeviceGroup

        .LINK
        New-HPICDeviceGroup

        .LINK
        Remove-HPICDeviceGroup

        .EXAMPLE
        PS C:\> $devg = Get-HPICDeviceGroup /rest/os-deployment-device-groups/5910001
        PS C:\> $devg.name = "NewName"
        PS C:\> Set-HPICDeviceGroup $devg

        Rename a particular device group.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the object resource definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICDEVICEGROUP] Verify auth"
        verify-auth "Set-HPICDeviceGroup"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter device group resource was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICDeviceGroup" ;break }

        Set-HPICResource $resource


    }
}

function New-HPICDeviceGroup {
     <#
        .SYNOPSIS
        Create a new Device Group.

        .DESCRIPTION
        Create a new Device Group.

        .PARAMETER resource
        The resource object of the Device Group to be created.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Device Group resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The created Device Group Resource Object.

        .LINK
        Get-HPICDeviceGroup

        .LINK
        Set-HPICDeviceGroup

        .LINK
        Remove-HPICDeviceGroup

        .EXAMPLE
        PS C:\> $devg = Get-HPICDeviceGroup /rest/os-deployment-device-groups/5910001
        PS C:\> New-HPICDeviceGroup $devg

        Create a copy of a Device Group.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,
        HelpMessage="Enter the resource object definition")]
        [ValidateNotNullOrEmpty()]
        [object] $resource
    )

    Begin {

        Write-Verbose "[NEW-HPICDEVICEGROUP] Verify auth"
        verify-auth "New-HPICDeviceGroup"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter Device Group resource was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "New-HPICDeviceGroup" ;break }

        New-HPICResource $deviceGroup $resource

    }
}

function Remove-HPICDeviceGroup {
  <#
        .SYNOPSIS
        Delete Device Group from appliance.

        .DESCRIPTION
        Delete a Device Group.

        .PARAMETER name
        The Device Group URI to be deleted.

        .INPUTS
        Accepted.
        System.String
        System.Management.Automation.PSCustomObject

        .OUTPUTS
        None

        .LINK
        Get-HPICDeviceGroup

        .EXAMPLE
        PS C:\> Remove-HPICDeviceGroup /rest/os-deployment-device-groups/5910001

        Remove the Device Group specifed by URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$true)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[REMOVE-HPICDEVICEGROUP] Verify auth"
        verify-auth "Remove-HPICDeviceGroup"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[REMOVE-HPICDEVICEGROUP] Received URI: $($name)"
            Remove-HPICResource -nameOrUri $name
        }
        else {
            Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#            Write-Verbose "[REMOVE-HPICDEVICEGROUP] Retrieving all device group objects"
#            $dgroup = Send-HPICRequest $deviceGroup
#            Write-Verbose "[REMOVE-HPICDEVICEGROUP] Filtering device group list to include only $($name)"
#            $dgroup = $dgroup.members | Where-Object {$_.name -eq $name}
#                       if (!$dgroup) {
#                               Write-Error -Message "Device Group resource $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                               break
#                       }
#            Remove-HPICResource -nameOrUri $dgroup
        }

    }
}

#######################################################
# Facility
#

function Get-HPICFacility {
   <#
                .SYNOPSIS
                List Facility resources

        .DESCRIPTION
        Obtain the Facility Resource for the appliance.

        .PARAMETER name
        The URI of the Facility resource to be returned.  All (1) Facility resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Facility:  System.Management.Automation.PSCustomObject

        .EXAMPLE
        PS C:\> $fac = Get-HPICFacility
        Return the Facility contained in this appliance.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICFACILITY] Verify auth"
        verify-auth "Get-HPICFacility"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICFACILITY] Received URI: $($name)"
            $fcl = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICFACILITY] Retrieving all facilities"
            $fcl = Send-HPICRequest $facility
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICFACILITY] Filtering facility list to include only $($name)"
#                $fcl = $fcl.members | Where-Object {$_.name -eq $name}
#                           if (!$fcl) {
#                                   Write-Error -Message "Facility $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $fcl = $fcl.members
            }
        }
        return $fcl
    }
}

function Set-HPICFacility {
    <#
        .SYNOPSIS
        Modify an existing Facility.

        .DESCRIPTION
        Modify a Facility.

        .PARAMETER server
        The resource object of the Facility to be modified.

        .INPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Facility resource object.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            The modified Facility Resource Object.

        .LINK
        Get-HPICFacility

        .EXAMPLE
        PS C:\> $fac = Get-HPICFacility /rest/os-deployment-facility/1
        PS C:\> $fac.name = "NewName"
        PS C:\> Set-HPICFacility $fac

        Set "Appliance" to be renamed as "NewName".
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Enter the object resource definition.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]$resource
    )

    Begin {

        Write-Verbose "[SET-HPICFACILITY] Verify auth"
        verify-auth "Set-HPICFacility"
    }


    Process {

        if (!$resource) { Write-Error "The input parameter facility resource was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Set-HPICFacility" ;break }

        Set-HPICResource $resource


    }
}

#######################################################
# Packages
#

function Get-HPICPackage {
   <#
                .SYNOPSIS
                List Package resources.

        .DESCRIPTION
        Obtain a collection of Package resources, or a specific Package with the specified URI.

        .PARAMETER name
        The URI of the Package resource to be returned.  All Package resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Package:  System.Management.Automation.PSCustomObject
                Multiple Packages:  System.Array

        .EXAMPLE
        PS C:\> $package = Get-HPICPackage
        Return all the Packages contained in this appliance.

        .EXAMPLE
        PS C:\> $package = Get-HPICPackage /rest/os-deployment-install-zips/3040001
        Return the Package resource with specified URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICPACKAGE] Verify auth"
        verify-auth "Get-HPICPackage"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICPACKAGE] Received URI: $($name)"
            $zips = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICPACKAGE] Retrieving all packages"
            $zips = Send-HPICRequest $package
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICPACKAGE] Filtering package list to include only $($name)"
#                $zips = $zips.members | Where-Object {$_.name -eq $name}
#                           if (!$zips) {
#                                   Write-Error -Message "Package $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $zips = $zips.members
            }
        }
        return $zips
    }
}

#######################################################
# Settings
#

function Get-HPICSetting {
   <#
                .SYNOPSIS
                List Settings resources.

        .DESCRIPTION
        Obtain a collection of Settings resources, or a specific Setting with the specified URI.

        .PARAMETER name
        The URI of the Setting resource to be returned.  All Setting resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Setting:  System.Management.Automation.PSCustomObject
                Multiple Settings:  System.Array

        .EXAMPLE
        PS C:\> $set = Get-HPICSetting
        Return all the Setting contained in this appliance.

        .EXAMPLE
        PS C:\> $set = Get-HPICSetting /rest/os-deployment-settings/OsdDhcpConfig
        Return the Setting resource by its URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICSETTING] Verify auth"
        verify-auth "Get-HPICSetting"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICSETTING] Received URI: $($name)"
            $stng = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICSETTING] Retrieving all settings"
            $stng = Send-HPICRequest $settings
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICSETTING] Filtering settings to include only $($name)"
#               $stng = $stng.members | Where-Object {$_.name -eq $name}
#                           if (!$stng) {
#                                   Write-Error -Message "Setting $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $stng = $stng.members
            }
        }
        return $stng
    }

}

function Set-HPICDHCPSetting {
    <#
        .SYNOPSIS
        Updates the DHCP Settings for the appliance.

        .DESCRIPTION
        Updates DHCP Settings for the appliance.

        .PARAMETER body
        The properly formatted body to be converted to JSON.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Array
            Array of all settings resources post-edit.

        .LINK
        Get-HPICSetting

        .EXAMPLE
        PS C:\> $body = {"dhcpState":"DHCP_FULL","subnetList":[{"subnetName":"10.1.0.0","netmask":"255.255.0.0","subnetStart":"10.1.1.100","subnetEnd":"10.1.1.199"}]}
        PS C:\> Set-HPICDHCPSetting $resource
        This example passes in updated values to set for the appliance's DHCP configuration.
    #>

    [CmdletBinding()]
    Param (

        [parameter(Mandatory=$true)]
        [object]$body
    )

    Begin {

        Write-Verbose "[SET-HPICDHCPSETTING] Verify auth"
        verify-auth "Set-HPICDHCPSetting"
    }


    Process {

        Send-HPICRequest $DHCPconfig PUT $body
    }
}

function Import-HPICWinPE {
    <#
        .SYNOPSIS
        Upload a WinPE file to the appliance.

        .DESCRIPTION
        This cmd provides the ability to upload a WinPE zip into the appliance.  It will return after the upload has completed.

        .PARAMETER File
        The full path and file name of the SPP file.  The function returns an error if the file path cannot be validated.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Management.Automation.PSCustomObject
        The progress of uploading the file to the appliance, and completion result.

        .EXAMPLE
        PS C:\> Import-HPICWinPE "C:\Users\me\Documents\winPE.zip"

        Upload WinPE to the appliance
    #>
        [CmdletBinding(DefaultParameterSetName='Update',SupportsShouldProcess=$True,ConfirmImpact='High')]
        Param (
                [parameter(Mandatory=$true)]
        [Alias('f')]
        [ValidateScript({Test-Path $_})]
        [string]$File

        )

    Begin {

        verify-auth "Import-HPICWinPE"

    }

    Process {

    Write-Verbose "[IMPORT-HPICWINPE] - UPLOAD FILE: $($File)"

    $upload = Upload-File $WinPE $File

    }
}

function Import-HPICContent {
    <#
        .SYNOPSIS
        Import content to the appliance.

        .DESCRIPTION
        This cmd provides the ability to import an appliance's exported content.  It will return after the upload has completed.
        Useful when syncing user-defined build plans among appliances.

        .PARAMETER File
        The full path and file name of the content zip.  The function returns an error if the file path cannot be validated.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        System.Management.Automation.PSCustomObject
        The progress of uploading the file to the appliance, and completion result.

        .EXAMPLE
        PS C:\> Import-HPICContent "C:\Users\me\Documents\content_export-2014_07_30-15_42_41.zip"

        Upload zipped content to the appliance
    #>
        [CmdletBinding(DefaultParameterSetName='Update',SupportsShouldProcess=$True,ConfirmImpact='High')]
        Param (
                [parameter(Mandatory=$true)]
        [Alias('f')]
        [ValidateScript({Test-Path $_})]
        [string]$File
        )

    Begin {

        verify-auth "Import-HPICContent"

    }

    Process {

    Write-Verbose "[IMPORT-HPICCONTENT] - UPLOAD FILE: $($File)"

    $upload = Upload-File $importContent $File

    }
}

function Export-HPICContent {
        <#
        .SYNOPSIS
        Download appliance zipped content.

        .DESCRIPTION
        Use this cmdlet to download the appliance zipped content.

        .PARAMETER Location
        The full path to where the zipped content will be saved to.  If omitted, current directory location will be used.

        .PARAMETER fileName
        Optional fileName to overwrite original File Name.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        The generated zipped file.

        .LINK
                Send-HPICRequest

        .LINK
        Download-File

        .EXAMPLE
        PS C:\> Export-HPICContent 'c:\temp'
                Save the Appliance content to C:\Temp
    #>
    [CmdLetBinding(DefaultParameterSetName="default")]
    Param (
        [parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName="default",HelpMessage="Specify the folder location to save the content.")]
        [Alias("save")]
        [string]$Location = (get-location).Path,

        [parameter(Mandatory=$false)]
        [string]$fileName=$null
    )

    Begin {

        write-verbose "[EXPORT-HPICCONTENT] Validating user is authenticated"
        verify-auth "Export-HPICContent"

        #Validate the path exists.  If not, create it.
                if (!(Test-Path $Location)){
            write-verbose "[EXPORT-HPICCONTENT] Directory does not exist.  Creating directory..."
            New-Item $Location -itemtype directory
        }

    }

    Process {

        write-verbose "[EXPORT-HPICCONTENT] Downloading content to $($Location)"
                Download-File $exportContent $Location -fileName $fileName
    }
}

function Get-HPICTool{
        <#
        .SYNOPSIS
        Download an appliance tool.

        .DESCRIPTION
        Use this cmdlet to download either the MediaServerTool or WinPETool

        .PARAMETER Location
        The full path to where the tool executable will be saved to.  If omitted, current directory location will be used.

        .PARAMETER toolName
        The name of the tool to download; either MediaServerTool or WinPETool

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        The generated File

        .LINK
        Download-File

        .EXAMPLE
        PS C:\> Get-HPICTool -toolName 'MediaServerTool' -Location c:\temp

                Save the Media Server Tool to C:\Temp
    #>
    [CmdLetBinding(DefaultParameterSetName="default")]
    Param (
        [parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName="default",HelpMessage="Specify the folder location to save the tool.")]
        [Alias("save")]
        [string]$Location = (get-location).Path,

        [parameter(Mandatory=$true,HelpMessage="Specify the tool to download; WinPETool or MediaServerTool")]
                [string]$toolName,

        [parameter(Mandatory=$false)]
        [string]$fileName=$null
    )

    Begin {

        write-verbose "[GET-HPICTOOL] Validating user is authenticated"
        verify-auth "Get-HPICTool"

        #Validate the path exists.  If not, create it.
                if (!(Test-Path $Location)){
            write-verbose "[Backup-HPICTool] Directory does not exist.  Creating directory..."
            New-Item $Location -itemtype directory
        }
        if (($toolName -ne 'WinPETool') -and ($toolName -ne 'MediaServerTool')){
          Write-Error 'Please specify either WinPETool or MediaServerTool'
          break
        }

    }

    Process {

                #Send the request
                write-verbose "[GET-HPICTOOL] Please wait while the tool is generated.  This can take a few minutes..."

        write-verbose "[GET-HPICTOOL] Downloading backup to $($Location)"
        $address = $tools +$toolName
                Download-File $address $Location -fileName $fileName
    }
}

#######################################################
# Jobs
#

function Get-HPICJob {
   <#
                .SYNOPSIS
                List Job resources.

        .DESCRIPTION
        Obtain a collection of Job resources, or a specific Job with the specified URI.

        .PARAMETER name
        The URI of the Job resource to be returned.  All Job resources will be returned if omitted.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
                Single Job:  System.Management.Automation.PSCustomObject
                Multiple Jobs:  System.Array

        .EXAMPLE
        PS C:\> $allJobs = Get-HPICJob
        Return all the Jobs contained in this appliance.

        .EXAMPLE
        PS C:\> $specificJob = Get-HPICPackage /rest/os-deployment-jobs/1920001
        Return a particular job resource by its URI.

    #>
    [CmdletBinding()]
        Param (
                [parameter(Mandatory=$false)]
                [string]$name=$null
        )

    Begin {
        Write-Verbose "[GET-HPICJOB] Verify auth"
        verify-auth "Get-HPICJob"
    }

    Process {
        if ($name.StartsWith('/rest')) {
            Write-Verbose "[GET-HPICJOB] Received URI: $($name)"
            $jobs = Send-HPICRequest $name
        }
        else {
            Write-Verbose "[GET-HPICJOB] Retrieving all jobs"
            $jobs = Send-HPICRequest $job
            if ($name) {
                Write-Error -Message "Filter by name not available in version 102. Will be implemented in a future release. Please use resource URI." -Category 'NotEnabled' -CategoryReason 'NotEnabled'
#                Write-Verbose "[GET-HPICJOB] Filtering job list to include only $($name)"
#                $jobs = $jobs.members | Where-Object {$_.name -eq $name}
#                           if (!$jobs) {
#                                   Write-Error -Message "Job $name not found. Please check the name again, and verify it exists." -Category 'ObjectNotFound' -CategoryReason 'ObjectNotFound'
#                                   break
#                           }
            } else {
                $jobs = $jobs.members
            }
        }
        return $jobs
    }
}

function New-HPICJob {
<#
        .SYNOPSIS
        Start a job to run one or more build plans and/or run post install network configuration.

        .DESCRIPTION
        Run one or more build plans with or without network configuration on or more servers.

        .PARAMETER body
        A Hashtable containing arrays of server URIs (with or without personalization data) and an array of build plan URIs. If the build plan array is empty, a network personalization job is run.

        .PARAMETER runtime
        Optional future time for build plan execution. ex. 2014-08-26T08:00:00.000Z

        .PARAMETER jobname
        Optional name for job.

        .INPUTS
        System.Collections.Hashtable
            Body to be converted to JSON.

        .OUTPUTS
        System.ObjectSystem.Management.Automation.PSCustomObject
            Object containing URI of job.

        .LINK
        Watch-Job

        .EXAMPLE
        PS C:\> $body = @{osbpUris=@("/rest/os-deployment-build-plans/600001";"/rest/os-deployment-build-plans/620001");serverData=@(@{serverUri="/rest/os-deployment-servers/210001"})}
                New-HPICJob $body | Watch-Job

        Run two Build Plans on a particular server and monitor job by piping output into Watch-Job CMDlet.

        .EXAMPLE
        PS C:\> $networkConfig = @{serverData=@(@{serverUri="/rest/os-deployment-servers/20001";personalityData=@{hostName="hostName";displayName="Example"}})}
                New-HPICJob $networkConfig | Watch-Job

        Run post install network configuration on a particular server and monitor job by piping output into Watch-Job CMDlet.

        .EXAMPLE
        PS C:\> $body = @{osbpUris=@("/rest/os-deployment-build-plans/1230001");serverData=@(@{serverUri="/rest/os-deployment-servers/40001"})}
                New-HPICJob $body | Watch-Job

        Run a Build Plan on a particular server and monitor job by piping output into Watch-Job CMDlet.

        .EXAMPLE
        PS C:\> $body = @{osbpUris=@("/rest/os-deployment-build-plans/1230001");serverData=@(@{serverUri="/rest/os-deployment-servers/40001";personalityData=@{hostName="hostName";displayName="Example"}})}
                New-HPICJob $body | Watch-Job
        Run a Build Plan on a particular server, change the host name and display name and pipe output into Watch-Job CMDlet.

    #>

    [CmdletBinding()]
    Param (

        [parameter(Mandatory=$true,
        HelpMessage="Enter the body in proper format")]
        [ValidateNotNullOrEmpty()]
        [object] $resource,

        [parameter(Mandatory=$false,
        HelpMessage="Enter the runtime in proper format")]
                [string]$runtime=$null,

        [parameter(Mandatory=$false)]
                [string]$jobname=$null
    )

    Begin {

        Write-Verbose "[START-HPICJOB] Verify auth"
        verify-auth "Start-HPICJob"
    }


    Process {



        $uri = $script:job

        if ($runtime) {
            $uri += '?time=' + $runtime
            if($jobname) {
            $uri += '&title=' + $jobname
            }
        }
        elseif($jobname){
            $uri += '?title=' + $jobname
        }

        Write-Verbose $uri

        Send-HPICRequest $uri POST $resource

    }
}

function Stop-HPICJob {
    <#
        .SYNOPSIS
        Stop a running or scheduled job.

        .DESCRIPTION
        Forces a stop on running or scheduled build plans on all servers within a job.

        .PARAMETER jobstop
        The rest uri of the job to be stopped.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .EXAMPLE
        PS C:\> Stop-HPIC /rest/os-deployment-jobs/5440001

        Stops a job identified by its URI.

    #>
    [CmdletBinding()]
    Param (

        [parameter(Mandatory=$true,
        HelpMessage="Enter the URI of the job to stop")]
        [ValidateNotNullOrEmpty()]
        [string] $jobstop
    )

    Begin {

        Write-Verbose "[STOP-HPICJOB] Verify auth"
        verify-auth "Stop-HPICJob"
    }


    Process {

        $jobToParse = Get-HPICJob $jobstop

        if ($jobToParse.name -ne 'Run OS Build Plans') {

            $bpID=$jobToParse.uriOfJobType.split('/')[-1]
            Write-Verbose "[STOP-HPICJOB] $($bpID)"

            #The build plan is running on only one server.
            if ($jobToParse.jobServerInfo.jobServerUri -is [String]){

                $servID=$jobToParse.jobServerInfo.jobServerUri.split('/')[-1]
                Write-Verbose "[STOP-HPICJOB] $($servID)"

                $uri = $jobstop + '/stop?bp=' + $bpID + '&server=' + $servID
                Write-Verbose "[STOP-HPICJOB] $($uri)"

                Send-HPICRequest $uri PUT $null
            }
            else{
                #The build plan is running on multiple servers.
                #Multiple stop requests must be sent.
                foreach ($servURI in $jobToParse.jobServerInfo.jobserveruri){

                    Write-Verbose "[STOP-HPICJOB] $($servURI)"
                    $servID=$servURI.split('/')[-1]
                    Write-Verbose "[STOP-HPICJOB] $($servID)"

                    $uri = $jobstop + '/stop?bp=' + $bpID + '&server=' + $servID
                    Write-Verbose "[STOP-HPICJOB] $($uri)"

                    Send-HPICRequest $uri PUT $null
                }

            }

        }

        #URI isn't needed to stop multiple build plans
        #Stop Job request is found within body.
        else {

            $uri = $jobstop + '/stop?bp=0&server=0'

            $body=@{uri=$jobstop;bpUri=’/rest/os-deployment-apxs/1770001’;serverUri=’/rest/os-deployment-servers/0’;serverName=’’;chainedJob=’true’;pendingJob=’false’}

            Send-HPICRequest $uri PUT $body

        }
    }
}

#######################################################
#  Export the public functions from this module

#  Generic support functions:
Export-ModuleMember -Function Send-HPICRequest
Export-ModuleMember -Function Connect-HPICMgmt
Export-ModuleMember -Function Set-HPICConnection
Export-ModuleMember -Function Disconnect-HPICMgmt
Export-ModuleMember -Function New-HPICResource
Export-ModuleMember -Function Set-HPICResourceS
Export-ModuleMember -Function Remove-HPICResource
Export-ModuleMember -Function Show-HPICAppliance
Export-ModuleMember -Function Show-HPICSSLCertificate
Export-ModuleMember -Function Import-HPICSSLCertificate
Export-ModuleMember -Function Watch-Job

#  Resource Controllers:
Export-ModuleMember -Function Get-HPICServer
Export-ModuleMember -Function Set-HPICServer
Export-ModuleMember -Function New-HPICServer
Export-ModuleMember -Function Remove-HPICServer

Export-ModuleMember -Function Get-HPICBuildPlan
Export-ModuleMember -Function Set-HPICBuildPlan
Export-ModuleMember -Function New-HPICBuildPlan
Export-ModuleMember -Function Remove-HPICBuildPlan

Export-ModuleMember -Function Get-HPICServerScript
Export-ModuleMember -Function Set-HPICServerScript
Export-ModuleMember -Function New-HPICServerScript
Export-ModuleMember -Function Remove-HPICServerScript

Export-ModuleMember -Function Get-HPICOgfsScript
Export-ModuleMember -Function Set-HPICOgfsScript
Export-ModuleMember -Function New-HPICOgfsScript
Export-ModuleMember -Function Remove-HPICOgfsScript

Export-ModuleMember -Function Get-HPICCfg
Export-ModuleMember -Function Set-HPICCfg
Export-ModuleMember -Function New-HPICCfg
Export-ModuleMember -Function Remove-HPICCfg

Export-ModuleMember -Function Get-HPICDeviceGroup
Export-ModuleMember -Function Set-HPICDeviceGroup
Export-ModuleMember -Function New-HPICDeviceGroup
Export-ModuleMember -Function Remove-HPICDeviceGroup

Export-ModuleMember -Function Get-HPICFacility
Export-ModuleMember -Function Set-HPICFacility

Export-ModuleMember -Function Get-HPICPackage

Export-ModuleMember -Function Get-HPICSetting
Export-ModuleMember -Function Set-HPICDHCPSetting
Export-ModuleMember -Function Import-HPICWinPE
Export-ModuleMember -Function Import-HPICContent
Export-ModuleMember -Function Export-HPICContent
Export-ModuleMember -Function Get-HPICTool

Export-ModuleMember -Function Get-HPICJob
Export-ModuleMember -Function New-HPICJob
Export-ModuleMember -Function Stop-HPICJob

#######################################################
# Library Prompt
#

$Script:PromptApplianceHostname = "[Not Connected]"

#Change the PowerShell Prompt
function global:prompt {

    $cwd = (get-location).Path

    #Disply no more than 2 directories deep in the Prompt, otherwise there will be severe prompt wrapping
    [array]$cwdt=$()
    $cwdi=-1
    do {$cwdi=$cwd.indexofany(“\”,$cwdi+1) ; [array]$cwdt+=$cwdi} until($cwdi -eq -1)

    if ($cwdt.count -gt 3) {
        $cwd = $cwd.substring(0,$cwdt[0]) + “..” + $cwd.substring($cwdt[$cwdt.count-3])
    }

    Write-Host '[HPIC]: ' -ForegroundColor Yellow -NoNewline
        if ($global:cimgmtICspSessionId){
        write-host $script:userName@$Script:PromptApplianceHostname PS $cwd>  -NoNewline
        }
        else{
                write-host $Script:PromptApplianceHostname PS $cwd>  -NoNewline
        }
    return " "

}

# Import-Module Text
write-host ""
write-host "         Welcome to the HP Insight Control server provisioning POSH Library, v$script:scriptVersion"
write-host "         ---------------------------------------------------"
write-host ""
write-host " To get a list of available CMDLETs in this library, type :  " -NoNewline
write-host "Get-Help HPIC" -foregroundcolor yellow
write-host " To get help for a specific command, type:                   " -NoNewLine
write-host "get-help " -NoNewLine -foregroundcolor yellow
Write-Host "[verb]" -NoNewLine -foregroundcolor red
Write-Host "-HPIC" -NoNewLine -foregroundcolor yellow
Write-Host "[noun]" -foregroundcolor red
write-host " To get extended help for a specific command, type:          " -NoNewLine
write-host "get-help " -NoNewLine -foregroundcolor yellow
Write-Host "[verb]" -NoNewLine -foregroundcolor red
Write-Host "-HPIC" -NoNewLine -foregroundcolor yellow
Write-Host "[noun]" -NoNewLine -foregroundcolor red
Write-Host " -full" -foregroundcolor yellow
Write-Host ""
Write-Host " Module sample scripts are located at: " -NoNewLine
write-host "$(split-path -parent $MyInvocation.MyCommand.Path)\Samples" -ForegroundColor yellow
write-host ""
write-host " Copyright (C) 2014 Hewlett-Packard"
if ((Get-Host).UI.RawUI.MaxWindowSize.width -lt 150) {
    write-host ""
    write-host " Note: Set your PowerShell console width to 150 to properly view report output. (Current Max Width: $((Get-Host).UI.RawUI.MaxWindowSize.width))" -ForegroundColor Green
}
write-host ""

#######################################################
#  Remove-Module Processing
#

$ExecutionContext.SessionState.Module.OnRemove = {

    Write-Verbose "[REMOVE-MODULE] Cleaning up"

    if ([System.Net.ServicePointManager]::CertificatePolicy) {

        #Restore System.Net.ServicePointManager
        [System.Net.ServicePointManager]::CertificatePolicy = $Null

    }

}
