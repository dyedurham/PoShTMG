################################################################
###                                                          ###
###  PoShTMG Module - Nial Francis, GlobalX 2014             ###
###                                                          ###
################################################################

function New-TMGWebPublishingRule {
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[parameter(Mandatory=$true)] [string]$ServerHostName,
		[parameter(Mandatory=$true)] [string]$ServerIP,
		[parameter(Mandatory=$true)] [string]$WebListener,
		[parameter(Mandatory=$true)] [string]$PublicNames,
		[string]$SourceNetwork,
		[string]$InternalPathMapping,
		[string]$ExternalPathMapping,
		[bool]$SameAsInternalPath,
		[bool]$Action = 0,
		[bool]$TranslateLinks = 0,
		[int]$ServerAuthentication = 4,
		[switch]$ForwardOriginalHostHeader
	)

	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}

	try {
	  $PolicyRules.Remove("$Name")
	}
	catch {	}

	$newrule = $PolicyRules.AddWebPublishingRule("$Name")
	$newrule.Action = $Action
	$newrule.WebPublishingProperties.WebSite = $ServerHostName
	$newrule.WebPublishingProperties.PublishedServer = $ServerIP
	$newrule.WebPublishingProperties.SendOriginalHostHeader = $ForwardOriginalHostHeader
	if ($SourceNetwork) {$newrule.SourceSelectionIPs.Networks.RemoveAll(); $newrule.SourceSelectionIPs.Networks.Add("$SourceNetwork",0)}
	$newrule.WebPublishingProperties.SetWebListener($WebListener)
	$newrule.WebPublishingProperties.PublicNames.Add($PublicNames)
	$newrule.WebPublishingProperties.TranslateLinks = 0
	$newrule.WebPublishingProperties.CredentialsDelegationType = $ServerAuthentication

	if ($SameAsInternalPath -eq 1) {$ExternalPathMapping = $InternalPathMapping}
	if ($InternalPathMapping) {$newrule.WebPublishingProperties.PathMappings.Add($InternalPathMapping,$SameAsInternalPath,$ExternalPathMapping)}

	Write-Host "`nWhen you're finished, run Save-TMGRules to save your changes`n"
}

function New-TMGAccessRule {
	Param(
		[parameter(Mandatory=$true)] [string]$Name,
		[bool]$Action = 0,
		[int]$ProtocolSelectionMethod = 1,
		[string]$ProtocolName,
		[string]$AppliedComputerSet
	)

	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}

	try {
		$PolicyRules.Remove("$Name")
	}
	catch { }

	$newrule = $PolicyRules.AddAccessRule("$Name")
	$newrule.Action = $Action
	$newrule.AccessProperties.ProtocolSelectionMethod = $ProtocolSelectionMethod
	$newrule.AccessProperties.SpecifiedProtocols.Add("$ProtocolName",0)
	$newrule.SourceSelectionIPs.ComputerSets.Add("$AppliedComputerSet",0)

	Write-Host "`nWhen you're finished, run Save-TMGRules to save your changes`n"
}

function New-TMGComputerSet {
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}

	$newcs = $ComputerSet.Add($Name)

	Write-Host "`nWhen you're finished, run Save-TMGComputerSet to save your changes`n"
}

function Add-TMGComputerToSet {
	Param( 
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$ClientName,
		[parameter(Mandatory=$true)] [string]$ComputerIP
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}

	$newcmp = $ComputerSet.item($SetName)
	$newcmp.Computers.Add($ClientName,$ComputerIP)

	Write-Host "`nWhen you're finished, run Save-TMGComputerSet to save your changes`n"
}

function New-TMGStaticRoute {
	Param( 
		[parameter(Mandatory=$true)] [string]$Destination,
		[parameter(Mandatory=$true)] [string]$Mask,
		[parameter(Mandatory=$true)] [string]$Gateway,
		[int]$Metric = 256
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:StRoute = $tmgarray.StaticRoutes
	}

	$newstrt = $StRoute.Add($Destination,$Mask,"",$Gateway)
	$newstrt.Metric = $Metric

	Write-Host "`nWhen you're finished, run Save-TMGStaticRoute to save your changes`n"
}

function New-TMGProtocolDefinition {
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($Protocol)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:Protocol = $tmgarray.RuleElements.ProtocolDefinitions
	}

	$newprot = $Protocol.Add($Name)

	Write-Host "`nWhen you're finished, run Save-TMGProtocols to save your changes`n"
}

function Add-TMGProtocolPort {
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[parameter(Mandatory=$true)] [int]$LowPort,
		[parameter(Mandatory=$true)] [int]$HighPort,
		[parameter(Mandatory=$true)] [int]$Direction,
		[switch]$TCP,
		[switch]$UDP
	)

	if (($TCP -eq $false) -and ($UDP -eq $false)) {throw "You must specify an IP protocol"}

	if (-not($Protocol)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:Protocol = $tmgarray.RuleElements.ProtocolDefinitions
	}

	$newprot = $Protocol.Item($Name)
	if ($TCP) { $newprot.PrimaryConnections.AddTCP($Direction,$LowPort,$HighPort) }
	if ($UDP) { $newprot.PrimaryConnections.AddUDP($Direction,$LowPort,$HighPort) }

	Write-Host "`nWhen you're finished, run Save-TMGProtocols to save your changes`n"
}


function New-TMGWebListener {
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[string]$ListeningIP,
		[string]$CustomFormsDirectory,
		$RedirectHTTPAsHTTPS = 2,
		$SSLPort,
		$HTTPPort = 80,
		[int]$MaxConnections,
		[bool]$SSOEnabled = 0,
		[string]$SSODomainNames,
		[string]$CertThumbprint
	)

	if (-not($WebListener)) {
	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$global:WebListener = $tmgarray.RuleElements.WebListeners
	}

	try {
	  $WebListener.Remove("$Name")
	}
	catch { }

	$newrule = $WebListener.Add("$Name")
	$newrule.Properties.RedirectHTTPAsHTTPS = $RedirectHTTPAsHTTPS
	if ($SSLPort) {$newrule.Properties.SSLPort = $SSLPort}
	$newrule.Properties.TCPPort = $HTTPPort
	if ($MaxConnections -gt 0) {$newrule.Properties.NumberOfConnections = $MaxConnections}
	$newrule.Properties.AuthenticationSchemes.Add("FBA with AD",0)
	$newrule.Properties.SSOEnabled = $SSOEnabled
	if ($SSODomainNames) {$newrule.Properties.SSOEnabled = 1; $newrule.Properties.SSODomainNames.Add($SSODomainNames)}
	$newrule.Properties.FormsBasedAuthenticationProperties.CustomFormsDirectory = $CustomFormsDirectory

	if ($ListeningIP) {
	  $newrule.IPsOnNetworks.Add("EXTERNAL",2,$ListeningIP)
	} else {
	  $newrule.IPsOnNetworks.Add("EXTERNAL",0,"")
	}

	if ($CertThumbprint) {
		$certhash = (gci cert:\LocalMachine\my\$CertThumbprint).getcerthash()
		$newrule.Properties.AppliedSSLCertificates.Add($certhash,"")
	}

	Write-Host "`nWhen you're finished, run Save-TMGWebListener to save your changes`n"
}

function Add-TMGIPRangeToNetwork {
	Param( 
		[parameter(Mandatory=$true)] [string]$NetworkName,
		[parameter(Mandatory=$true)] [string]$LowIP,
		[parameter(Mandatory=$true)] [string]$HighIP
	)

	if (-not($NetworkConf)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:NetworkConf = $tmgarray.NetworkConfiguration.Networks
	}

	$newrange = $NetworkConf.Item($NetworkName)
	$newrange.IPRangeSet.Add($LowIP,$HighIP)

	Write-Host "`nWhen you're finished, run Save-TMGNetworkConfiguration to save your changes`n"
}

function Add-TMGAdapterRangeToNetwork {
	Param( 
		[parameter(Mandatory=$true)] [string]$NetworkName,
		[parameter(Mandatory=$true)] [string]$AdapterName
	)

	if (-not($NetworkConf)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:NetworkConf = $tmgarray.NetworkConfiguration.Networks
	}
	
	if (-not($TMGServer)) {
		$fpcroot = New-Object -ComObject fpc.root
		$global:TMGServer = $fpcroot.GetContainingServer()
	}
	
	$adap = $TMGServer.Adapters | Where-Object -FilterScript { $_.friendlyname -eq $AdapterName }

	$newrange = $NetworkConf.Item($NetworkName)
	foreach ($elem in $adap.IpRanges) {
	$newrange.IPRangeSet.Add(($elem | foreach {$_.IP_From}),($elem | foreach {$_.IP_To}))
	}

	Write-Host "`nWhen you're finished, run Save-TMGNetworkConfiguration to save your changes`n"
}

function Save-TMGWebListener {
	if (-not($WebListener)) {throw "Nothing to save"}
	try { $WebListener.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGComputerSet {
	if (-not($ComputerSet)) {throw "Nothing to save"}
	try { $ComputerSet.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGRules {
	if (-not($PolicyRules)) {throw "Nothing to save"}
	try { $PolicyRules.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGProtocols {
	if (-not($Protocol)) {throw "Nothing to save"}
	try { $Protocol.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGStaticRoute {
	if (-not($StRoute)) {throw "Nothing to save"}
	try { $StRoute.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGNetworkConfiguration {
	if (-not($NetworkConf)) {throw "Nothing to save"}
	try { $NetworkConf.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function WaitForSync {

	if (-not($TMGServer)) {
		$fpcroot = New-Object -ComObject fpc.root
		$global:TMGServer = $fpcroot.GetContainingServer()
	}

	sleep 15
	do {write-host "Waiting for sync...";sleep 10;$TMGServer.DistributionStatus.Refresh()}
	while ($TMGServer.DistributionStatus.Status -ne 2)
	write-host "Configuration synced!"
}

export-modulemember *-*