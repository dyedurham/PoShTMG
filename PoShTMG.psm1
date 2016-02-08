###############################################################
###															###
###  PoShTMG Module											###
###	 v 0.89													###
###															###
###	 Powershell interface for administering and automating	###
###	 Microsoft Forefront Threat Management Gateway			###
###															###
###	 Original Authors:										###
###  Nial Francis &	Matt Parkes								###
###  @ GlobalX Information Pty. Ltd. Brisbane 2015			###
###															###
###															###
###############################################################

## TODO
# Need to add protocols to webpublishingrules


########	TYPE DEFINITIONS

#PolicyRuleTypes
Add-Type -TypeDefinition @"
	[System.Flags] public enum PolicyRuleTypes {
		Access  = 0,
		ServerPublishing  = 1,
		WebPublishing  = 2,
		PolicyPlaceHolder  = 100
	}
"@

#PolicyRuleActions
Add-Type -TypeDefinition @"
	[System.Flags] public enum PolicyRuleActions {
		Allow  = 0,
		Deny  = 1
	}
"@

#RedirectHTTPAsHTTPS
Add-Type -TypeDefinition @"
	[System.Flags] public enum RedirectHTTPAsHTTPS {
		Disabled  = 0,
		IfAuthenticated  = 1,
		Always  = 2
	}
"@

#PublishedServerType
Add-Type -TypeDefinition @"
	[System.Flags] public enum PublishedServerType {
		HTTP  = 0,
		HTTPS  = 1,
		HTTPAndHTTPS  = 2,
		FTP = 3
	}
"@

#CredentialsDelegation
# 0 = fpcDelegationNonePassThrough
# 1 = fpcDelegationNoneBlock
# 2 = fpcDelegationSecurID 
# 3 = fpcDelegationBasic
# 4 = fpcDelegationNTLM
# 5 = fpcDelegationSPNEGO
# 6 = fpcDelegationKerberosConstrained
Add-Type -TypeDefinition @"
	[System.Flags] public enum CredentialsDelegation {
		NoneClientMay  = 0,
		NoneClientCannot  = 1,
		RSASecurID  = 2,
		Basic = 3,
		NTLM = 4,
		Negotiate = 5,
		Kerberos = 6
	}
"@

#FpcProtocolSelectionType
Add-Type -TypeDefinition @"
	[System.Flags] public enum ProtocolSelectionType {
		All  = 0,
		Selected  = 1,
		AllExceptSelected  = 2
	}
"@

#FpcUDPConnectionDirectionType
# fpcReceiveOnly = 0
# fpcSendOnly = 1
# fpcReceiveSend = 2
# fpcSendReceive = 3
Add-Type -TypeDefinition @"
	[System.Flags] public enum ConnectionDirection {
		In  = 0,
		Out  = 1,
		Receive = 0,
		Send = 1,
		ReceiveSend = 2,
		SendReceive = 3
	}
"@

#FpcConnectionProtocolType 
# fpcICMP = 1
# fpcIGMP = 2
# fpcGGP  = 3
# fpcIP = 4
# fpcST = 5
# fpcTCP = 6
# fpcUDP = 17
# fpcICMPv6 = 158
Add-Type -TypeDefinition @"
	[System.Flags] public enum ConnectionProtocolType {
		ICMP = 1,
		IGMP = 2,
		GGP  = 3,
		IP = 4,
		ST = 5,
		TCP = 6,
		UDP = 17,
		ICMPv6 = 158
	}
"@

#FpcIpSelectionMethods
Add-Type -TypeDefinition @"
	[System.Flags] public enum IPSelectionMethod {
		All  = 0,
		Default  = 1,
		Specified  = 2
	}
"@

#FpcLinkTranslationOptions
Add-Type -TypeDefinition @"
	[System.Flags] public enum LinkTranslationOptions {
		NoOptionsOn = 0x00000000,
		EscapeColon = 0x00000001,
		AllowTranslationOfPartialLinks = 0x00000002
	}
"@

#FpcIncludeStatus
Add-Type -TypeDefinition @"
	[System.Flags] public enum IncludeStatus {
		Include  = 0,
		Exclude  = 1
	}
"@

#FpcLoadBalancingAffinityType
Add-Type -TypeDefinition @"
	[System.Flags] public enum LoadBalancingAffinityType {
		SessionCookie	= 0,
		IP				= 1
	}
"@

#CredentialsDelegation
# 1 = fpcExportImportPasswords
# 2 = fpcExportImportUserPermissions
# 4 = fpcExportImportServerSpecific
# 8 = fpcExportImportEnterpriseSpecific

Add-Type -TypeDefinition @"
	[System.Flags] public enum ExportImportOptionalData {
		None  = 0,
		Passwords  = 1,
		UserPermissions  = 2,
		ServerSpecific  = 4,
		EnterpriseSpecific = 8
	}
"@

########	CONSTANTS

#LINK TRANSLATION MAPPING GUID
Set-Variable LinkTransGUID -option Constant -value "{3563FFF5-DF93-40eb-ABC3-D24B5F14D8AA}"

Set-Variable SharePointXML -option Constant -value '<Configuration BlockExecutables="false" ViaHeaderAction="0" NewViaHeaderValue="" ServerHeaderAction="0" NewServerHeaderValue="" MaxRequestBodyLen="107374182400"><UrlValidation NormalizeBeforeScan="true" VerifyNormalization="false" AllowHighBitCharacters="true" BlockDotInPath="false" MaxLength="10240" MaxQueryLength="10240"><Extensions AllowCondition="0"/></UrlValidation><Verbs AllowCondition="0"/><RequestHeaders/><ResponseHeaders/><DeniedSignatures/></Configuration>'

########	FUNCTIONS AND MAGIC
####		(DON'T CHANGE THIS STUFF)

function Get-TMGWebPublishingRules ($Name) {
	Write-Error "Get-TMGWebPublishingRules is deprecated. Your command will be converted now, but next time use Get-TMGRules with -Type WebPublishing instead."
	Get-TMGRules $Name -Type WebPublishing
}

function Get-TMGAccessRules ($Name) {
	Write-Error "Get-TMGAccessRules is deprecated. Your command will be converted now, but next time use Get-TMGRules with -Type Access instead."
	Get-TMGRules $Name -Type Access
}

function Remove-TMGWebPublishingRule ($Name) {
	Write-Error "Remove-TMGWebPublishingRule is deprecated. Your command will be converted now, but next time use Remove-TMGRule instead."
	Remove-TMGRule $Name
}

function Add-TMGComputerToSet {
	Param(
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$ClientName,
		[parameter(Mandatory=$true)] [string]$ComputerIP
	)
	Write-Error "Add-TMGComputerToSet is deprecated. Your command will be converted now, but next time use Add-TMGEntryToComputerSet instead."
	Add-TMGEntryToComputerSet -SetName $SetName -ClientName $Name -ComputerIP $HostAddress
}

function Get-TMGRules {
<#
	.SYNOPSIS
	Gets the TMG Firewall Policy Rules whose names match the specified Filter.
	.DESCRIPTION
	Uses COM to get the TMG Firewall Policy Rules from the Array that this TMG server is a member of, which match the specified Filter.
	.EXAMPLE
	Get-TMGRules -Filter "Test *"
	.PARAMETER Filter
	The string you want to filter on. Leave blank or don't specify for no filtering.
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, HelpMessage='The Filter to apply to the list of Rule Names.')] [string]$Filter,
		[ValidateSet("Access","ServerPublishing","WebPublishing")][string]$Type
	)
	
	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}
	
	if (-Not $Filter) { $Filter = "*" }
	
	if ($Type) {
		$result = ForEach ($stn in ([array]$Filter -split ",")) {
			$PolicyRules | Where-Object { ($_.Name -like $stn) -And ($_.Type -eq [PolicyRuleTypes]::$Type) }
		}
	} else {
		$result = ForEach ($stn in ([array]$Filter -split ",")) {
			$PolicyRules | Where-Object { $_.Name -like $stn }
		}
	}
	
	return $result | Sort-Object -Unique -Property PersistentName
}

function New-TMGWebPublishingRule {
<#
	.SYNOPSIS
	Creates a new TMG Web Publishing Rule.
	.DESCRIPTION
	Uses COM to create the specified TMG Web Publishing Rule on the array that this TMG server is a member of.
	
	New-TMGWebPublishingRule can be executed consecutively to create new rules. Save-TMGRules must then be executed to save the changes.

	Parameter names match the option name in the GUI Web Publishing Rule Properties dialog where possible, others have been added to parameter help.
	Run Get-Help New-TMGWebPublishingRule -Full
	.PARAMETER ServerHostName
	GUI Location: To tab / The rule applies to the published site.
	.PARAMETER ServerIP
	GUI Location: To tab / Computer name or IP address...
	.PARAMETER ForwardOriginalHostHeader
	GUI Location: To tab.
	.PARAMETER AllPublicNames
	GUI Location: Public Names tab / All requests.
	Boolean. Sets the rule to respond to all requested host names.
	.PARAMETER PublicNames
	GUI Location: Public Names tab / Requests to the following Web sites.
	A comma separated list of DNS and IP addresses specified on the Public Name tab.
	.PARAMETER SourceNetwork
	A comma separated list of network objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputerSet
	A comma separated list of computer set objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputer
	A comma separated list of computer objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER ExcludeNetwork
	A comma separated list of network objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputerSet
	A comma separated list of computer set objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputer
	A comma separated list of computer objects to add to the Exceptions box on the From tab.
	.PARAMETER DeniedRuleRedirectURL
	GUI Location: Action tab / Redirect HTTP requests... box. Setting this also checks the check box and nullifying unchecks.
	.PARAMETER InternalPathMapping
	GUI Location: Paths tab - The Internal Path setting. NOTE: This item must be paired with either ExternalPathMapping or SameAsInternalPath.
	.PARAMETER ExternalPathMapping
	GUI Location: Paths tab - The External Path setting. Must be paired with InternalPathMapping.
	.PARAMETER SameAsInternalPath
	GUI Location: Paths tab - This option is a boolean, paired with the Internal Path setting autofills ExternalPathMapping to match.
	.PARAMETER LinkTranslationReplace
	GUI Location: Link Translation tab / Configure / Replace. Must be paired with LinkTranslationReplaceWith.
	.PARAMETER LinkTranslationReplaceWith
	GUI Location: Link Translation tab / Configure / With. Must be paired with LinkTranslationReplace.
	.PARAMETER TranslateLinks
	GUI Location: Link Translation tab / Apply link translation...
	.PARAMETER ServerAuthentication
	GUI Location: Authentication Delegation tab / Method used...
	NoneClientMay | NoneClientCannot | RSASecurID | Basic | NTLM | Negotiate | Kerberos
	.PARAMETER ServerType
	GUI Location: Bridging tab.
	HTTP | HTTPS | HTTPandSSL | FTP
	.PARAMETER LoadBalancingAffinity
	GUI Location: Web Farm tab / Load-Balance Mechanism.
	SessionCookie | IP
	Default is SessionCookie.
	.PARAMETER LoadBalancingEnabled
	Modifies the rule to enable TMG load balancing across multiple servers defined in a Server Farm (New-TMGServerFarm) object, which is specified by the LoadBalancingFarm parameter.
	.PARAMETER LoadBalancingFarm
	Adds a server farm definition to the rule. Use with the LoadBalancingEnabled parameter.
	.PARAMETER ServerApplication
	GUI Location: Firewall Policy > New context menu - Choice of:
	Web Site Publishing Rule...
	Exchange Web Client Access Publishing Rule...
	SharePoint Site Publishing Rule...
	GeneralWebServer | ExchangeServer | SharePointServer
	Default is GeneralWebServer.
	.PARAMETER AlternateAccessMapping
	GUI Location: Firewall Policy > New context menu > SharePoint Site Publishing Rule... > Alternate Access Mapping Configuration page.
	The switch enables SharePoint Alternate Access Mapping. This parameter is ignored if ServerApplication does not equal SharePointServer.
	Default is disabled.
	.PARAMETER HTTPRedirectPort
	GUI Location: Bridging tab.
	.PARAMETER SSLRedirectPort
	GUI Location: Bridging tab.
	.PARAMETER UserSet
	GUI Location: Users tab.
	Specifies a User Set object to add to the rule. This can be included or an excluded with the IncludeStatus parameter.
	.PARAMETER IncludeStatus
	GUI Location: Users tab.
	Include | Exclude
	When specified with a UserSet, this parameter specifies whether the User Set is Included or Excluded.
	Included adds the set to the This rule applies to... list.
	Excluded adds the set to the Exceptions list.
	Default is Included.
	.EXAMPLE
	New-TMGWebPublishingRule -Name Test -Action Allow -ServerHostName myinternalserver -ServerIP 192.168.1.1 -WebListener MyWL -PublicNames "www.mysite.com,www.awesome.com"
	.EXAMPLE
	New-TMGWebPublishingRule -Name Test -Action Deny -WebListener MyWL -PublicNames "www.mysite.com,www.awesome.com"
	.EXAMPLE
	New-TMGWebPublishingRule -Name Test -Action Allow -ServerHostName myinternalserver -ServerIP 192.168.1.1  -WebListener MyWL -ForwardOriginalHostHeader -UserSet MyUserList -IncludeStatus Include
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[parameter(Mandatory=$true)] [ValidateSet("Allow","Deny")][string]$Action,
		[parameter(Mandatory=$true)] [string]$WebListener,
		[ValidateSet("HTTP","HTTPS","HTTPandSSL","FTP")][string]$ServerType,
		[ValidateSet("GeneralWebServer","ExchangeServer","SharePointServer")][string]$ServerApplication = "GeneralWebServer",
		[ValidateSet("NoneClientMay","NoneClientCannot","RSASecurID","Basic","NTLM","Negotiate","Kerberos")][string]$ServerAuthentication = "NTLM",
		[ValidateSet("Include","Exclude")][string]$IncludeStatus = "Include",
		[ValidateSet("NoOptionsOn","EscapeColon","AllowTranslationOfPartialLinks")][string]$LinkTranslationOptions,
		[ValidateSet("SessionCookie","IP")][string]$LoadBalancingAffinity = "SessionCookie",
		[string]$UserSet,
		[string]$ServerHostName,
		[string]$ServerIP,
		[bool]$AllPublicNames,
		[string]$PublicNames,
		[string]$DeniedRuleRedirectURL,
		[string]$SourceNetworks,
		[string]$ExcludeNetworks,
		[string]$SourceComputerSets,
		[string]$ExcludeComputerSets,
		[string]$SourceComputers,
		[string]$ExcludeComputers,
		[string]$LogoffURL,
		[string]$InternalPathMapping,
		[string]$ExternalPathMapping,
		[string]$LoadBalancingFarm,
		[bool]$SameAsInternalPath,
		[hashtable]$PathMappings,
		[bool]$TranslateLinks = 0,
		[string]$LinkTranslationReplace,
		[string]$LinkTranslationReplaceWith,
		[bool]$Enabled = $true,
		[int]$SSLRedirectPort,
		[int]$HTTPRedirectPort,
		[switch]$LoadBalancingEnabled,
		[switch]$ForwardOriginalHostHeader,
		[switch]$StripDomainFromCredentials,
		[switch]$AlternateAccessMapping
	)
	
	#### INPUT VALIDATION
	if (($Enabled) -and (!$ServerHostName -and !$LoadBalancingEnabled)) { throw "An enabled rule must contain a ServerHostName or have LoadBalancingEnabled" }
	if (($LoadBalancingEnabled) -and (-not($LoadBalancingFarm))) {throw "A load balancing server farm must be specified with -LoadBalancingFarm if -LoadBalancingEnabled is set."}
	
	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}

	try {
		if ( $PolicyRules.Item("$Name") ) {
			Write-Verbose "A web publishing rule named $Name already exists."
			return
		}
	} catch {}
	
	$newrule = $PolicyRules.AddWebPublishingRule("$Name")
	
	switch ($ServerApplication) {
		GeneralWebServer	{ $newrule.WebPublishingProperties.PublishedServerApplication = 0 }
		ExchangeServer		{
			$newrule.WebPublishingProperties.PublishedServerApplication = 1
			Write-Host "Exchange settings have not been implemented in PoShTMG yet"
		}
		SharePointServer	{
			$newrule.WebPublishingProperties.PublishedServerApplication = 2
			$newrule.WebPublishingProperties.AlternateAccessMappingConfigured = $AlternateAccessMapping
			$TranslateLinks = 1
			$LinkTranslationOptions = 'EscapeColon'
			if (-not($LogoffURL)) { $LogoffURL = '/_layouts/SignOut.aspx' }
			$ForwardOriginalHostHeader = $true
			$AllPublicNames = 0
			
			$splt = $newrule.VendorParametersSets.Add($LinkTransGUID)
			foreach ($pnm in ([array]$PublicNames -split ",")) {
				$splt.Value("http:\/\/$pnm") = "https:\/\/$pnm"
			}
			
			$newrule.WebPublishingProperties.PathMappings.Add('/_vti_inf.html*',1,'')
			$newrule.WebPublishingProperties.PathMappings.Add('/_vti_bin/*',1,'')
			$newrule.WebPublishingProperties.PathMappings.Add('/_upresources/*',1,'')
			$newrule.WebPublishingProperties.PathMappings.Add('/_layouts/*',1,'')
			$newrule.WebPublishingProperties.PathMappings.Add('/*',1,'')
			
			$splt = $newrule.VendorParametersSets.Add('{5e302ed5-f5d5-4fad-9b8a-01c72e1569f3}')
			$splt.Value("AddHttpsFrontEndOn") = ''
			
			$splt = $newrule.VendorParametersSets.Add('{f1076e51-bbaf-48ba-a2d7-b0875211e80d}')
			$splt.Value("XML_POLICY") = $SharePointXML
		}
	}
	
	$newrule.WebPublishingProperties.WebSite = $ServerHostName
	$newrule.WebPublishingProperties.PublishedServer = $ServerIP
	$newrule.WebPublishingProperties.LogoffURL = $LogoffURL
	$newrule.WebPublishingProperties.AllPublicNames = $AllPublicNames
	$newrule.WebPublishingProperties.SetWebListener($WebListener)
	$newrule.WebPublishingProperties.TranslateLinks = $TranslateLinks
	$newrule.WebPublishingProperties.CredentialsDelegationType = [int][CredentialsDelegation]::($ServerAuthentication)
	$newrule.WebPublishingProperties.RedirectURL = $DeniedRuleRedirectURL
	$newrule.WebPublishingProperties.StripDomainFromCredentials = $StripDomainFromCredentials
	$newrule.Enabled = $Enabled
	$newrule.WebPublishingProperties.SendOriginalHostHeader = $ForwardOriginalHostHeader
	
	if ($SSLRedirectPort) { $newrule.WebPublishingProperties.SSLRedirectPort = $SSLRedirectPort }
	if ($HTTPRedirectPort) { $newrule.WebPublishingProperties.HTTPRedirectPort = $HTTPRedirectPort }
	if ($Action) { $newrule.Action = [int][PolicyRuleActions]::$Action }
	if ($ServerType) { $newrule.WebPublishingProperties.PublishedServerType = [int][PublishedServerType]::$ServerType }
	if ($LinkTranslationOptions) { $newrule.WebPublishingProperties.LinkTranslationOptions = [int][LinkTranslationOptions]::$LinkTranslationOptions }
	if ($SameAsInternalPath -eq 1) { $ExternalPathMapping = '' }
	if ($InternalPathMapping) { $newrule.WebPublishingProperties.PathMappings.Add($InternalPathMapping,$SameAsInternalPath,$ExternalPathMapping) }
	
	## APPLY ACCESS POLICY IF SPECIFIED
	if ($SourceNetworks) {
		$newrule.SourceSelectionIPs.Networks.RemoveAll()
		foreach ($src in ([array]$SourceNetworks -split ",")) {
				$newrule.SourceSelectionIPs.Networks.Add("$src",0)}
	}

	if ($SourceComputerSets) {
		$newrule.SourceSelectionIPs.ComputerSets.RemoveAll()
		foreach ($src in ([array]$SourceComputerSets -split ",")) {
				$newrule.SourceSelectionIPs.ComputerSets.Add("$src",0)}
	}
	
	if ($SourceComputers) {
		$newrule.SourceSelectionIPs.Computers.RemoveAll()
		foreach ($src in ([array]$SourceComputers -split ",")) {
				$newrule.SourceSelectionIPs.Computers.Add("$src",0)}
	}
	
	if ($ExcludeNetworks) {
		foreach ($exc in ([array]$ExcludeNetworks -split ",")) {
				$newrule.SourceSelectionIPs.Networks.Add("$exc",1)}
	}
	
	if ($ExcludeComputerSets) {
		foreach ($exc in ([array]$ExcludeComputerSets -split ",")) {
				$newrule.SourceSelectionIPs.ComputerSets.Add("$exc",1)}
	}
	
	if ($ExcludeComputers) {
		foreach ($exc in ([array]$ExcludeComputers -split ",")) {
				$newrule.SourceSelectionIPs.Computers.Add("$exc",1)}
	}
	
	if ($PublicNames) {
		foreach ($pnm in ([array]$PublicNames -split ",")) {
				$newrule.WebPublishingProperties.PublicNames.Add($pnm.Trim()) }
	}
	
	if ($LinkTranslationReplace) {
		$nlt = $newrule.VendorParametersSets.Add($LinkTransGUID)
		$nlt.Value($LinkTranslationReplace) = $LinkTranslationReplaceWith
		#$nlt.Save()
	}
	
	if ($UserSet) {
		$newrule.WebPublishingProperties.UserSets.RemoveAll()
		$newrule.WebPublishingProperties.UserSets.Add($UserSet,([int][IncludeStatus]::$IncludeStatus))
	}
	
	if ($PathMappings) {
		ForEach ($PathMapping in $PathMappings.GetEnumerator()) {
			if ($PathMapping.Name -eq $PathMapping.Value) {
				$PathMappingsSame = $true
			} else {
				$PathMappingsSame = $false
			}
			$newrule.WebPublishingProperties.PathMappings.Add($PathMapping.Name,$PathMappingsSame,$PathMapping.Value)
		}
	}
	
	if ($LoadBalancingEnabled) {
		$newrule.WebPublishingProperties.LoadBalancingEnabled = 1
		$newrule.WebPublishingProperties.LoadBalancingConfig.SetServerFarm($LoadBalancingFarm)
		$newrule.WebPublishingProperties.LoadBalancingConfig.AffinityType = [int][LoadBalancingAffinityType]::$LoadBalancingAffinity
	}
	
	return $newrule
}

function Set-TMGWebPublishingRule {
<#
	.SYNOPSIS
	Modifies a TMG Web Publishing Rule.
	.DESCRIPTION
	Uses COM to modify the specified TMG Web Publishing Rule on the array that this TMG server is a member of.
	
	Set-TMGWebPublishingRule can be executed consecutively to modify rules. Save-TMGRules must then be executed to save the changes.

	Parameter names match the option name in the GUI Web Publishing Rule Properties dialog where possible, others have been added to parameter help.
	Run Get-Help Set-TMGWebPublishingRule -Full
	.PARAMETER ServerHostName
	GUI Location: To tab / The rule applies to the published site.
	.PARAMETER ServerIP
	GUI Location: To tab / Computer name or IP address...
	.PARAMETER ForwardOriginalHostHeader
	GUI Location: To tab.
	.PARAMETER PublicNames
	A comma separated list of DNS and IP addresses specified on the Public Name tab.
	.PARAMETER SourceNetwork
	A comma separated list of network objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputerSet
	A comma separated list of computer set objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputer
	A comma separated list of computer objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER ExcludeNetwork
	A comma separated list of network objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputerSet
	A comma separated list of computer set objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputer
	A comma separated list of computer objects to add to the Exceptions box on the From tab.
	.PARAMETER DeniedRuleRedirectURL
	GUI Location: Action tab / Redirect HTTP requests... box. Setting this also checks the check box and nullifying unchecks.
	.PARAMETER InternalPathMapping
	GUI Location: Paths tab - The Internal Path setting. NOTE: This item must be paired with either ExternalPathMapping or SameAsInternalPath.
	.PARAMETER ExternalPathMapping
	GUI Location: Paths tab - The External Path setting. Must be paired with InternalPathMapping.
	.PARAMETER SameAsInternalPath
	GUI Location: Paths tab - This option is a boolean, paired with the Internal Path setting autofills ExternalPathMapping to match.
	.PARAMETER LinkTranslationReplace
	GUI Location: Link Translation tab / Configure / Replace. Must be paired with LinkTranslationReplaceWith.
	.PARAMETER LinkTranslationReplaceWith
	GUI Location: Link Translation tab / Configure / With. Must be paired with LinkTranslationReplace.
	.PARAMETER TranslateLinks
	GUI Location: Link Translation tab / Apply link translation...
	.PARAMETER ServerAuthentication
	GUI Location: Authentication Delegation tab / Method used...
	NoneClientMay | NoneClientCannot | RSASecurID | Basic | NTLM | Negotiate | Kerberos
	.PARAMETER ServerType
	GUI Location: Bridging tab.
	HTTP | HTTPS | HTTPandSSL | FTP
	.PARAMETER HTTPRedirectPort
	GUI Location: Bridging tab.
	.PARAMETER SSLRedirectPort
	GUI Location: Bridging tab.
	.PARAMETER UserSet
	GUI Location: Users tab.
	Specifies a User Set object to add to the rule. This can be included or an excluded with the IncludeStatus parameter.
	.PARAMETER IncludeStatus
	GUI Location: Users tab.
	Include | Exclude
	When specified with a UserSet, this parameter specifies whether the User Set is Included or Excluded.
	Included adds the set to the This rule applies to... list.
	Excluded adds the set to the Exceptions list.
	Default is Included.
	.EXAMPLE
	Set-TMGWebPublishingRule -Name Test -Action Deny -WebListener MyWL -PublicNames "www.mysite.com,www.awesome.com"
#>
	Param(
		[parameter(Mandatory=$true)] [string]$Name,
		[ValidateSet("Allow","Deny")][string]$Action,
		[ValidateSet("HTTP","HTTPS","HTTPandSSL","FTP")][string]$ServerType,
		[ValidateSet("NoneClientMay","NoneClientCannot","RSASecurID","Basic","NTLM","Negotiate","Kerberos")][string]$ServerAuthentication,
		[ValidateSet("Include","Exclude")][string]$IncludeStatus,
		[ValidateSet("GeneralWebServer","ExchangeServer","SharePointServer")][string]$ServerApplication,
		[ValidateSet("SessionCookie","IP")][string]$LoadBalancingAffinity,
		[string]$NewName,
		[string]$WebListener,
		[string]$UserSet,
		[string]$ServerHostName,
		[string]$ServerIP,
		[string]$PublicNames,
		[string]$DeniedRuleRedirectURL,
		[string]$SourceNetworks,
		[string]$ExcludeNetworks,
		[string]$SourceComputerSets,
		[string]$ExcludeComputerSets,
		[string]$SourceComputers,
		[string]$ExcludeComputers,
		[string]$RemoveSourceNetworks,
		[string]$RemoveSourceComputerSets,
		[string]$RemoveSourceComputers,
		[string]$LogoffURL,
		[string]$InternalPathMapping,
		[string]$ExternalPathMapping,
		[string]$LoadBalancingFarm,
		[bool]$SameAsInternalPath,
		[hashtable]$PathMappings,
		[bool]$TranslateLinks,
		[string]$LinkTranslationReplace,
		[string]$LinkTranslationReplaceWith,
		[bool]$Enabled,
		[int]$SSLRedirectPort,
		[int]$HTTPRedirectPort,
		[bool]$ForwardOriginalHostHeader,
		[bool]$LoadBalancingEnabled,
		[switch]$StripDomainFromCredentials
	)
	
	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}

	try {
	  $modrule = $PolicyRules.Item($Name)
	} catch {
		Write-Error "Rule $Name could not be bound. Does the rule exist?"
		return
	}
	
	if ($PSBoundParameters.ContainsKey('NewName')) { $modrule.Name = $NewName }
	if ($PSBoundParameters.ContainsKey('Action')) {$modrule.Action = [int][PolicyRuleActions]::$Action}
	if ($PSBoundParameters.ContainsKey('SSLRedirectPort')) { $modrule.WebPublishingProperties.SSLRedirectPort = $SSLRedirectPort }
	if ($PSBoundParameters.ContainsKey('HTTPRedirectPort')) { $modrule.WebPublishingProperties.HTTPRedirectPort = $HTTPRedirectPort }
	if ($PSBoundParameters.ContainsKey('ServerType')) { $modrule.WebPublishingProperties.PublishedServerType = [int][PublishedServerType]::$ServerType }
	if ($PSBoundParameters.ContainsKey('ServerApplication')) {$modrule.WebPublishingProperties.PublishedServerApplication = [int][PublishedServerApplication]::$ServerApplication}
	if ($SameAsInternalPath -eq 1) { $ExternalPathMapping = $InternalPathMapping }
	if ($PSBoundParameters.ContainsKey('InternalPathMapping')) { $modrule.WebPublishingProperties.PathMappings.Add($InternalPathMapping,$SameAsInternalPath,$ExternalPathMapping) }
	if ($PSBoundParameters.ContainsKey('ServerHostName')) { $modrule.WebPublishingProperties.WebSite = $ServerHostName }
	if ($PSBoundParameters.ContainsKey('ServerIP')) { $modrule.WebPublishingProperties.PublishedServer = $ServerIP }
	if ($PSBoundParameters.ContainsKey('LogoffURL')) { $modrule.WebPublishingProperties.LogoffURL = $LogoffURL }
	if ($PSBoundParameters.ContainsKey('WebListener')) { $modrule.WebPublishingProperties.SetWebListener($WebListener) }
	if ($PSBoundParameters.ContainsKey('TranslateLinks')) { $modrule.WebPublishingProperties.TranslateLinks = $TranslateLinks }
	if ($PSBoundParameters.ContainsKey('ServerAuthentication')) { $modrule.WebPublishingProperties.CredentialsDelegationType = [int][CredentialsDelegation]::($ServerAuthentication) }
	if ($PSBoundParameters.ContainsKey('DeniedRuleRedirectURL')) { $modrule.WebPublishingProperties.RedirectURL = $DeniedRuleRedirectURL }
	if ($PSBoundParameters.ContainsKey('StripDomainFromCredentials')) { $modrule.WebPublishingProperties.StripDomainFromCredentials = $StripDomainFromCredentials }
	if ($PSBoundParameters.ContainsKey('Enabled')) { $modrule.Enabled = $Enabled }
	if ($PSBoundParameters.ContainsKey('ForwardOriginalHostHeader')) { $modrule.WebPublishingProperties.SendOriginalHostHeader = $ForwardOriginalHostHeader }
	if ($PSBoundParameters.ContainsKey('LoadBalancingEnabled')) { $modrule.WebPublishingProperties.LoadBalancingEnabled = $LoadBalancingEnabled }
	
	if ($LoadBalancingFarm) { $modrule.WebPublishingProperties.LoadBalancingConfig.SetServerFarm($LoadBalancingFarm) }
	if ($LoadBalancingAffinity) { $modrule.WebPublishingProperties.LoadBalancingConfig.AffinityType = [int][LoadBalancingAffinityType]::$LoadBalancingAffinity }
	
	## APPLY ACCESS POLICY IF SPECIFIED
	if (($SourceNetworks) -or ($SourceComputerSets) -or ($SourceComputers)) { $modrule.SourceSelectionIPs.Networks.RemoveAll() }
	
	if ($SourceNetworks) {
		foreach ($src in ([array]$SourceNetworks -split ",")) {
				$modrule.SourceSelectionIPs.Networks.Add("$src",0)}
	}
		
	if ($SourceComputerSets) {
		foreach ($src in ([array]$SourceComputerSets -split ",")) {
				$modrule.SourceSelectionIPs.ComputerSets.Add("$src",0)}
	}
	
	if ($SourceComputers) {
		foreach ($src in ([array]$SourceComputers -split ",")) {
				$modrule.SourceSelectionIPs.Computers.Add("$src",0)}
	}
	
	if ($ExcludeNetworks) {
		foreach ($exc in ([array]$ExcludeNetworks -split ",")) {
				$modrule.SourceSelectionIPs.Networks.Add("$exc",1)}
	}
	
	if ($ExcludeComputerSets) {
		foreach ($exc in ([array]$ExcludeComputerSets -split ",")) {
				$modrule.SourceSelectionIPs.ComputerSets.Add("$exc",1)}
	}
	
	if ($ExcludeComputers) {
		foreach ($exc in ([array]$ExcludeComputers -split ",")) {
				$modrule.SourceSelectionIPs.Computers.Add("$exc",1)}
	}
	
	if ($RemoveSourceNetworks) {
		foreach ($src in ([array]$RemoveSourceNetworks -split ",")) {
				$modrule.SourceSelectionIPs.Networks.RemoveSpecified("$src")}
	}
		
	if ($RemoveSourceComputerSets) {
		foreach ($src in ([array]$RemoveSourceComputerSets -split ",")) {
				$modrule.SourceSelectionIPs.ComputerSets.RemoveSpecified("$src")}
	}
	
	if ($RemoveSourceComputers) {
		foreach ($src in ([array]$RemoveSourceComputers -split ",")) {
				$modrule.SourceSelectionIPs.Computers.RemoveSpecified("$src")}
	}
	
	if ($PublicNames) {
		foreach ($pnm in ([array]$PublicNames -split ",")) {
				$modrule.WebPublishingProperties.PublicNames.Add($pnm.Trim()) }
	}
	
	if ($LinkTranslationReplace) {
		try {
			$nlt = $modrule.VendorParametersSets.Add($LinkTransGUID)
		} catch {}
		
		$nlt = $modrule.VendorParametersSets.Item($LinkTransGUID)
		$nlt.Value($LinkTranslationReplace) = $LinkTranslationReplaceWith
		#$nlt.Save()
	}
	
	if ($UserSet) {
		$modrule.WebPublishingProperties.UserSets.RemoveAll()
		$modrule.WebPublishingProperties.UserSets.Add($UserSet,([int][IncludeStatus]::$IncludeStatus))
	}
	
	if ($PathMappings) {
		ForEach ($PathMapping in $PathMappings.GetEnumerator()) {
			if ($PathMapping.Name -eq $PathMapping.Value) {
				$PathMappingsSame = $true
			} else {
				$PathMappingsSame = $false
			}
			$modrule.WebPublishingProperties.PathMappings.Add($PathMapping.Name,$PathMappingsSame,$PathMapping.Value)
		}
	}
	
	return $modrule
}

function Remove-TMGRule {
<#
	.SYNOPSIS
	Deletes the specified TMG firewall policy rules.
	
	Supports pipelining.
	.EXAMPLE
	Remove-TMGRule -Name "Test"
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)] [string]$Name
)
	BEGIN {
		if (-not($PolicyRules)) {
			$fpcroot = New-Object -ComObject fpc.root
			$tmgarray = $fpcroot.GetContainingArray()
			$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
		}
	}
	
	PROCESS {
		try {
			$PolicyRules.remove($Name)
		} catch {
			Write-error $_.Exception.Message
			break
		}
	}
}

function Move-TMGRule {
	<#
	.SYNOPSIS
	Moves (changes the order) of a TMG Rule
	.DESCRIPTION
	
	.EXAMPLE
	Move-TMGRule -Name "Web Publishing Rule 1" -Up
#>
	Param( 
		[parameter(Mandatory=$true,ParameterSetName = "Name")] [string]$Name,
		[parameter(Mandatory=$true,ParameterSetName = "Rule")] $Rule,
		[parameter(Mandatory=$true,ParameterSetName = "Up")][parameter(ParameterSetName = "Name")][parameter(ParameterSetName = "Rule")] [switch]$Up,
		[parameter(Mandatory=$true,ParameterSetName = "Down")][parameter(ParameterSetName = "Name")][parameter(ParameterSetName = "Rule")] [switch]$Down
		#[parameter(Mandatory=$false,ParameterSetName = "Up")][parameter(ParameterSetName = "Down")] [int]$Number =1

		
#		[int]$Position,		#Position will determine correct number of MoveUp() or MoveDown() to get to the desired position
#		[switch]$Top,		#Top 			""					""
#		[switch]$Bottom		#Bottom			""					""

#		$AboveRuleNamed		#will place this rule immediately above the specified rule
#		$BelowRuleNamed,	#will place this rule immediately below the specified rule

	)
	
	if ((-Not $Rule) -And (-Not $Name)) { Throw "You must provide either -Rule or -Name" }
	if ((-Not $Up) -And (-Not $Down)) { Throw "You must provide either -Up or -Down" }
		
	if (-Not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}
	
	if ($Name) {
		ForEach ($policyrule in $global:PolicyRules) {
			if ($policyrule.Name -eq $Name) {
				$Rule = $policyrule
				break
			}
		}
	}
	
	if ($Up) { 
		$global:PolicyRules.MoveUp($Rule.order)
	}
	
	if ($Down) {
		$global:PolicyRules.MoveDown($Rule.order)
	}
}

function New-TMGAccessRule {
<#
	.SYNOPSIS
	Creates a new TMG Access Rule.
	.DESCRIPTION
	Uses COM to create the specified TMG Access Rule on the array that this TMG server is a member of.
	
	New-TMGAccessRule can be executed consecutively to create new rules. Save-TMGRules must then be executed to save the changes.

	Parameter names match the option name in the GUI Access Rule Properties dialog where possible, others have been added to parameter help.
	Run Get-Help New-TMGAccessRule -Full
	.PARAMETER ProtocolNames
	A comma separated list of protocol object names.
	.PARAMETER SourceNetwork
	A comma separated list of network objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputerSet
	A comma separated list of computer set objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER SourceComputer
	A comma separated list of computer objects to add to the [applies to traffic] box on the From tab.
	.PARAMETER ExcludeNetwork
	A comma separated list of network objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputerSet
	A comma separated list of computer set objects to add to the Exceptions box on the From tab.
	.PARAMETER ExcludeComputer
	A comma separated list of computer objects to add to the Exceptions box on the From tab.
	.EXAMPLE
	New-TMGAccessRule -Name Test -Action Allow -ProtocolSelectionMethod AllExceptSelected -ProtocolNames HTTP -ExcludeNetwork MyEnemies
#>
	Param(
		[parameter(Mandatory=$true)][string]$Name,
		[parameter(Mandatory=$true)][ValidateSet("Allow","Deny")][string]$Action,
		[ValidateSet("All","Selected","AllExceptSelected")][string]$ProtocolSelectionMethod = "Selected",
		[ValidateSet("Include","Exclude")][string]$IncludeStatus = "Include",
		[string]$UserSet,
		[string]$ProtocolNames,
		[string]$SourceNetwork,
		[string]$ExcludeNetwork,
		[string]$SourceComputerSet,
		[string]$ExcludeComputerSet,
		[string]$SourceComputer,
		[string]$ExcludeComputer,
		[string]$DestinationNetwork
	)

	if (-not($PolicyRules)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:PolicyRules = $tmgarray.ArrayPolicy.PolicyRules
	}

	try {
		if ( $PolicyRules.Item("$Name") ) {
			Write-Verbose "An access rule named $Name already exists."
			return
		}
	} catch {}

	$newrule = $PolicyRules.AddAccessRule("$Name")
	$newrule.Action = [int][PolicyRuleActions]::$Action
	$newrule.AccessProperties.ProtocolSelectionMethod = [int][ProtocolSelectionType]::$ProtocolSelectionMethod
	
	## APPLY ACCESS POLICY IF SPECIFIED
	if (($SourceNetwork) -or ($SourceComputerSet) -or ($SourceComputer)) { $newrule.SourceSelectionIPs.Networks.RemoveAll() }
	
	if ($SourceNetwork) {
		foreach ($src in ([array]$SourceNetwork -split ",")) {
				$newrule.SourceSelectionIPs.Networks.Add("$src",0) }
	}
		
	if ($SourceComputerSet) {
		foreach ($src in ([array]$SourceComputerSet -split ",")) {
				$newrule.SourceSelectionIPs.ComputerSets.Add("$src",0) }
	}
	
	if ($SourceComputer) {
		foreach ($src in ([array]$SourceComputer -split ",")) {
				$newrule.SourceSelectionIPs.Computers.Add("$src",0) }
	}
	
	if ($ExcludeNetwork) {
		foreach ($exc in ([array]$ExcludeNetwork -split ",")) {
				$newrule.SourceSelectionIPs.Networks.Add("$exc",1) }
	}
	
	if ($ExcludeComputerSet) {
		foreach ($exc in ([array]$ExcludeComputerSet -split ",")) {
				$newrule.SourceSelectionIPs.ComputerSets.Add("$exc",1) }
	}
	
	if ($ExcludeComputer) {
		foreach ($exc in ([array]$ExcludeComputer -split ",")) {
				$newrule.SourceSelectionIPs.Computers.Add("$exc",1) }
	}
	
	if ($DestinationNetwork) {
		$newrule.AccessProperties.DestinationSelectionIPs.Networks.Add($DestinationNetwork, 0)
	}
	
	if ($ProtocolNames) {
		foreach ($prt in ([array]$ProtocolNames -split ",")) {
				$newrule.AccessProperties.SpecifiedProtocols.Add("$prt",0) }
	}
	
	if ($UserSet) {
		$newrule.AccessProperties.UserSets.RemoveAll()
		$newrule.AccessProperties.UserSets.Add($UserSet,([int][IncludeStatus]::$IncludeStatus))
	}
	
	return $newrule
}

function Get-TMGComputerSets {
<#
	.SYNOPSIS
	Gets the TMG Computer Sets whose names match the specified Filter.
	.DESCRIPTION
	Uses COM to get the TMG Computer Sets from the Array that this TMG server is a member of, which match the specified Filter.
	
	The filter is a string and can include a * wildcard.
	Multiple filters may be used to return multiple results by separating the items with a comma. Therefore, a rule name containing a comma should be matched by a wildcard.
	.EXAMPLE
	Get-TMGComputerSets -Filter "Test *"
	.EXAMPLE
	Get-TMGComputerSets -Filter "Test *,Set2"
	.PARAMETER Filter
	The string you want to filter on. Leave blank or don't specify for no filtering, or use an exact name, wildcard or a comma-separated list for multiple results.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True,
	HelpMessage='The Filter to apply to the list of Rule Names.')] [string]$Filter
)
	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$computersets = $tmgarray.RuleElements.ComputerSets
	
	#Set $Filter to * if not set
	if (-Not $Filter) {	$Filter = "*" }
	
	$result = ForEach ($stn in ([array]$Filter -split ",")) {
		$computersets | Where-Object {$_.Name -like $stn}
	}
	
	return $result | Sort-Object -Unique -Property PersistentName
}

function New-TMGServerFarm {
<#
	.SYNOPSIS
	Adds a TMG Server Farm with the specified name.
	.DESCRIPTION
	Uses COM to create the specified TMG Server Farm on the array that this TMG server is a member of.
	
	New-TMGServerFarm can be executed consecutively to create new sets. Save-TMGServerFarm must then be executed to save the changes.
	.EXAMPLE
	New-TMGServerFarm -Name MySet
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($ServerFarm)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ServerFarm = $tmgarray.RuleElements.ServerFarms
	}

	$newsf = $ServerFarm.Add($Name)

	return $newsf
}

function Get-TMGServerFarms {
	Param( 
		[string]$Filter
	)

	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$ServerFarms = $tmgarray.RuleElements.ServerFarms

	if (-Not $Filter) { $Filter = "*" }
	
	$result = ForEach ($stn in ([array]$Filter -split ",")) {
		$ServerFarms | Where-Object {$_.Name -like $stn}
	}
		
	return $result | Sort-Object -Unique -Property PersistentName
}

function Remove-TMGServerFarm {
<#
	.SYNOPSIS
	Removes a TMG Server Farm with the specified name.
	.DESCRIPTION
	Uses COM to remove the specified TMG Server Farm on the array that this TMG server is a member of. TMG cannot delete a server farm if it is applied to a firewall policy rule.
	
	Remove-TMGServerFarm can be executed consecutively to create new sets. Save-TMGServerFarm must then be executed to save the changes.
	.PARAMETER EnumerateRules
	This switch will return web publishing rules which the server farm is assigned to. These can be inspected or piped into Remove-TMGRule.
	.PARAMETER Force
	This switch will force PoShTMG to automatically delete all web publishing rules which use this server farm then continue and delete the server farm object.
	.EXAMPLE
	Remove-TMGServerFarm -Name MySet
	If firewall rules are using the MySet server farm, an error will be printed and the matching firewall objects are returned.
	.EXAMPLE
	Remove-TMGServerFarm -Name MySet -EnumerateRules | Remove-TMGRule
	Firewall rules using the MySet server farm will be returned and piped into Remove-TMGRule. The ruleset will need to be manually saved.
	.EXAMPLE
	Remove-TMGServerFarm -Name MySet -Force
	Deletes the MySet server farm AND any firewall objects using it without confirmation.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[switch]$EnumerateRules,
		[switch]$Force
	)

	if (-not($ServerFarm)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ServerFarm = $tmgarray.RuleElements.ServerFarms
	}
	
	$refrules = Get-TMGWebPublishingRules | where {$_.WebPublishingProperties.LoadBalancingConfig.ServerFarm.Name -eq $Name}
	
	if ($EnumerateRules) { return $refrules }
	
	if (($refrules) -and (!$Force)) {
		Write-Error "This server farm cannot be deleted while it is used in TMG firewall policy rules. This farm is currently assigned to these rules:"
		return $refrules
	} elseif (($refrules) -and ($Force)) {
		$refrules | Remove-TMGRule
		Save-TMGRules
	}
	
	try {
		$ServerFarm.Remove($Name)
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function New-TMGComputerSet {
<#
	.SYNOPSIS
	Adds a TMG Computer Set with the specified name.
	.DESCRIPTION
	Uses COM to create the specified TMG Computer Set on the array that this TMG server is a member of.
	
	New-TMGComputerSet can be executed consecutively to create new sets. Save-TMGComputerSet must then be executed to save the changes.
	.EXAMPLE
	New-TMGComputerSet -Name MySet
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}

	$newcs = $ComputerSet.Add($Name)

	return $newcs
}

function Add-TMGServerToFarm {
<#
	.SYNOPSIS
	Adds an entry to the TMG Server Farm with the specified name.
	.DESCRIPTION
	Uses COM to add a name/address pair to the specified TMG Server Farm on the array that this TMG server is a member of.
	
	Add-TMGServerToFarm can be executed consecutively add new entries. Save-TMGServerFarm must then be executed to save the changes.
	.EXAMPLE
	Add-TMGServerToFarm -FarmName MySet -Server MYSERVER
	.PARAMETER Server
	The DNS name or IP address of the server to add to the farm.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$FarmName,
		[parameter(Mandatory=$true)] [string]$Server
	)

	if (-not($ServerFarm)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ServerFarm = $tmgarray.RuleElements.ServerFarms
	}
	
	if ( $ServerFarm.Item($FarmName).PublishedServers | where {$_.NameOrIP -eq $Server } ) {
		Write-Verbose "Element $Server exists."
		return
	}

	$newsvr = $ServerFarm.item($FarmName)
	$newsvr.PublishedServers.Add($Server)

	return $newsvr
}

function Remove-TMGServerFromFarm {
<#
	.SYNOPSIS
	Removes an entry from the TMG Server Farm with the specified name.
	.DESCRIPTION
	Uses COM to remove a name/address pair to the specified TMG Server Farm on the array that this TMG server is a member of.
	
	Remove-TMGServerFromFarm can be executed consecutively add new entries. Save-TMGServerFarm must then be executed to save the changes.
	.EXAMPLE
	Remove-TMGServerFromFarm -FarmName MySet -Server MYSERVER
	.PARAMETER Server
	The DNS name or IP address of the server to add to the farm.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$FarmName,
		[parameter(Mandatory=$true)] [string]$Server
	)

	if (-not($ServerFarm)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ServerFarm = $tmgarray.RuleElements.ServerFarms
	}
	
	try {
		$rmsvr = $ServerFarm.item($FarmName)
		$rmsvr.PublishedServers.Remove($Server)
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $rmsvr
}

function Remove-TMGComputerSet {
<#
	.SYNOPSIS
	Removes a TMG Computer Set with the specified name.
	.DESCRIPTION
	Uses COM to remove the specified TMG Computer Set on the array that this TMG server is a member of.

	Remove-TMGComputerSet can be executed consecutively to create new sets. Save-TMGComputerSet must then be executed to save the changes.
	.EXAMPLE
	Remove-TMGComputerSet -Name MySet
	.EXAMPLE
	Remove-TMGComputerSet -Name MySet -EnumerateRules
	Enumerates rules using the computer set.
	.EXAMPLE
	Remove-TMGComputerSet -Name MySet -Force
	Deletes the MySet computer set AND any firewall objects using it without confirmation.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[switch]$EnumerateRules,
		[switch]$Force
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}

	$refrules = @()
	$allrules = Get-TMGRules
	
	foreach ($rule in $allrules) {
		if ($rule.Type -eq 0) {
			$refrules += $rule | Where-Object { ($_.SourceSelectionIPs.ComputerSets.Exists($Name) -eq $true) -or ($_.AccessProperties.DestinationSelectionIPs.ComputerSets.Exists($Name) -eq $true) }
		} else {
			$refrules += $rule | Where-Object { ($_.SourceSelectionIPs.ComputerSets.Exists($Name) -eq $true) }
		}
	}

	if ($EnumerateRules) { return $refrules }
	
	if (($refrules) -and (!$Force)) {
		Write-Error "This computer set cannot be deleted while it is used in TMG firewall policy rules. This set is currently assigned to these rules:"
		return $refrules
	} elseif (($refrules) -and ($Force)) {
		$refrules | Remove-TMGRule
		Save-TMGRules
	}
	
	try {
		$ComputerSet.Remove($Name)
	} catch {
		Write-error $_.Exception.Message
		break
	}
		
}		
		
function Add-TMGEntryToComputerSet {
<#
	.SYNOPSIS
	Adds an entry to the TMG Computer Set with the specified name.
	.DESCRIPTION
	Uses COM to add a name/[address|network|range] pair to the specified TMG Computer Set on the array that this TMG server is a member of.
	
	Add-TMGEntryToComputerSet can be executed consecutively add new entries. Only one entry should be specified per command.
	
	Save-TMGComputerSet must then be executed to save the changes.
	.EXAMPLE
	Add-TMGEntryToComputerSet -SetName MySet -Name MYSERVER -HostAddress 192.168.1.1
	.EXAMPLE
	Add-TMGEntryToComputerSet -SetName MySet -Name MYSERVERNETWORK -SubnetAddress 192.168.1.1 -SubnetMask 255.255.255.0
	.EXAMPLE
	Add-TMGEntryToComputerSet -SetName MySet -Name MYSERVERNETWORK -RangeStart 192.168.1.1 -RangeEnd 192.168.1.50
#>
	Param(
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$Name,
		[string]$HostAddress,
		[string]$SubnetAddress,
		[string]$SubnetMask,
		[string]$RangeStart,
		[string]$RangeEnd
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}
	
	try {
		$newcmp = $ComputerSet.item($SetName)
		
		if ($HostAddress) {
			$newcmp.Computers.Add($Name,$HostAddress)
		}
		
		if ($SubnetAddress) {
			$newcmp.Subnets.Add($Name,$SubnetAddress,$SubnetMask)
		}
		
		if ($RangeStart) {
			$newcmp.AddressRanges.Add($Name,$RangeStart,$RangeEnd)
		}
		
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $newcmp
}

function Remove-TMGComputerFromSet {
<#
	.SYNOPSIS
	Removes an entry from the TMG Computer Set with the specified name.
	.DESCRIPTION
	Uses COM to remove a name/address pair from the specified TMG Computer Set on the array that this TMG server is a member of.
	
	Remove-TMGComputerFromSet can be executed consecutively add new entries. Save-TMGComputerSet must then be executed to save the changes.
	.EXAMPLE
	Remove-TMGComputerFromSet -SetName MySet -ClientName MYSERVER
	.PARAMETER ClientName
	Matches the Name field in the list of entries under a computer set.
#>
	Param(
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$ClientName
	)

	if (-not($ComputerSet)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ComputerSet = $tmgarray.RuleElements.ComputerSets
	}

	try {
		$rmcmp = $ComputerSet.item($SetName)
		$rmcmp.Computers.Remove($ClientName)
	} catch {
		Write-error $_.Exception.Message
		break
	}
	
	return $rmcmp
}

function Enable-TMGCompressibleContentType {
<#
	.SYNOPSIS
	Enables HTTP compression on a TMG Content Type set with the specified name.
	
	A content type set must be specified, not a content type. Content type sets can be viewed with Get-TMGContentTypeSet.
	.EXAMPLE
	Enable-TMGCompressibleContentType -Name TestType
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($HTTPCCT)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:HTTPCCT = $tmgarray.ArrayPolicy.WebProxy.HTTPCompressionConfiguration
	}
	
	try {
		$ncts = $HTTPCCT.CompressibleContentTypeSets.Add($Name,0)
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $ncts
}

function Disable-TMGCompressibleContentType {
<#
	.SYNOPSIS
	Disables HTTP compression on a TMG Content Type set with the specified name.
	
	A content type set must be specified, not a content type. Content type sets can be viewed with Get-TMGContentTypeSet.
	.EXAMPLE
	Disable-TMGCompressibleContentType -Name TestType
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($HTTPCCT)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:HTTPCCT = $tmgarray.ArrayPolicy.WebProxy.HTTPCompressionConfiguration
	}
	
	try {
		$tsa = [array]($HTTPCCT.CompressibleContentTypeSets | foreach { echo $_.Name.ToLower() } )
		$cctind = [array]::IndexOf($tsa,$Name.ToLower()) + 1
		$HTTPCCT.CompressibleContentTypeSets.Remove($cctind)
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function Add-TMGCompressibleSource {
<#
	.SYNOPSIS
	Enables HTTP compression on a TMG network object with the specified name.
	
	A predefined network object must be specified as the Source, and it's type as the SourceType.
	.EXAMPLE
	Add-TMGCompressibleSource -SourceType ComputerSet -Source 'Management PCs'
	.EXAMPLE
	Add-TMGCompressibleSource -SourceType ComputerSet -Source 'Management PCs' -Exception
	This command adds the source object as an exception. HTTP compression will not be applied to it.
#>
	Param(
		[parameter(Mandatory=$true)][ValidateSet('Network','NetworkSet','Computer','AddressRange','Subnet','ComputerSet','EnterpriseNetwork','WebListener')] [string]$SourceType,
		[parameter(Mandatory=$true)] [string]$Source,
		[switch]$Exception
	)

	if (-not($HTTPCCT)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:HTTPCCT = $tmgarray.ArrayPolicy.WebProxy.HTTPCompressionConfiguration
	}
	
	switch ($SourceType) {
		Network				{ $path = "RequestSource.Networks" }
		NetworkSet			{ $path = "RequestSource.NetworkSets" }
		Computer			{ $path = "RequestSource.Computers" }
		AddressRange		{ $path = "RequestSource.AddressRanges" }
		Subnet				{ $path = "RequestSource.Subnets" }
		ComputerSet			{ $path = "RequestSource.ComputerSets" }
		EnterpriseNetwork	{ $path = "RequestSource.EnterpriseNetworks" }
		WebListener			{ $path = "WebListeners" }
	}
	
	try {
		$ncts = Invoke-Expression "`$HTTPCCT.$path.Add('$Source',$([int][bool]$Exception))"
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $ncts
}

function Get-TMGCompressibleSource {
<#
	.EXAMPLE
	Get-TMGCompressibleSource -SourceType Computer
#>
	Param(
		[parameter(Mandatory=$true)][ValidateSet('Network','NetworkSet','Computer','AddressRange','Subnet','ComputerSet','EnterpriseNetwork','WebListener')] [string]$SourceType
	)

	if (-not($HTTPCCT)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:HTTPCCT = $tmgarray.ArrayPolicy.WebProxy.HTTPCompressionConfiguration
	}
	
	switch ($SourceType) {
		Network				{ $path = "RequestSource.Networks" }
		NetworkSet			{ $path = "RequestSource.NetworkSets" }
		Computer			{ $path = "RequestSource.Computers" }
		AddressRange		{ $path = "RequestSource.AddressRanges" }
		Subnet				{ $path = "RequestSource.Subnets" }
		ComputerSet			{ $path = "RequestSource.ComputerSets" }
		EnterpriseNetwork	{ $path = "RequestSource.EnterpriseNetworks" }
		WebListener			{ $path = "WebListeners" }
	}
	
	try {
		$ncts = Invoke-Expression "`$HTTPCCT.$path"
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $ncts
}

function Remove-TMGCompressibleSource {
<#
	.SYNOPSIS
	Disables HTTP compression on a TMG network object with the specified name.
	
	A predefined network object must be specified as the Source, and it's type as the SourceType.
	.EXAMPLE
	Remove-TMGCompressibleSource -SourceType ComputerSet -Source 'Management PCs'
#>
	Param( 
		[parameter(Mandatory=$true)][ValidateSet('Network','NetworkSet','Computer','AddressRange','Subnet','ComputerSet','EnterpriseNetwork','WebListener')] [string]$SourceType,
		[parameter(Mandatory=$true)] [string]$Source
	)

	if (-not($HTTPCCT)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:HTTPCCT = $tmgarray.ArrayPolicy.WebProxy.HTTPCompressionConfiguration
	}
	
	switch ($SourceType) {
		Network				{ $path = "RequestSource.Networks" }
		NetworkSet			{ $path = "RequestSource.NetworkSets" }
		Computer			{ $path = "RequestSource.Computers" }
		AddressRange		{ $path = "RequestSource.AddressRanges" }
		Subnet				{ $path = "RequestSource.Subnets" }
		ComputerSet			{ $path = "RequestSource.ComputerSets" }
		EnterpriseNetwork	{ $path = "RequestSource.EnterpriseNetworks" }
		WebListener			{ $path = "WebListeners" }
	}
		
	try {
		[array]$tsa = Invoke-Expression "`$HTTPCCT.$path" | foreach { echo $_.Name.ToLower() }
		$cctind = [array]::IndexOf($tsa,$Source.ToLower()) + 1
		Invoke-Expression "`$HTTPCCT.$path.Remove($cctind)"
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function New-TMGContentTypeSet {
<#
	.SYNOPSIS
	Adds a TMG Content Type set with the specified name.
	.EXAMPLE
	New-TMGContentTypeSet -Name TestType
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	try {
		$ncts = $ContentTypes.Add($Name)
	} catch {
		Write-error $_.Exception.Message
		break
	}

	return $ncts
}

function Get-TMGContentTypeSet {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, HelpMessage='The Filter to apply to the list of Rule Names.')] [string]$Filter
	)
	
	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	if (-Not $Filter) { $Filter = "*" }
	
	$result = @()
	
	ForEach ($stn in ([array]$Filter -split ",")) {
		$result += $ContentTypes | Where { $_.Name -like $stn } | select-object *
	}

	return $result | Sort-Object -Unique -Property PersistentName
}

function Remove-TMGContentTypeSet {
<#
	.SYNOPSIS
	Removes a TMG Content Type set with the specified name.
	.EXAMPLE
	Remove-TMGContentTypeSet -Name TestType
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	try {
		$ContentTypes.Remove($Name)
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function Add-TMGContentTypeToSet {
<#
	.SYNOPSIS
	Adds an entry to the TMG Content Type Set with the specified name.
	.DESCRIPTION
	Uses COM to add a type to the specified TMG Content Type Set on the array that this TMG server is a member of.
	
	Add-TMGContentTypeToSet can be executed consecutively add new entries. Save-TMGContentTypeSet must then be executed to save the changes.
	.EXAMPLE
	Add-TMGContentTypeToSet -SetName TestType -ContentType 'text/plain'
#>
	Param(
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$ContentType
	)

	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	try {
		$ncts = $ContentTypes.Item($SetName).Add($ContentType)
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function Get-TMGContentTypeFromSet {
	Param(
		[parameter(Mandatory=$true)] [string]$SetName
	)

	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	try {
		$ncts = $ContentTypes.Item($SetName)
	} catch {
		Write-error $_.Exception.Message
		break
	}
	
	return $ncts
}

function Remove-TMGContentTypeFromSet {
<#
	.SYNOPSIS
	Removes an entry from the TMG Content Type Set with the specified name.
	.EXAMPLE
	Remove-TMGContentTypeFromSet -SetName TestType -ContentType 'text/plain'
#>
	Param(
		[parameter(Mandatory=$true)] [string]$SetName,
		[parameter(Mandatory=$true)] [string]$ContentType
	)

	if (-not($ContentTypes)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ContentTypes = $tmgarray.RuleElements.ContentTypeSets
	}
	
	try {
		$ncts = $ContentTypes.Item($SetName).Remove($ContentType)
	} catch {
		Write-error $_.Exception.Message
		break
	}
}

function New-TMGStaticRoute {
<#
	.SYNOPSIS
	Adds an entry to the TMG Network Topology Routes list.
	.DESCRIPTION
	Uses COM to add a route to the TMG Network Topology Routes list on the array that this TMG server is a member of.
	
	Accepts dot-decimal notation only for all address parameters.
	
	New-TMGStaticRoute can be executed consecutively to create new routes. Save-TMGStaticRoute must then be executed to save the changes.
	.EXAMPLE
	New-TMGStaticRoute -Destination 192.168.5.128 -Mask 255.255.255.128 -Gateway 192.168.1.254 -Metric 16
	.PARAMETER Destination
	The network address of the destination network.
	.PARAMETER Mask
	The netmask of the destination.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Destination,
		[parameter(Mandatory=$true)] [string]$Mask,
		[parameter(Mandatory=$true)] [string]$Gateway,
		[int]$Metric = 256
	)

	if (-not($StRoute)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:StRoute = $tmgarray.StaticRoutes
	}
	
	#Remove route for destination if it already exists
	if ( $exstroute = $StRoute | where { ($_.Destination -eq $Destination) -and ($_.Subnet -eq $Mask) } ) {
		$exstroute.remove()
	}

	$newstrt = $StRoute.Add($Destination,$Mask,"",$Gateway)
	$newstrt.Metric = $Metric

	return $newstrt
}

function Get-TMGStaticRoute {
<#
	.SYNOPSIS
	Retrieves entries from the TMG Network Topology Routes list.
	.EXAMPLE
	Get-TMGStaticRoute
#>

	if (-not($StRoute)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:StRoute = $tmgarray.StaticRoutes
	}
	
	return $StRoute
}

function Remove-TMGStaticRoute {
<#
	.SYNOPSIS
	Removes an entry in the TMG Network Topology Routes list.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Destination
	)

	if (-not($StRoute)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:StRoute = $tmgarray.StaticRoutes
	}
	
	$exstroute = $StRoute | where { ($_.Destination -eq $Destination) }
	
	if ($exstroute) {
		$exstroute.remove()
	} else {
		Write-error "The specified route could not be bound."
	}
}

function Get-TMGProtocolDefinitions {
<#
	.SYNOPSIS
	Gets the TMG Protocol Definitions whose names match the specified Filter.
	.DESCRIPTION
	Uses COM to get the TMG Protocol Definitions from the Array that this TMG server is a member of, which match the specified Filter.
	.EXAMPLE
	Get-TMGProtocolDefinitions -Filter "Test *"
	.PARAMETER Filter
	The string you want to filter on. Leave blank or don't specify for no filtering.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, HelpMessage='The Filter to apply to the list of Rule Names.')] [string]$Filter
)
	$result = @()

	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$protocols = $tmgarray.RuleElements.ProtocolDefinitions
	
	#Set $Filter to * if not set
	if (-Not $Filter) {
		$Filter = "*"
	}
	
	ForEach ($protocol in $protocols) {
		if ($protocol.Name -Like $Filter) {
			$result += $protocol
		}
	}
	
	return $result
}

function New-TMGProtocolDefinition {
<#
	.SYNOPSIS
	Adds a TMG User-Defined Protocol object with the specified name.
	.DESCRIPTION
	Uses COM to create the TMG Protocol on the array that this TMG server is a member of, with the specified name.
	
	New-TMGProtocolDefinition can be executed consecutively to create new objects. Save-TMGProtocols must then be executed to save the changes.
	.EXAMPLE
	New-TMGProtocolDefinition -Name MySpecialProtocol
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($Protocol)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:Protocol = $tmgarray.RuleElements.ProtocolDefinitions
	}

	$newprot = $Protocol.Add($Name)

	return $newprot
}

function Add-TMGProtocolPort {
<#
	.SYNOPSIS
	Adds a TMG User-Defined Protocol port entry to the protocol with the specified name.
	.DESCRIPTION
	Uses COM to add a port to the specified TMG protocol on the array that this TMG server is a member of.
	
	Add-TMGProtocolPort can be executed consecutively to create new entries. Save-TMGProtocols must then be executed to save the changes.
	.PARAMETER Connection
	Primary | Secondary
	Places the protocol in the Primary or Secondary Connections box. A primary protocol must be defined before a secondary protocol can.
	.PARAMETER IPType
	ICMP | TCP | UDP | IPLevel
	.PARAMETER Direction
	If IPType is set to TCP - The options available are In | Out.
	If IPType is set to UDP - The options available are Receive | Send | ReceiveSend | SendReceive.
	If IPType is set to ICMP or IPLevel - The options available are Send | SendReceive.
	.PARAMETER IPLevelConnectionProtocol
	ICMP | IGMP | GGP | IP | ST | TCP | UDP | ICMPv6
	.EXAMPLE
	Add-TMGProtocolPort -Name MySpecialProtocol -Connection Primary -Direction In -IPType TCP -LowPort 110 -HighPort 120
	.EXAMPLE
	Add-TMGProtocolPort -Name MyRawProtocol -Connection Primary -Direction ReceiveSend -IPType IPLevel -IPLevelConnectionProtocol GGP
	.EXAMPLE
	Add-TMGProtocolPort -Name MyICMPProtocol -Connection Primary -Direction In -IPType ICMP -ICMPCode 0 -ICMPType 8
#>
	Param(
		[parameter(Mandatory=$true)][string]$Name,
		[parameter(Mandatory=$true)][ValidateSet("In","Out","Receive","Send","ReceiveSend","SendReceive")][string]$Direction,
		[parameter(Mandatory=$true)][ValidateSet("Primary","Secondary")][string]$Connection,
		[parameter(Mandatory=$true)][ValidateSet("ICMP","TCP","UDP","IPLevel")][string]$IPType,
		[ValidateSet("ICMP","IGMP","GGP","IP","ST","TCP","UDP","ICMPv6")][string]$IPLevelConnectionProtocol,
		[int]$LowPort,
		[int]$HighPort,
		[int]$ICMPCode,
		[int]$ICMPType
	)

	if (-not($Protocol)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:Protocol = $tmgarray.RuleElements.ProtocolDefinitions
	}
	
	$newprot = $Protocol.Item($Name)
	
	if ($Connection -eq "Primary") { $npcmd = $newprot.PrimaryConnections }
	if ($Connection -eq "Secondary") { $npcmd = $newprot.SecondaryConnections }
	
	switch ($IPType) {
		TCP { $npcmd.AddTCP(([int][ConnectionDirection]::$Direction),$LowPort,$HighPort) }
		UDP { $npcmd.AddUDP(([int][ConnectionDirection]::$Direction),$LowPort,$HighPort) }
		ICMP { $npcmd.AddICMP(([int][ConnectionDirection]::$Direction),$ICMPCode,$ICMPType) }
		IPLevel { $npcmd.AddRAW(([int][ConnectionDirection]::$Direction),([int][ConnectionProtocolType]::$IPLevelConnectionProtocol)) }
	}
	
	return $newprot
}

function Get-TMGWebListeners {
<#
	.SYNOPSIS
	Gets the TMG Web Listeners whose names match the specified Filter.
	.DESCRIPTION
	Uses COM to get the TMG Web Listeners from the Array that this TMG server is a member of, which match the specified Filter.
	.EXAMPLE
	Get-TMGWebListeners -Filter "Test *"
	.PARAMETER Filter
	The string you want to filter on. Leave blank or don't specify for no filtering.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, HelpMessage='The Filter to apply to the list of Rule Names.')] [string]$Filter
)
	$result = @()

	if (-not($WebListener)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:WebListener = $tmgarray.RuleElements.WebListeners
	}
	
	#Set $Filter to * if not set
	if (-Not $Filter) {
		$Filter = "*"
	}
	
	ForEach ($listener in $weblistener) {
		if ($listener.Name -Like $Filter) {
			$result += $listener
		}
	}
	
	return $result
}

function New-TMGWebListener {
<#
	.SYNOPSIS
	Creates a TMG Web Listener with the specified name.
	.DESCRIPTION
	Uses COM to create the specified TMG Web Listener on the array that this TMG server is a member of.
	
	New-TMGWebListener can be executed consecutively to create new rules. Save-TMGWebListener must then be executed to save the changes.
	.EXAMPLE
	New-TMGWebListener -Name MyWL -ClientAuthentication NoAuth -ListeningIP 1.2.2.1 -HTTPPort 81 
	.PARAMETER ClientAuthentication
	Client Authentication Method.
	NoAuth | IfAuthenticated | Always
	.PARAMETER RedirectHTTPAsHTTPS
	Disabled | IfAuthenticated | Always
	.PARAMETER HTTPPort
	Client connections port number.
	If set connections are enabled on the port number.
	Set to 0 to disable.
	.PARAMETER SSLPort
	Client connections port number.
	If set connections are enabled on the port number.
	Set to 0 to disable.
	.PARAMETER SourceNetworkName
	Specify the name of the network object to listen on. If not specified, the new listener will bind to the External network and listen on all IPs.
	.PARAMETER ListeningForRequests
	Sets the listener IP address binding type.
	All | Default | Specified
	All - the listener will bind to all IPs on the SourceNetworkName network.
	Default - the default IP - eg. if load balancing is configured the VIP will be chosen.
	Specified - the listener binds to the address specified by ListeningIP.
	.PARAMETER ListeningIP
	Binds the listener to a specified IP. This must be used with the SourceNetworkName set and ListeningForRequests set to Specified.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[ValidateSet("NoAuth","HTTP","HTMLForm")] [string]$ClientAuthentication,
		[ValidateSet("Disabled","IfAuthenticated","Always")][string]$RedirectHTTPAsHTTPS,
		[ValidateSet("All","Default","Specified")][string]$ListeningForRequests,
		[string]$SourceNetworkName,
		[string]$ListeningIP,
		[string]$CustomFormsDirectory,
		[string]$SSODomainNames,
		[string]$CertThumbprint,
		[int]$SSLPort,
		[int]$HTTPPort = 80,
		[int]$MaxConnections,
		[int]$SSLClientCertificateTimeout,
		[int]$ConnectionTimeout,
		[switch]$UnlimitedNumberOfConnections,
		[bool]$SSOEnabled = 0,
		[bool]$SSLClientCertificateTimeoutEnabled,
		[int]$FormAuthenticationPublicTimeOut,
		[int]$FormAuthenticationPrivateTimeOut,
		[bool]$FormAuthenticationCookieValidationIgnoreIP
	)

	if (-not($WebListener)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:WebListener = $tmgarray.RuleElements.WebListeners
	}
	
	try {
		if ( $WebListener.Item("$Name") ) {
			Write-Verbose "Listener $Name already exists."
			return
		}
	} catch {}

	$newlistener = $WebListener.Add("$Name")
	$newlistener.Properties.TCPPort = $HTTPPort
	$newlistener.Properties.SSOEnabled = $SSOEnabled
	$newlistener.Properties.SSLPort = $SSLPort
	$newlistener.Properties.SSLClientCertificateTimeoutEnabled = $SSLClientCertificateTimeoutEnabled

	if ($MaxConnections) { $newlistener.Properties.NumberOfConnections = $MaxConnections }
	if ($SSLClientCertificateTimeout) { $newlistener.Properties.SSLClientCertificateTimeout = $SSLClientCertificateTimeout }
	if ($ConnectionTimeout) { $newlistener.Properties.ConnectionTimeout = $ConnectionTimeout }
	if ($SSODomainNames) {$newlistener.Properties.SSOEnabled = 1; $newlistener.Properties.SSODomainNames.Add($SSODomainNames)}
	if ($RedirectHTTPAsHTTPS) {$newlistener.Properties.RedirectHTTPAsHTTPS = [int][RedirectHTTPAsHTTPS]::$RedirectHTTPAsHTTPS}

	switch ($ClientAuthentication) {
		NoAuth {
			$newlistener.Properties.IntegratedWindowsAuthentication = 0
		}
		HTTP { <# DEFAULT #> }
		HTMLForm {
			$newlistener.Properties.IntegratedWindowsAuthentication = 0
			$newlistener.Properties.AuthenticationSchemes.Add("FBA with AD",0)
			$newlistener.Properties.FormsBasedAuthenticationProperties.CustomFormsDirectory = $CustomFormsDirectory
			
			if ($FormAuthenticationPublicTimeOut)  {$newlistener.Properties.FormsBasedAuthenticationProperties.SessionTimeOutForPublicComputers = $FormAuthenticationPublicTimeOut}
			if ($FormAuthenticationPrivateTimeOut)  {$newlistener.Properties.FormsBasedAuthenticationProperties.SessionTimeOutForTrustedComputers = $FormAuthenticationPrivateTimeOut}
			$newlistener.Properties.FormsBasedAuthenticationProperties.ClientIPAddressSigningEnabled = !$FormAuthenticationCookieValidationIgnoreIP	#NOT is to flip the variable to solve Double Negative. Our Parameter is named to match the GUI rather than the API which is "backwards"
		}
	}

	if (-not($SourceNetworkName)) {
		$newlistener.IPsOnNetworks.Add("External",0,"")
		} else {
		$newlistener.IPsOnNetworks.Add($SourceNetworkName,[int][IPSelectionMethod]::$ListeningForRequests,$ListeningIP)
	}
	
	if ($CertThumbprint) {
		$certhash = (gci cert:\LocalMachine\my\$CertThumbprint).getcerthash()
		$newlistener.Properties.AppliedSSLCertificates.Add($certhash,"")
	}

	if ($UnlimitedNumberOfConnections) {
		$newlistener.Properties.UnlimitedNumberOfConnections = 1
	}

	return $newlistener
}

function Set-TMGWebListener {
<#
	.SYNOPSIS
	Modifies a TMG Web Listener with the specified name.
	.DESCRIPTION
	Uses COM to modify the specified TMG Web Listener on the array that this TMG server is a member of.
	
	Set-TMGWebListener can be executed consecutively to modify rules. Save-TMGWebListener must then be executed to save the changes.
	.EXAMPLE
	Set-TMGWebListener -Name MyWL -ClientAuthentication NoAuth -ListeningIP 1.2.2.1 -HTTPPort 81 
	.PARAMETER ClientAuthentication
	Client Authentication Method.
	NoAuth | IfAuthenticated | Always
	.PARAMETER RedirectHTTPAsHTTPS
	Disabled | IfAuthenticated | Always
	.PARAMETER HTTPPort
	Client connections port number.
	If set connections are enabled on the port number.
	Set to 0 to disable.
	.PARAMETER SSLPort
	Client connections port number.
	If set connections are enabled on the port number.
	Set to 0 to disable.
	.PARAMETER SourceNetworkName
	Specify the name of the network object to listen on. If not specified, the new listener will bind to the External network and listen on all IPs.
	.PARAMETER ListeningForRequests
	Sets the listener IP address binding type.
	All | Default | Specified
	All - the listener will bind to all IPs on the SourceNetworkName network.
	Default - the default IP - eg. if load balancing is configured the VIP will be chosen.
	Specified - the listener binds to the address specified by ListeningIP.
	.PARAMETER ListeningIP
	Binds the listener to a specified IP. This must be used with the SourceNetworkName set and ListeningForRequests set to Specified.
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name,
		[ValidateSet("NoAuth","HTTP","HTMLForm")] [string]$ClientAuthentication,
		[ValidateSet("Disabled","IfAuthenticated","Always")][string]$RedirectHTTPAsHTTPS,
		[ValidateSet("All","Default","Specified")][string]$ListeningForRequests,
		[string]$NewName,
		[string]$SourceNetworkName,
		[string]$ListeningIP,
		[string]$CustomFormsDirectory,
		[string]$SSODomainNames,
		[string]$CertThumbprint,
		[int]$SSLPort,
		[int]$HTTPPort = 80,
		[int]$MaxConnections,
		[int]$SSLClientCertificateTimeout,
		[int]$ConnectionTimeout,
		[switch]$UnlimitedNumberOfConnections,
		[bool]$SSOEnabled = 0,
		[bool]$SSLClientCertificateTimeoutEnabled,
		[int]$FormAuthenticationPublicTimeOut,
		[int]$FormAuthenticationPrivateTimeOut,
		[bool]$FormAuthenticationCookieValidationIgnoreIP
	)

	if (-not($WebListener)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:WebListener = $tmgarray.RuleElements.WebListeners
	}
	
	try {
		$modlistener = $WebListener.Item($Name)
	} catch {
		Write-Verbose "Listener $Name cannot be bound. Does it exist?"
		return
	}
	
	if ($PSBoundParameters.ContainsKey('NewName')) { $modlistener.Name = $NewName }
	if ($PSBoundParameters.ContainsKey('SSLPort')) { $modlistener.Properties.SSLPort = $SSLPort }
	if ($PSBoundParameters.ContainsKey('HTTPPort')) { $modlistener.Properties.TCPPort = $HTTPPort }
	if ($PSBoundParameters.ContainsKey('UnlimitedNumberOfConnections')) { $modlistener.Properties.UnlimitedNumberOfConnections = 1 }
	if ($PSBoundParameters.ContainsKey('SSOEnabled')) { $modlistener.Properties.SSOEnabled = $SSOEnabled }
	if ($PSBoundParameters.ContainsKey('SSLClientCertificateTimeoutEnabled')) { $modlistener.Properties.SSLClientCertificateTimeoutEnabled = $SSLClientCertificateTimeoutEnabled }
	if ($PSBoundParameters.ContainsKey('MaxConnections')) { $modlistener.Properties.NumberOfConnections = $MaxConnections }
	if ($PSBoundParameters.ContainsKey('SSLClientCertificateTimeout')) { $modlistener.Properties.SSLClientCertificateTimeout = $SSLClientCertificateTimeout }
	if ($PSBoundParameters.ContainsKey('ConnectionTimeout')) { $modlistener.Properties.ConnectionTimeout = $ConnectionTimeout }
	if ($PSBoundParameters.ContainsKey('SSODomainNames')) {$modlistener.Properties.SSOEnabled = 1; $modlistener.Properties.SSODomainNames.Add($SSODomainNames)}
	if ($PSBoundParameters.ContainsKey('RedirectHTTPAsHTTPS')) {$modlistener.Properties.RedirectHTTPAsHTTPS = [int][RedirectHTTPAsHTTPS]::$RedirectHTTPAsHTTPS}
	if ($PSBoundParameters.ContainsKey('SourceNetworkName')) { $modlistener.IPsOnNetworks.Add($SourceNetworkName,[int][IPSelectionMethod]::$ListeningForRequests,$ListeningIP) }

	switch ($ClientAuthentication) {
		NoAuth {
			$modlistener.Properties.IntegratedWindowsAuthentication = 0
		}
		HTTP { <# DEFAULT #> }
		HTMLForm {
			$modlistener.Properties.IntegratedWindowsAuthentication = 0
			$modlistener.Properties.AuthenticationSchemes.Add("FBA with AD",0)
			$modlistener.Properties.FormsBasedAuthenticationProperties.CustomFormsDirectory = $CustomFormsDirectory

			if ($PSBoundParameters.ContainsKey('FormAuthenticationPublicTimeOut'))  {$modlistener.Properties.FormsBasedAuthenticationProperties.SessionTimeOutForPublicComputers = $FormAuthenticationPublicTimeOut}
			if ($PSBoundParameters.ContainsKey('FormAuthenticationPrivateTimeOut'))  {$modlistener.Properties.FormsBasedAuthenticationProperties.SessionTimeOutForTrustedComputers = $FormAuthenticationPrivateTimeOut}
			$modlistener.Properties.FormsBasedAuthenticationProperties.ClientIPAddressSigningEnabled = !$FormAuthenticationCookieValidationIgnoreIP	#NOT is to flip the variable to solve Double Negative. Our Parameter is named to match the GUI rather than the API which is "backwards"
		}
	}

	if ($CertThumbprint) {
		$certhash = (gci cert:\LocalMachine\my\$CertThumbprint).getcerthash()
		$modlistener.Properties.AppliedSSLCertificates.Add($certhash,"")
	}

	return $modlistener
}

function Remove-TMGWebListener {
<#
	.SYNOPSIS
	Deletes a TMG Web Listener with the specified name.
	.DESCRIPTION
	Uses COM to delete the specified TMG Web Listener on the array that this TMG server is a member of.
	
	Remove-TMGWebListener can be executed consecutively to delete rules. Save-TMGWebListener must then be executed to save the changes.
	.EXAMPLE
	Remove-TMGWebListener -Name MyWL
#>
	Param( 
		[parameter(Mandatory=$true)] [string]$Name
	)

	if (-not($WebListener)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:WebListener = $tmgarray.RuleElements.WebListeners
	}
	
	# Remove rules using this listener if it already exists
	$refrules = Get-TMGWebPublishingRules | where {$_.WebPublishingProperties.WebListenerUsed.Name -eq $Name}
	
	if ($refrules) {
		foreach ($rule in $refrules) {
			Remove-TMGWebPublishingRule -Name $rule.Name
		}
	
		Save-TMGRules
		
		# Try restarting the service if there is an issue with saving rules (config is screwed) after this change
		# Restart-Service isactrl -Force
		# You'll need to reinitialise the objects too??
	}
	
	try {
		$delwl = $WebListener.Remove($Name)
	} catch {
		Write-error $_.Exception.Message
		break
	}
	
	return $delwl
}

function Add-TMGIPRangeToNetwork {
<#
	.SYNOPSIS
	Adds an IP range to the specified TMG Network object.
	.DESCRIPTION
	Uses COM to add an IP range to a TMG Network on the array that this TMG server is a member of.
	
	Add-TMGIPRangeToNetwork can be executed consecutively to create new entries. Save-TMGNetworkConfiguration must then be executed to save the changes.
	.EXAMPLE
	Add-TMGIPRangeToNetwork -NetworkName Internal -LowIP 192.168.6.12 -HighIP 192.168.6.80
	.EXAMPLE
	Add-TMGIPRangeToNetwork -NetworkName SecretNetwork -LowIP 192.168.7.12 -HighIP 192.168.8.90
#>
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

	return $newrange
}

function Add-TMGAdapterRangeToNetwork {
<#
	.SYNOPSIS
	Automatically adds an IP range taken from a network adaprot to the specified TMG Network object.
	.DESCRIPTION
	Uses COM to gather network data from the specified ethernet adapter then add it's IP range to a TMG Network on the array that this TMG server is a member of.
	
	Available adapter names can be gathered via the GUI - Networking > Network Adapters.
	
	Add-TMGAdapterRangeToNetwork can be executed consecutively to create new entries. Save-TMGNetworkConfiguration must then be executed to save the changes.
	.EXAMPLE
	Add-TMGAdapterRangeToNetwork -NetworkName Internal -AdapterName Ethernet
	.EXAMPLE
	Add-TMGAdapterRangeToNetwork -NetworkName Internal -AdapterName MyVLAN63Adapter
#>
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
		try {
			$newrange.IPRangeSet.Add(($elem | foreach {$_.IP_From}),($elem | foreach {$_.IP_To}))
		} catch	[System.Management.Automation.RuntimeException] {
			Write-Verbose "Object already exists"
		}
	}

	return $newrange
}

function Set-TMGFailedLogonAttemptFix {
<#
	.SYNOPSIS
	Fixes failed logon attempt logging to the TMG logger.
	.DESCRIPTION
	In TMG RTM:
	"This issue occurs when an authentication attempt that is made to TMG fails. When this occurs, the request is handled as an anonymous request and will appear in the web proxy logs with the username logged as Anonymous."
	https://support.microsoft.com/en-us/kb/2592929
	
	This fix will still return 'anonymous' on attempted authentication to disabled accounts in Active Directory.
#>
	
	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$flavps = $tmgarray.VendorParametersSets
	
	try {
		if ($flavps.Item("{143F5698-103B-12D4-FF34-1F34767DEabc}")) {
			return "Set-TMGFailedLogonAttemptFix has already been applied."
		}
	} catch {}
	
	Write-Host "Executing Set-TMGFailedLogonAttemptFix"
	$flafix = $flavps.Add("{143F5698-103B-12D4-FF34-1F34767DEabc}")
	$flafix.Value("LogUsernameForFailedAuthentication") = 1
	
	Write-Host "Saving..."
	$flavps.Save()
	WaitForSync
	
	return $flafix
}

function Set-TMGFloodMitigation {
<#
	.SYNOPSIS
	
	.DESCRIPTION
	
	.EXAMPLE
	
	.PARAMETER Filter
	
#>
[CmdletBinding(DefaultParametersetName="DefaultLimit")]
param
( 
	# Int.MinValue is horrible but it's the only way because PowerShell won't tell
	# you if a Parameter has been _set_ or not (other than switches via IsPresent).
    [Parameter(Mandatory=$false)] [int]$Enabled = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$LogQuotaRejectedTraffic = $([int]::MinValue),

    [Parameter(Mandatory=$false)] [int]$DefaultUDPLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$DefaultTCPLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$DefaultOtherLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$DefaultTCPLimitPerMinute = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$DefaultHTTPLimitPerMinute = $([int]::MinValue),
    
	[Parameter(Mandatory=$false)] [int]$SpecialUDPLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$SpecialTCPLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$SpecialOtherLimit = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$SpecialTCPLimitPerMinute = $([int]::MinValue),
    [Parameter(Mandatory=$false)] [int]$SpecialHTTPLimitPerMinute = $([int]::MinValue)
)

	if (-not($ConnLimit)) {
		$fpcroot = New-Object -ComObject fpc.root
		$tmgarray = $fpcroot.GetContainingArray()
		$global:ConnLimit = $tmgarray.ArrayPolicy.ConnectionLimitPolicy
	}

	if ($Enabled -ge 0) {
		$ConnLimit.Enabled = $Enabled
	}
	if ($LogQuotaRejectedTraffic -ge 0) {
		$ConnLimit.LogQuotaRejectedTraffic = $LogQuotaRejectedTraffic
	}

	if ($DefaultUDPLimit -ge 0) {
		$ConnLimit.DefaultLimit.UDPLimit = $DefaultUDPLimit
	}
	if ($DefaultTCPLimit -ge 0) {
		$ConnLimit.DefaultLimit.TCPLimit = $DefaultTCPLimit
	}
	if ($DefaultOtherLimit -ge 0) {
		$ConnLimit.DefaultLimit.OtherLimit = $DefaultOtherLimit
	}
	if ($DefaultTCPLimitPerMinute -ge 0) {
		$ConnLimit.DefaultLimit.TCPLimitPerMinute = $DefaultTCPLimitPerMinute
	}
	if ($DefaultHTTPLimitPerMinute -ge 0) {
		$ConnLimit.DefaultLimit.HTTPLimitPerMinute = $DefaultHTTPLimitPerMinute
	}
	
	if ($SpecialUDPLimit -ge 0) {
		$ConnLimit.SpecialLimit.UDPLimit = $SpecialUDPLimit
	}
	if ($SpecialTCPLimit -ge 0) {
		$ConnLimit.SpecialLimit.TCPLimit = $SpecialTCPLimit
	}
	if ($SpecialOtherLimit -ge 0) {
		$ConnLimit.SpecialLimit.OtherLimit = $SpecialOtherLimit
	}
	if ($SpecialTCPLimitPerMinute -ge 0) {
		$ConnLimit.SpecialLimit.TCPLimitPerMinute = $SpecialTCPLimitPerMinute
	}
	if ($SpecialHTTPLimitPerMinute -ge 0) {
		$ConnLimit.SpecialLimit.HTTPLimitPerMinute = $SpecialHTTPLimitPerMinute
	}
	
	Write-Host "`nWhen you're finished, run Save-TMGFloodMitigationConfiguration to save your changes`n"
}

function Export-TMGArrayConfiguration {
Param(
	[Parameter(Mandatory=$true, position=0)] [string]$FilePath,
	[Parameter(Mandatory=$false, position=1)] [ValidateSet("None", "Passwords", "UserPermissions", "ServerSpecific", "EnterpriseSpecific")] [string]$OptionalData = "None",
	[Parameter(Mandatory=$false, position=2)] [string]$Password
)
	$OptionalDataFlags = ([int][ExportImportOptionalData]::($OptionalData))

	$fpcroot = New-Object -ComObject fpc.root
	$tmgarray = $fpcroot.GetContainingArray()
	$tmgarray.ExportToFile( $FilePath, $OptionalDataFlags, $Password )	
}

function Save-TMGFloodMitigationConfiguration {
	if (-not($ConnLimit)) {throw "Nothing to save"}
	try { $ConnLimit.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGWebListener {
	if (-not($WebListener)) {throw "Nothing to save"}
	try { $WebListener.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
	Clear-Variable WebListener
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
	Clear-Variable PolicyRules
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

function Save-TMGServerFarm {
	if (-not($ServerFarm)) {throw "Nothing to save"}
	try { $ServerFarm.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGContentTypeSet {
	if (-not($ContentTypes)) {throw "Nothing to save"}
	try { $ContentTypes.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Save-TMGCompressibleContent {
	if (-not($HTTPCCT)) {throw "Nothing to save"}
	try { $HTTPCCT.Save() }
	catch { throw $_.Exception.Message }
	write-host "Saving..."
	WaitForSync
}

function Clear-TMGFloodMitigationConfiguration {
<#
	.SYNOPSIS
	Clears the unsaved TMG Flood Mitigation Configuration settings in this session.
#>
	Remove-Variable -Name ConnLimit -Scope global
}

function Clear-TMGWebListener {
<#
	.SYNOPSIS
	Clears the unsaved TMG Web Listeners in this session.
#>
	Remove-Variable -Name WebListener -Scope global
}

function Clear-TMGComputerSet {
<#
	.SYNOPSIS
	Clears the unsaved TMG Computer Sets in this session.
#>
	Remove-Variable -Name ComputerSet -Scope global
}

function Clear-TMGRules {
<#
	.SYNOPSIS
	Clears the unsaved TMG Policy Rules in this session.
#>
	Remove-Variable -Name PolicyRules -Scope global
}

function Clear-TMGProtocols {
<#
	.SYNOPSIS
	Clears the unsaved TMG Protocols in this session.
#>
	Remove-Variable -Name Protocol -Scope global
}

function Clear-TMGStaticRoute {
<#
	.SYNOPSIS
	Clears the unsaved TMG Static Routes in this session.
#>
	Remove-Variable -Name StRoute -Scope global
}

function Clear-TMGNetworkConfiguration {
<#
	.SYNOPSIS
	Clears the unsaved TMG Network Configuration settings in this session.
#>
	Remove-Variable -Name NetworkConf -Scope global
}

function Clear-TMGServerFarm {
<#
	.SYNOPSIS
	Clears the unsaved TMG Protocols in this session.
#>
	Remove-Variable -Name ServerFarm -Scope global
}

#### PRIVATE FUNCTIONS ####

function WaitForSync {

	if (-not($TMGServer)) {
		$fpcroot = New-Object -ComObject fpc.root
		$global:TMGServer = $fpcroot.GetContainingServer()
	}

	sleep 10
	Write-Host "Waiting for sync..."
	$synctries = 0
	do {
		$synctries++
		$TMGServer.DistributionStatus.Refresh()
		sleep 3
	}
	while ( ($TMGServer.DistributionStatus.Status -lt 2) -and ($synctries -lt 100) )
	
	if ($TMGServer.DistributionStatus.Status -eq 2) {
		Return "Configuration synced!"
	} elseif ($synctries -eq 100) {
		Throw "Timed out waiting for TMG to update it's configuration."
	} elseif ($TMGServer.DistributionStatus.Status -eq 3) {
		Throw "The sync process did not complete. This could mean the configuration is invalid - check Monitoring in the GUI console for errors."
	}
}

export-modulemember *-*