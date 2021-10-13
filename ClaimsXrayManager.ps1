Param(
  [switch] $SkipSetup
  )
$global:SelRP = $null
$global:SelOp = $null
  
$dateObj = Get-Date
$Logfile = $PWD.Path + "\ClaimsXray_"+$dateObj.Year+$dateObj.Month+$dateObj.Day+$dateObj.Hour+$dateObj.Minute+$dateObj.Second+".log"
$defaultIssuanceRule = "@RuleName = `"Issue all claims`"`nx:[]=>issue(claim = x); "
$defaultAuthzRules = "=>issue(Type = `"http://schemas.microsoft.com/authorization/claims/permit`", Value = `"true`"); "

$allClaimRules = "Default: Issue all claims"
$copyToXray = "Copy claims to Claims X-Ray"
$copyFromXray = "Copy claims from Claims X-Ray"
        
Function LogWrite 
{
   Param (
    [switch]$Err,
    [switch]$Success,
    [switch]$LogOnly,
    [string]$logstring
    
   )
   
   if ($LogOnly -eq $false) {
       if ($err) 
	   { 
		Write-Host -ForegroundColor Red $logstring
       }
       elseif ($success) 
	   {
		Write-Host -ForegroundColor Green $logstring
	   }
       else 
	   {
		Write-Host $logstring
	   } 
   }
   
   Add-content $Logfile -value $logstring
}

$claimsXRayName = "ClaimsXray"
$claimsXRayIdentifier = "urn:microsoft:adfs:claimsxray"

if ($SkipSetup -eq $false) {
	LogWrite "Checking current configuration..."
	
    ##################################################################
    #
    # Verify that the ADFS Server service is running.  
    #
    ##################################################################
    LogWrite "  - Verifying that the AD FS service is running..."
    $srvc = Get-Service -Name "adfssrv"
    if ($srvc.Status.ToString().ToLower() -ne "running") {
        LogWrite -Err "AD FS service is not running on this box. Please execute the script on the primary AD FS server"
        exit 100
    }

    ##################################################################
    #
    # Configure the Claims X-Ray RP and oAuth client
    #
    ##################################################################

    LogWrite "  - Checking to see if the Claims X-Ray RP is already configured..."

    $claimsXRayRP = Get-AdfsRelyingPartyTrust -Name $claimsXRayName
    if ($claimsXRayRP -eq $null) {
        LogWrite "    - The Claims X-Ray RP is not configured."
        LogWrite "    - Creating the Claims X-Ray RP..."

        $authzRules = $defaultAuthzRules
        $issuanceRules = $defaultIssuanceRule
        $redirectUrl = "https://adfshelp.microsoft.com/ClaimsXray/TokenResponse"
        $samlEndpoint = New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $redirectUrl

        Add-ADFSRelyingPartyTrust -Name $claimsXRayName -Identifier $claimsXRayIdentifier -IssuanceAuthorizationRules $authzRules -IssuanceTransformRules $issuanceRules -WSFedEndpoint $redirectUrl -SamlEndpoint $samlEndpoint
    }
    LogWrite "    - Claims X-Ray RP configured."

    LogWrite "  - Checking to see if the Claims X-Ray oAuth client is configured..."

	if (([System.Environment]::OSVersion.Version.major -lt 6) -or 
		(([System.Environment]::OSVersion.Version.major -eq 6) -and ([System.Environment]::OSVersion.Version.minor -lt 3)))
	{
			LogWrite "    - Windows Server version doesn't support oAuth."
	}
	else
	{
		$claimsXRayClient = Get-AdfsClient -ClientId "claimsxrayclient"
		if ($claimsXRayClient -eq $null)
		{
			LogWrite "    - The Claims X-Ray oAuth client is not configured."
			LogWrite "    - Creating the Claims X-Ray oAuth client..."

			Add-AdfsClient -Name "ClaimsXrayClient" -ClientId "claimsxrayclient" -RedirectUri https://adfshelp.microsoft.com/ClaimsXray/TokenResponse
			if ([System.Environment]::OSVersion.Version.major -gt 6) 
			{ 
				Grant-AdfsApplicationPermission -ServerRoleIdentifier $claimsXRayIdentifier -AllowAllRegisteredClients -ScopeNames "openid","profile" 
			}
		}    
		LogWrite "    - Claims X-Ray oAuth Client configured."
	}
}

##################################################################
#
# Get the AD FS Relying party trusts.
#
##################################################################

LogWrite "  - Getting the current RP trusts..."
	
$AllRPS = Get-ADFSRelyingPartyTrust
$HostName = (Get-ADFSProperties).hostname.ToString()
$RPIdentifiers  = @()
LogWrite ("    - Number of RP trusts found: " + $AllRPS.Count)
foreach ($RPitem in $AllRPs){
    $RPIdentifiers += $RPItem.Name
    LogWrite -LogOnly $RPitem.Name
}

##################################################################
#
# Show the UI to select the UI
#
##################################################################

#Import the Assemblies
Add-Type -AssemblyName System.Windows.Forms
  
#Form Objects
$Form = New-Object system.Windows.Forms.Form
$comboBoxOperation = New-Object system.windows.Forms.ComboBox
$labelOperation = New-Object system.windows.Forms.Label
$labelRP = New-Object system.windows.Forms.Label
$comboBoxRP = New-Object system.windows.Forms.ComboBox
$buttonOk = New-Object system.windows.Forms.Button

##################################################################
#
# Event Script Blocks
#
##################################################################

$buttonOK_OnClick=
{
    $global:SelRP = $comboBoxRP.SelectedItem
    $global:SelOp = $comboBoxOperation.SelectedItem
    $Form.close()
}
     
$OnLoadForm_StateCorrection=
{
	#Correct the initial state of the form to prevent the .Net maximized form issue
    $Form.WindowState = $InitialFormWindowState

    $RPIdentifiers | Foreach {
        $comboBoxRP.items.add($_)
        $comboBoxRP.SelectedIndex=0
    }
    $comboBoxRP.visible = $true
    $labelRP.visible = $true
    $buttonOK.visible = $true
    $comboBoxOperation.Visible = $true
    $Form.Text = "ADFS Help Claims X-Ray Manager"
}

##################################################################
#
# Generating UI
#
##################################################################  

$Form.Text = "Form"
$Form.TopMost = $true
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $false
$Form.Width = 500
$Form.Height = 180

$comboBoxOperation.Text = ""
$comboBoxOperation.Width = 336
$comboBoxOperation.Height = 20
$comboBoxOperation.location = new-object system.drawing.point(134,13)
$comboBoxOperation.Font = "Segoe UI,10"
$comboBoxOperation.Items.Add($copyToXray) | Out-Null
$comboBoxOperation.Items.Add($copyFromXray) | Out-Null
$comboBoxOperation.SelectedIndex = 0
$Form.controls.Add($comboBoxOperation)

$labelOperation.Text = "Select Operation"
$labelOperation.AutoSize = $true
$labelOperation.Width = 25
$labelOperation.Height = 10
$labelOperation.location = new-object system.drawing.point(7,12)
$labelOperation.Font = "Segoe UI,10"
$Form.controls.Add($labelOperation)

$labelRP.Text = "Select Relying Party"
$labelRP.AutoSize = $true
$labelRP.Width = 25
$labelRP.Height = 10
$labelRP.location = new-object system.drawing.point(6,49)
$labelRP.Font = "Segoe UI,10"
$Form.controls.Add($labelRP)

$comboBoxRP.Text = ""
$comboBoxRP.Width = 336
$comboBoxRP.Height = 20
$comboBoxRP.location = new-object system.drawing.point(135,48)
$comboBoxRP.Items.Add($allClaimRules) | Out-Null
$comboBoxRP.Font = "Segoe UI,10"
$comboBoxRP.SelectedIndex = 0
$Form.controls.Add($comboBoxRP)

$buttonOk.Text = "Apply changes"
$buttonOk.Width = 150
$buttonOk.Height = 30
$buttonOk.Add_MouseClick(
    $buttonOK_OnClick
)
$buttonOk.location = new-object system.drawing.point(160,100)
$buttonOk.Font = "Segoe UI,10"
$Form.controls.Add($buttonOk)

##################################################################
#
# Save the initial state of the form
#
##################################################################    
$InitialFormWindowState = $Form.WindowState
#Init the OnLoad event to correct the initial state of the form
$Form.add_Load($OnLoadForm_StateCorrection)
  
#Show the Form
$Form.ShowDialog()| Out-Null

if ([string]::IsNullOrEmpty($global:SelRP) -or [string]::IsNullOrEmpty($global:SelOp))
{
    LogWrite "User canceled the operation."
    exit 0
}

LogWrite ("Selected Operation: " + $SelOp)
LogWrite ("Selected RP: " + $SelRP)
$sourceRP = ""
$targetRP = ""

if (($global:SelOp -eq $copyFromXray) -and ($global:SelRP -eq $allClaimRules))
{
	LogWrite "Cannot copy All Claims from Claims X-Ray"
	exit 1
}
  
if ($SelOp -eq $copyToXray) 
{
    $sourceRP = $SelRP
    $targetRP = $claimsXRayName
}
else 
{
    $sourceRP = $claimsXRayName
    $targetRP = $SelRP
}

LogWrite ("Copying claims...")
try 
{        
    if ($sourceRP -eq $allClaimRules)
	{
        $IssuanceTransformRules = $defaultIssuanceRule
        $IssuanceAuthzRules = $defaultAuthzRules
        $DelegationAuthzRules = ""
    }
    else 
	{
        $IssuanceTransformRules = (Get-AdfsRelyingPartyTrust -Name $sourceRP).IssuanceTransformRules
        $IssuanceAuthzRules = (Get-AdfsRelyingPartyTrust -Name $sourceRP).IssuanceAuthorizationRules
        $DelegationAuthzRules = (Get-AdfsRelyingPartyTrust -Name $sourceRP).DelegationAuthorizationRules
    }

    LogWrite -LogOnly $IssuanceTransformRules
    LogWrite -LogOnly $IssuanceAuthzRules
    LogWrite -LogOnly $DelegationAuthzRules
        
    Set-AdfsRelyingPartyTrust -TargetName $targetRP -IssuanceTransformRules $IssuanceTransformRules

    #We don't want to accidentally overwrite some temporary authorization and delegation rules from Claims X-Ray
    if ($targetRP -eq $claimsXRayName) 
	{
        Set-AdfsRelyingPartyTrust -TargetName $targetRP -IssuanceAuthorizationRules $IssuanceAuthzRules #$IssuanceAuthzRules.ClaimsRulesString
        if ($DelegationAuthzRules.ClaimRules.Length -gt 0 )
		{
            Set-AdfsRelyingPartyTrust -TargetName $targetRP -DelegationAuthorizationRules $DelegationAuthzRules            
        }
    }
	
    ## At this point we are done
    LogWrite "Operation completed."
}
catch 
{
    $errorMessage = $_.Exception.Message
    LogWrite -Err "Operation was not completed successfully."
    LogWrite -Err $errorMessage        
}
# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDUfzymEMNxtlcw
# Z3Anj/M08ayGLp0yQ72fqqj7pEdKMaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgaKqxeBGC
# /e+FVv0EX6xeTZza6PlscLLVAAylOhG6F7MwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQA8pCfZulnPiOXSxK0nNN07Ms6hgXPGOpyo30UoJ103
# yDg+4xq/NkqDBiNZqDzI7tQuRWVx+MHM9ZQk7untUmq3IpOCPU4eY+awYSs/z8uS
# 2zplWyPyNjJ+t/GAirtd8KBQx+KlwaP40ZDssMlyOIBScLJOsSNAWf5x0YLNPbnG
# h9AuSQ6GdDWY6rzar18f7I/rGwGxFDbayJh7zmNjhSm3Yav2xCMS/QU0gIwL7wTG
# dELKt7EJqE51cQ9L4VY/izmrvXX5ymHBE/dINpTjIla2wejRrw+qtcsDtFRTEbJc
# B1jSvmlcGW/19DjWWfhHt8AIsvutEwb4a8C7tBc2f0IloYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIA/UkOonF1zcf6nJesQe/TTuqD88XWNOAY/lW1PW
# 1QY9AgZhHpsEN5kYEzIwMjEwODI0MDM1NTQwLjQwNVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAFJgAhKuwmgMwsAAAAAAUkw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNTU3WhcNMjIwMjExMTgyNTU3WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIz
# M0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvE/uJD4XYdtp6OSoZPkolG9p3CWcw
# Lle1XkQMluEejNzIQMeWMsd8ZbujdfjJfWG/c3SOmZBwUAWEfVSdlCaMayt8gQHk
# KFikoD/bY1Q4y7Rfda7sCJw8CXf5wfLqzsGMvKkhtBFGOhqN/YqQm5j7B0c9qq12
# 8i40lrrspOm31Vel+UAqlVt1L7Jb5MGKMWmEaoQpgvLGQq9NPBDMdgVjm1XwFFVc
# peBRWWn3Vb0UCWA6tqRuFLLaOsheYCA/jw6zw3+UwITm3JmnQVMIr9HALgvKY2uS
# 7lnSKiEaKRjb1oB1v0U0s8WPzkgbVpsyro+Uml2v7VreagzQzwvR+dWtAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUVnea8aPvuLS8NTXWT8mpc+pvJIEwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAEN54Cz4g7OBKqc8iwqLzNdQj2OCTxKmH+jr3Ayp+
# AY/1qw4d77A/4WCP8g8PdToYiC47UXC6Fd2epJ07Olen50f88rFAz49H5BV7XlwP
# jiyE1ZU0vLKHiCcB2mibalui7W0dtg4W4bIqi7UlQkhBLERS5nn+zHYQg/rFQUQv
# vJrKpx2NM0MFgv2hki4B3JkDUfFwoHxYbAAJR1UtXaH+0PG1BW5yL1DLs451q7D/
# RsHGmvx1M6+RKSr3qCUicbfQEa8vaP+nKJ0T/Da5vSqpSKocfD8dwM3Unn0tpoC+
# lKmqQMDbllghGs7NVhps+9xG95s7beCMr3AuUZG/E6RQaTCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUzN0EtMjMz
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAP+Wxrucu9GSImwAdD52BRGupqHeggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOTOX1wwIhgPMjAy
# MTA4MjQwMTU0MzZaGA8yMDIxMDgyNTAxNTQzNlowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA5M5fXAIBADAKAgEAAgIFDQIB/zAHAgEAAgISMDAKAgUA5M+w3AIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAD31Ll/45z8QdbhJPg5qeQPlWG5FeYUZ
# jHBgtt/64aLEQ52ep3HNXPLavFZynCqeeVusNIpMl1Y9DHf1m3fA22jnrvpEf/YY
# Rnuls8or/xts3o7Jx4aFjP0CSbVHrstmLhMPBknyY4XOYK0om6oXGIcPp73uxg0o
# KobgEj7QJEHEMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAFJgAhKuwmgMwsAAAAAAUkwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgxmohtqA/
# 8VJwvsNmDRTqBbC6wQEhuVlPxJAX849/6L4wgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCAolfr8WH1478zdhngQdSqc7DQL0sZx0OXG9a0fueihsjCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABSYAISrsJoDMLAAAA
# AAFJMCIEIA9zoUUIHrb4diBst55bQbiTkjKT5G6aNIg9e8s0vxOQMA0GCSqGSIb3
# DQEBCwUABIIBABuJpmTqTmQYk0LszQCF5qSDVIaMxZH0noyPHyftGdWzaLsvPcx7
# LfngL2DOyk0KUCw4bITO7JS0FJXuLySBdVOc2vrxd1RF14xnJvF1rOJGXhAuteYC
# VOBElCEVZO3Kz5Cy1ObZWTckbaLM6ByVuZFVk4abvHiMOHcbyUYJvIgVspeF6CtU
# Uu1QOjJonHHVQwgEb5BboSswc9X3uNF6rDClGRacGPSXaad6llIBfeSuhRaA9mNm
# 58eOU/fnY9oDDtHTSE+4z5GF/EvkvqvoAKROIBli/RVr50AdOGH1g4c/UpByfm2g
# hUubutibX8EIXMqDh+gmx6lxSsyDVXrIMxg=
# SIG # End signature block
