# Trustees we are interested in: Authenticated Users, Builtin Users, Interactive, Everyone, Builtin Guest
$groupsToCheck = @("AU", "BU", "IU", "WD", "BG")

$escalate_permissions = @("WD", "WO","GA", "GW", "FA", "DC", "KW", "KA")
# Define modification-related permissions for Windows Services
# Common rights that allow changes:
# WD - Write DAC (Change Permissions)
# WO - Write Owner (Take Ownership)
# DC - Delete Child
# GA - Generic All (Full Control)
# GW - Generic Write
# KW - Key Write
# KA - Key All

$DoS_permissions = @("WP","SD")
# Denial of service permissions (might want be interested in these as well)
# WP - Service Stop
# SD - Service Delete
function Group-Check 
{
    # Extract the DACL part (everything after D: up to S: if present)
    $sddl = $args[0]
	#Write-Host "Checking SDDL: $sddl ..."
	$out = ""
	# Check if the object is owned by SYSTEM
	if(!$sddl.StartsWith("O:SY") -and !$sddl.StartsWith("O:BA"))
	{
		$out = $out + "$sddl is NOT owned by SYSTEM or Builtin Administrators!`n"
	}
    $daclMatch = [regex]::Match($sddl, "D:(.*?)(?:S:|$)")
    if ($daclMatch.Success) {
        $dacl = $daclMatch.Groups[1].Value    
        # Split into individual ACEs by finding patterns between parentheses
        $aces = [regex]::Matches($dacl, "\((.*?)\)")    
        foreach ($aceMatch in $aces) {
            $ace = $aceMatch.Groups[1].Value        
            # Split the ACE into its components       
			# Extract the group SID/alias (last part after ;;;)
			# Check to distinguish Deny ACEs, so we can ignore them:
			if($ace.StartsWith('D')) { continue; }
			$group = $ace -split ';;;' | Select-Object -Last 1 		
			# Get the permissions field (second element)
            $acentries = $ace -split ';;'
			$permissions = $acentries[1]
            # Check if this group is in our array
			#Write-Host "Checking group $group"
            if ($groupsToCheck -contains $group) 
			{              
				# Check if any potential escalation permissions are present
				foreach ($perm in $escalate_permissions) 
				{
					#Write-Host "Checking perm $perm"
					if ($permissions -match $perm) 
					{
						# Uncomment for debugging
						$out = $out + "Group $group has escalation permission $perm in ACE: ($ace),SDDL: $sddl`n"		
					}
				}
				# Check if any potential DoS permissions are present
				foreach ($perm in $DoS_permissions) {
					if ($permissions -match $perm) {
						$out = $out + "Group $group has denial of service permission $perm in ACE: ($ace), SDDL: $sddl`n"
					}
				}
            }
        }
    }
	return $out
}
function Convert-HexToBin {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HexString
    )
    if ($HexString.Length % 2 -ne 0) {
        Write-Error "Hex string length must be even, got: $($HexString.Length)"
        return
    }
    $byteArray = [byte[]]::new($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $byteArray[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $byteArray
}

# Initialize COM
$com = New-Object -ComObject "WbemScripting.SWbemLocator"
$svc = $com.ConnectServer(".", "root\cimv2")
$helper = $svc.Get("Win32_SecurityDescriptorHelper")
$filePath = "SDDLs_hexascii.txt"
foreach ($hex in Get-Content -Path $filePath) 
{
    Write-Output $line
	$bin = Convert-HexToBin -HexString $hex
	$inParams = ($helper.Methods_ | Where-Object { $_.Name -eq "BinarySDToSDDL" }).InParameters.SpawnInstance_()
	$inParams.Properties_.Item("BinarySD").Value = $bin
	try {
		$outParams = $helper.ExecMethod_("BinarySDToSDDL", $inParams)
		#Write-Host "Out Params: $outParams"
	} catch {
		Write-Host "ExecMethod_ crashed! Error: $($_.Exception.Message)"
	}
	# Check the vibe with full debug
	if ($null -eq $outParams) 
	{
		Write-Host "BinarySDToSDDL flopped! No output params returned!"
	} 
	else 
	{
		# Dump all properties
		$returnValue = $outParams.Properties_.Item("ReturnValue").Value
		#Write-Host "ReturnValue Raw: $returnValue"
		if ($returnValue -eq 0) 
		{
			$sddl = $outParams.Properties_.Item("SDDL").Value
			#Write-Host "Hex: $hex"
			#Write-Host "Binary: " (($bin | ForEach-Object { "{0:X2}" -f $_ }) -join " ")
			#Write-Host "SDDL: $sddl"
			$output = Group-Check($sddl)
			if($output -ne "")
			{
				Write-Host $output "for original $hex"
			}
		}
			else 
		{	
			Write-Host "BinarySDToSDDL flopped! Error: $returnValue"
			# Spill all out params
			#Write-Host "Out Params Full Dump:"
			#$outParams.Properties_ | ForEach-Object {
			#    Write-Host "$($_.Name): $($_.Value)"
			#}
		}
	}
}
# Clean up the COM dance floor
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($inParams) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($helper) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($svc) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($com) | Out-Null
