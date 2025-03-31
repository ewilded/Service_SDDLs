# Converts SDDL string from CrowdStrike CreateService base event into regular SDDL strings.
$SDDL_bin_asciihex = "01000480b0000000bc000000000000001400000002009c0007000000000014008d010200010100000000000504000000000014008d01020001010000000000050600000000001400ff010f0001010000000000051200000000001800ff010f00010200000000000520000000200200000000180014000000010200000000000f02000000010000000000140014000000010100000000000504000000000014001400000001010000000000050b000000010100000000000512000000010100000000000512000000"
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
$com = New-Object -ComObject "WbemScripting.SWbemLocator"
$svc = $com.ConnectServer(".", "root\cimv2")
$helper = $svc.Get("Win32_SecurityDescriptorHelper")
$bin = Convert-HexToBin -HexString $SDDL_bin_asciihex
$inParams = ($helper.Methods_ | Where-Object { $_.Name -eq "BinarySDToSDDL" }).InParameters.SpawnInstance_()
$inParams.Properties_.Item("BinarySD").Value = $bin
# Call the method
try {
	$outParams = $helper.ExecMethod_("BinarySDToSDDL", $inParams)
	#Write-Host "Out Params: $outParams"
} catch {
	Write-Host "ExecMethod_ crashed! Error: $($_.Exception.Message)"
}
if ($null -eq $outParams) 
{
	Write-Host "BinarySDToSDDL flopped! No output params returned!"
	exit;
} 
$returnValue = $outParams.Properties_.Item("ReturnValue").Value
if ($returnValue -ne 0) 
{
	Write-Host "BinarySDToSDDL flopped! Error: $returnValue"
	exit;
}
$sddl = $outParams.Properties_.Item("SDDL").Value
Write-Host $sddl
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($inParams) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($helper) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($svc) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($com) | Out-Null