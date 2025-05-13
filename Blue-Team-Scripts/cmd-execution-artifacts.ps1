<#

Author: Dennys Simbolon
Date  : 12-05-2025

Script for live investigation / hunting of command execution artifact in Microsoft Windows OS such as malicious running process,
by using Loki scanner with Yara signatures.

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

Function Malicious_Process_Artifacts {
	
	$yara_rules = Get-ChildItem -Path C:\Temp\yara\signature-base\yara
	
	$running_processes = Get-CimInstance -ClassName Win32_Process
	
	ForEach ($running_process in $running_processes) {
		
		ForEach ($yara_rule in $yara_rules) {
			
			$yara_scanned_results = C:\Temp\yara\yara64.exe $yara_rule.fullname $running_process.ProcessId --print-strings 2> $null
			
			if ($yara_scanned_results -ne $null)
			{
				$yara_rule.Name
				$yara_scanned_results
			}
		}
	}
			
			<#
			$artifacts = [PSCustomObject]@{
				Hostname = $hostname
				"Process Name" = (Get-Process -Id $malicious_process_id).Name
				"Process Parent" = $running_process_parent
				Artifact = 
				ArtifactPath = 
				ArtifactHash = 
				"IOC Pattern" = 
				"ATT&CK Technique (ID)" = 
				"TI Result" = 
				User = 
			}
			#>
	
	Remove-Item -Recurse -Path C:\Temp\yara
	
	#return $artifacts
}

#Function PSReadLine_Artifacts {
#}

Malicious_Process_Artifacts