<#

Author: Dennys Simbolon
Date  : 12-05-2025

Script for live investigation / hunting of command execution artifact in Microsoft Windows OS such as malicious running process,
by using Loki scanner with Yara signatures

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

Function Malicious_Process_Artifacts {
	
	$loki_scanned_results = C:\Temp\loki\loki.exe --nofilescan --nolog --csv
	
	$running_processess = Get-CimInstance -ClassName Win32_Process
	
	$artifacts = ""
	$malicious_process = ""
	$malicious_process_id = ""
	
	For ($i=0; $i -lt $loki_scanned_results.Length; $i++){
		if ($loki_scanned_results[$i].Contains("WARNING"))
		{
			Write-Host $loki_scanned_results[$i]
			Write-Host $loki_scanned_results[$i-1]
			$loki_scanned_results_array = $loki_scanned_results[$i] -split ","
			$hostname = $loki_scanned_results_array[1]
			Write-Host $hostname
			$malicious_process = $loki_scanned_results[$i]
			$process_id_start_index = $loki_scanned_results[$i-1].IndexOf("PID: ")
			$process_id_last_index = $loki_scanned_results[$i-1].IndexOf("NAME:")
			$malicious_process_id = -join ($loki_scanned_results[$i-1])[($process_id_start_index+5)..($process_id_last_index-2)]
			
			<#
			$artifacts = [PSCustomObject]@{
				Hostname = $hostname
				PID = $malicious_process_id
				Artifact = 
				ArtifactPath = 
				ArtifactHash = 
				"IOC Pattern" = 
				"ATT&CK Technique (ID)" = 
				"TI Result" = 
				User = 
			}
			#>
			
			ForEach ($running_process in $running_processess) {
				if ($running_process.ProcessId -eq $malicious_process_id)
				{
					$running_process_parent = Get-Process -Id $running_process.ParentProcessId | Select-Object Name
					$running_process_parent.Name
				}
			}
		}
	}
	
	Remove-Item -Recurse -Path C:\Temp\loki
	
	#return $artifacts
}

#Function PSReadLine_Artifacts {
#}

Malicious_Process_Artifacts