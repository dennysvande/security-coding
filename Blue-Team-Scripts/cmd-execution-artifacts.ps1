<#

Author: Dennys Simbolon
Date  : 12-05-2025

Script for live investigation / hunting of command execution artifact in Microsoft Windows OS such as malicious/suspicious running process,
by using Loki scanner with Yara signatures.

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

Function Threat_Intelligence_Analysis {
	
	param(
		[String]$FileHash
	)
	
	$headers=@{}
	$headers.Add("accept", "application/json")
	$headers.Add("x-apikey", "f4d19e3fa12e08ce115b50af89be40df80e2e0cb486b20516ee775f529acc260")
	$response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$FileHash" -Method GET -Headers $headers
	$ti_result = $response.Content | ConvertFrom-Json
	#$ti_result.data.attributes.last_analysis_results.CrowdStrike.result
	return $ti_result.data.attributes.last_analysis_results.Elastic.result
	
}

Function Get-SuspicousProcess {
	
	$yara_rules = Get-ChildItem -Path C:\Temp\yara\signature-base\yara\windows
	
	$running_processes = Get-WmiObject -Class Win32_Process
		
	ForEach ($running_process in $running_processes) {
		
		if ($running_process.ProcessName -ne "svchost.exe")
		{
			$process_owner = $running_process.GetOwner().Domain + "\" + $running_process.GetOwner().User
			
			ForEach ($yara_rule in $yara_rules) {
				
				$yara_scanned_results = C:\Temp\yara\yara64.exe $yara_rule.fullname $running_process.ProcessId 2> $null
				
				if ($yara_scanned_results -ne $null)
				{
					$yara_scanned_results_strings_array = [System.Text.StringBuilder]::new()
								
					Write-Host "Scanning Process: "$running_process.ProcessName $running_process.ProcessId", Yara Rule: "$yara_rule.Name", Process Owner: "$process_owner -ForegroundColor Red
					
					Foreach ($yara_scanned_results_strings in $yara_scanned_results) {
						$yara_scanned_results_strings_array.AppendLine($yara_scanned_results_strings)
					}
					
					Write-Host $yara_scanned_results_strings_array
					
					$yara_scanned_results_array = ($yara_scanned_results_strings_array.ToString() -split "`r?`n")
					
					if ((Get-Process -Id $running_process.ParentProcessId).Name -eq $null)
					{
						$process_parent = ""
					}
					else
					{
						$process_parent = (Get-Process -Id $running_process.ParentProcessId).Name + ".exe"
					}
					
					$artifacts = [PSCustomObject]@{
						Hostname = $env:COMPUTERNAME
						"Process Name" = $running_process.ProcessName
						"Process Id" = $running_process.ProcessId
						"Process Command Line" = $running_process.CommandLine
						"Process Parent" = $process_parent
						"Process Parent Id" = $running_process.ParentProcessId
						Artifact = $running_process.ProcessName
						ArtifactPath = $running_process.ExecutablePath
						ArtifactHash = (Get-FileHash -Path $running_process.Path).Hash
						"IOC Pattern" = $yara_scanned_results_array -join ";"
						"Yara Rule" = $yara_rule.Name
						"ATT&CK Technique (ID)" = ""
						"TI Result" = Threat_Intelligence_Analysis -FileHash (Get-FileHash -Path $running_process.Path).Hash
						User = $process_owner
					}
					
					$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
					$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
					$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
				}
				else
				{
					Write-Host "Scanning Process: "$running_process.ProcessName $running_process.ProcessId", Yara Rule: "$yara_rule.Name", Process Owner: "$process_owner -ForegroundColor Green
				}
			}
		}
		else
		{
			continue
		}
	}
	
	Remove-Item -Recurse -Path C:\Temp\yara
	
	#return $artifacts
}

Function Get-ProcessCreate {
	
}

#Function PSReadLine_Artifacts {
#}

$malicious_process = Get-SuspicousProcess

$artifacts_data_csv_array = ($artifacts_data_csv.ToString() -split "`r?`n")

$artifacts_data_csv_array