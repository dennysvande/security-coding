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
		
		if ($running_process.ProcessName -ne "svchost.exe")
		{
			ForEach ($yara_rule in $yara_rules) {
				
				$yara_scanned_results = C:\Temp\yara\yara64.exe $yara_rule.fullname $running_process.ProcessId --print-strings 2> $null
				
				if ($yara_scanned_results -ne $null)
				{
					Write-Host "Scanning Process: "$running_process.ProcessName $running_process.ProcessId", Yara Rule: $yara_rule.Name" -ForegroundColor Green
					
					$yara_rule.Name
					$yara_scanned_results
					
					$artifacts = [PSCustomObject]@{
						Hostname = $hostname
						"Process Name" = $running_process.ProcessName
						"Process Command Line" = $running_process.CommandLine
						"Process Parent" = (Get-Process -Id $running_process.ParentProcessId).Name
						Artifact = $running_process.ProcessName
						ArtifactPath = $running_process.Path
						ArtifactHash = (Get-FileHash -Path $running_process.Path).Hash
						"IOC Pattern" = $yara_scanned_results
						"Yara Rule" = $yara_rule.Name
						"ATT&CK Technique (ID)" = ""
						"TI Result" = ""
						User = ""
					}
					
					$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
					$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
					$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
				}
				else
				{
					Write-Host "Scanning Process: "$running_process.ProcessName $running_process.ProcessId", Yara Rule: $yara_rule.Name"
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

#Function PSReadLine_Artifacts {
#}

$malicious_process = Malicious_Process_Artifacts

$artifacts_data_csv_array = ($artifacts_data_csv.ToString() -split "`r?`n")
$artifacts_data_csv_array[1..($artifacts_data_csv_array.Length -1)]