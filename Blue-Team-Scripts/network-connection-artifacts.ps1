<#

Author: Dennys Simbolon
Date  : 16-05-2025

Script for live investigation, collection / detection of network connection activity in Microsoft Windows OS such as C2 beacon activity,
for a 24 hour period. The log is sourced from windows Sysmon event log.

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

Function Get-NetworkConnection {
	$network_connections = Get-WinEvent -filterhashtable @{logname="Microsoft-Windows-Sysmon/Operational"; StartTime="05/17/2025 00:00:00"; EndTime="05/17/2025 23:59:00"; id=3}
	ForEach ($network_connection in $network_connections) {
		$network_connection_attributes = ($network_connection.Message -split "\n")
		
		$artifacts = [PSCustomObject]@{
			"Detected Date" = ($network_connection.TimeCreated).ToString("yyyy-MM-dd HH:mm:ss")
			"Event Source" = $network_connection.ProviderName
			"Image" = (($network_connection_attributes[5] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"ProcessId" = (($network_connection_attributes[4] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"User" = (($network_connection_attributes[6] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"Initiated" = (($network_connection_attributes[8] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"SourceHostname" = (($network_connection_attributes[11] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"SourceIp" = (($network_connection_attributes[10] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"SourcePort" = (($network_connection_attributes[12] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"DestinationHostname" = (($network_connection_attributes[16] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"DestinationIp" = (($network_connection_attributes[15] -split " ", 2)[1]).TrimEnd("`r", "`n")
			"DestinationPort" = (($network_connection_attributes[17] -split " ", 2)[1]).TrimEnd("`r", "`n")
		}
			
		$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
		$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
		$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
		
	}
}

$network_connection = Get-NetworkConnection

$artifacts_data_csv_array = ($artifacts_data_csv.ToString() -split "`r?`n")

$artifacts_data_csv_array