<#

Author: Dennys Simbolon
Date  : 20-04-2025

Script for hunting persistence artifact in Microsoft Windows OS. The script will go through startup folder, registry run key, scheduled task, etc and 
generate a CSV output which needs to be directed to a file for further processing. This script can be used to scope out incident by searching for compromise host with specific IOC.
This script must be run with WinRM. e.g Invoke-Command -ComputerName 127.0.0.1 -Credential $creds -FilePath .\persistence-artifacts-hunt.ps1 | Out-File -FilePath .\persistence-artifacts.csv

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

Function Users_Startup_Persistence {

	$local_users = Get-LocalUser

	$enabled_local_users = $local_users | Where-Object {$_.enabled -eq 'True'}

	$users_startup_persistence_artifacts = $enabled_local_users | ForEach-Object {Get-ChildItem -Path "C:\Users\$_\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -ErrorAction SilentlyContinue}

	$artifacts = $users_startup_persistence_artifacts | Select-Object @{name='Hostname';expression={$env:COMPUTERNAME}}, @{name='Artifact';expression={$_.Name}}, @{name='ArtifactPath';expression={$_.FullName}}, @{name='ArtifactHash';expression={(Get-FileHash $_.FullName).Hash}}, @{name='Payload';expression={$_.FullName}}, @{name='Technique';expression={"Startup Folder"}}, @{name='MitreID';expression={"T1547.001"}}, @{name='RegistryPath';expression={""}}, @{name='TaskName';expression={""}}, @{name='EventConsumerName';expression={""}}, @{name='User';expression={(Get-Acl $_.FullName).Owner}} | ConvertTo-Csv -NoTypeInformation

	$generic_startup_persistence_artifact = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object @{name='Hostname';expression={$env:COMPUTERNAME}}, @{name='Artifact';expression={$_.Name}}, @{name='ArtifactPath';expression={$_.FullName}}, @{name='ArtifactHash';expression={(Get-FileHash $_.FullName).Hash}}, @{name='Payload';expression={$_.FullName}}, @{name='Technique';expression={"Startup Folder"}}, @{name='MitreID';expression={"T1547.001"}}, @{name='RegistryPath';expression={""}}, @{name='TaskName';expression={""}}, @{name='EventConsumerName';expression={""}}, @{name='User';expression={(Get-Acl $_.FullName).Owner}} | ConvertTo-Csv -NoTypeInformation
	
	$full_artifacts = $artifacts + ($generic_startup_persistence_artifact | Select-Object -Skip 1)
		
	ForEach ($artifact in $full_artifacts) {
		$artifacts_data_csv.AppendLine($artifact)
	}
	
}

Function Registry_Persistence {
	
	$registry_aseps = @(
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
		"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
	)
	
	ForEach ($registry_asep in $registry_aseps){
		$registry_asep_properties = Get-ItemProperty -Path $registry_asep | ForEach-Object {$_.psobject.properties}
		
		Foreach ($registry_asep_property in $registry_asep_properties){
			if ($registry_asep_property.Name -ne "PSPath" -and $registry_asep_property.Name -ne "PSParentPath" -and $registry_asep_property.Name -ne "PSChildName" -and $registry_asep_property.Name -ne "PSDrive" -and $registry_asep_property.Name -ne "PSProvider")
			{
				$registry_asep_exe = $registry_asep_property.Value.Substring(0, $registry_asep_property.Value.IndexOf(".exe"))
				
				if ($registry_asep_exe[0] -eq '"')
				{
					$registry_asep_exe = $registry_asep_exe + '.exe"'
				}
				else
				{
					$registry_asep_exe = $registry_asep_exe + '.exe'
				}
								
				$artifact_path = $registry_asep_exe -split "\\"
				$artifact = $artifact_path[-1]
				$registry_asep_exe_trim = $registry_asep_exe.trim('"')
			
				if ($artifact[-1] -eq '"')
				{
					$artifact_name = $artifact.Substring(0, $artifact.Length - 1)
				}
				else
				{
					$artifact_name = $artifact
				}
				
				$artifacts = [PSCustomObject]@{
					Hostname = $env:COMPUTERNAME
					Artifact = $artifact_name
					ArtifactPath = $registry_asep_exe_trim
					ArtifactHash = (Get-FileHash -Path $registry_asep_exe_trim).Hash
					Payload = $registry_asep_property.Value
					Technique = "Registry Run Keys"
					MitreID = "T1547.001"
					RegistryPath = $registry_asep
					TaskName = ""
					EventConsumerName = ""
					User = ""
				
				}
				
				$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
				$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
				$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
			}
			
		}
		#$acl = Get-Acl -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
		#Write-Host $acl
	}
}

Function Scheduled_Tasks_Persistence {
	$local_users = Get-LocalUser

	$enabled_local_users = $local_users | Where-Object {$_.enabled -eq 'True'}
	
	ForEach ($enabled_local_user in $enabled_local_users){
		
		$enabled_local_user_scheduled_tasks = Get-ScheduledTask | Where-Object {$_.Author -like "$env:COMPUTERNAME\$enabled_local_user"}
		
		ForEach ($scheduled_task in $enabled_local_user_scheduled_tasks){
			
			$artifacts = [PSCustomObject]@{
				Hostname = $env:COMPUTERNAME
				Artifact = ($scheduled_task.Actions.Execute -split "\\")[-1]
				ArtifactPath = $scheduled_task.Actions.Execute
				ArtifactHash = (Get-FileHash -Path $scheduled_task.Actions.Execute).Hash
				Payload = $scheduled_task.Actions.Execute + " " + $scheduled_task.Actions.Arguments
				Technique = "Scheduled Task"
				MitreID = "T1053.005"
				RegistryPath = ""
				TaskName = $scheduled_task.TaskName
				EventConsumerName = ""
				User = $enabled_local_user.Name
			}
						
			$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
			$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
			$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
		}
	}
	
	#$system_scheduled_task = Get-ScheduledTask | Where-Object {$_.Author -like "*system*"}
}

Function WMI_Persistence {
	$wmi_event_consumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer
	
	ForEach ($wmi_event_consumer in $wmi_event_consumers) {
		if ($wmi_event_consumer.CommandLineTemplate -ne $null) 
		{
			$sid = New-Object System.Security.Principal.SecurityIdentifier($wmi_event_consumer.CreatorSID, 0)
			$user = $sid.Translate([System.Security.Principal.NTAccount])
						
			$artifacts = [PSCustomObject]@{
				Hostname = $wmi_event_consumer.PSComputerName
				Artifact = ($wmi_event_consumer.CommandLineTemplate -split " ")[0]
				ArtifactPath = $wmi_event_consumer.ExecutablePath
				ArtifactHash = ""#(Get-FileHash -Path ($wmi_event_consumer.CommandLineTemplate -split " ")[0]).Hash
				Payload = $wmi_event_consumer.CommandLineTemplate
				Technique = "WMI Persistence"
				MitreID = "T1546.003"
				RegistryPath = ""
				TaskName = ""
				EventConsumerName = $wmi_event_consumer.Name
				User = $user.Value
			}
						
			$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
			$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
			$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
		}
	}
}

Function Run {
	
	$users_startup_artifacts = Users_Startup_Persistence
	$registry_persistence_artifacts = Registry_Persistence
	$scheduled_task_artifacts = Scheduled_Tasks_Persistence
	$wmi_persistence_artifacts = WMI_Persistence
	
	$artifacts_data_csv_array = ($artifacts_data_csv.ToString() -split "`r?`n")
	$artifacts_data_csv_array[1..($artifacts_data_csv_array.Length -1)]
	
}

Run