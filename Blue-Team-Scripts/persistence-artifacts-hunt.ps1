<#

Author: Dennys Simbolon
Date  : 20-04-2025

Script for hunting persistence artifact in Microsoft Windows OS. The script will go through startup folder, registry run key,
scheduled task, etc and generate a CSV output which needs to be directed to a file for further processing. This script must be run with WinRM.
e.g Invoke-Command -ComputerName 127.0.0.1 -Credential $creds -FilePath .\persistence-artifacts-hunt.ps1 | Out-File -FilePath .\persistence-artifacts.csv

#>

$artifacts_data_csv = [System.Text.StringBuilder]::new()

function Users_Startup_Persistence {

	$local_users = Get-LocalUser

	$enabled_local_users = $local_users | Where-Object {$_.enabled -eq 'True'}

	$users_startup_persistence_artifacts = $enabled_local_users | ForEach-Object {Get-ChildItem -Path "C:\Users\$_\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -ErrorAction SilentlyContinue}

	$artifacts = $users_startup_persistence_artifacts | Select-Object @{name='Artifact';expression={$_.Name}}, @{name='FilePath';expression={$_.FullName}}, @{name='RegistryPath';expression={""}}, @{name='User';expression={(Get-Acl $_.FullName).Owner}}, @{name='FileHash';expression={(Get-FileHash $_.FullName).Hash}}, @{name='Hostname';expression={$env:COMPUTERNAME}} | ConvertTo-Csv -NoTypeInformation

	$generic_startup_persistence_artifact = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object @{name='Artifact';expression={$_.Name}}, @{name='FilePath';expression={$_.FullName}}, @{name='RegistryPath';expression={""}}, @{name='User';expression={(Get-Acl $_.FullName).Owner}}, @{name='FileHash';expression={(Get-FileHash $_.FullName).Hash}}, @{name='Hostname';expression={$env:COMPUTERNAME}} | ConvertTo-Csv -NoTypeInformation
	
	$full_artifacts = $artifacts + ($generic_startup_persistence_artifact | Select-Object -Skip 1)
		
	ForEach ($artifact in $full_artifacts) {
		$artifacts_data_csv.AppendLine($artifact)
	}
	
}

function Registry_Persistence {
	
	$registry_aseps = @(
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
		"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
	)
	
	ForEach ($registry_asep in $registry_aseps){
		$registry_asep_value = Get-ItemProperty -Path $registry_asep | ForEach-Object {$_.psobject.properties.value} | ForEach-Object {$_.Substring(0, $_.IndexOf(".exe")) } -ErrorAction SilentlyContinue | ForEach-Object { if ($_[0] -eq '"') {$_ + '.exe"'} else {$_ + '.exe'}}
			
		foreach ($registry_asep_exe in $registry_asep_value){
			$artifact_path = $registry_asep_exe -split "\\"
			$artifact = $artifact_path[-1]
			$registry_asep_exe_trim = $registry_asep_exe.trim('"')
			
			if ($artifact[-1] -eq '"')
			{
				$artifact_name = $artifact.Substring(0, $artifact.Length - 1)
				$file_hash = (Get-FileHash -Path $registry_asep_exe_trim).Hash
			}
			else
			{
				$artifact_name = $artifact
				$file_hash = (Get-FileHash -Path $registry_asep_exe_trim).Hash
			}
			
			$artifacts = [PSCustomObject]@{
				Artifact = $artifact_name
				FilePath = $registry_asep_exe_trim
				RegistryPath = $registry_asep
				User = ""
				FileHash = $file_hash
				Hostname = $env:COMPUTERNAME
			}
			
			$csv_converted_artifacts = $artifacts | ConvertTo-Csv -NoTypeInformation
			$csv_converted_artifacts_no_headers = $csv_converted_artifacts | Select-Object -Skip 1
			$artifacts_data_csv.AppendLine($csv_converted_artifacts_no_headers)
		}
		#$acl = Get-Acl -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
		#Write-Host $acl
	}
}

function Run {

	$users_startup_artifacts = Users_Startup_Persistence
	$registry_persistence_artifacts = Registry_Persistence

	return $artifacts_data_csv.ToString()
	
}

Run