<#
.SYNOPSIS
    Collect persistence artifacts from remote hosts
.DESCRIPTION
    Collect persistence artifacts from remote hosts
.PARAMETER ComputerName
    Target hosts / computer
.PARAMETER Password
    Password for user to log in to remote hosts
.PARAMETER Username
    Username for user to log in to remote hosts
.EXAMPLE
    .\hunt.ps1 -ComputerName 127.0.0.1 -Password "insertpassword" -Username "insertusername"
#>

[CmdletBinding()]
Param(
	[Array]$ComputerName,
	[String]$Password,
	[String]$Username
)

Function Hunt {

	$secure_password = ConvertTo-SecureString $Password -AsPlainText -Force

	$creds = New-Object System.Management.Automation.PSCredential ($Username, $secure_password)
	
	$session = New-PSSession -ComputerName $ComputerName -Credential $creds
	
	Copy-Item -Recurse -Path "C:\Users\Vande\Documents\Tools\yara-v4.5.2-2326-win64" -Destination "C:\Temp\yara" -ToSession $session

	$csv_headers = '"Hostname","Artifact","ArtifactPath","ArtifactHash","Payload","ATT&CK Technique (ID)","TI Result","RegistryPath","TaskName","EventConsumerName","User"'

	$csv_headers | Out-File -FilePath "C:\Users\Vande\Documents\Scripts\security-coding\Blue-Team-Scripts\persistence-artifacts.csv"

	Invoke-Command -Session $session -FilePath .\persistence-artifacts.ps1 | Out-File -FilePath .\persistence-artifacts.csv -Append

	#Invoke-Command -ComputerName $ComputerName -Credential $creds -FilePath .\persistence-artifacts.ps1 | foreach {($_ -split ",")[3]}

	Invoke-Command -Session $session -FilePath .\cmd-execution-artifacts.ps1
}

Hunt