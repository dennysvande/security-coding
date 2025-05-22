<#
.SYNOPSIS
    Collect indicators of compromise and artifacts from remote hosts
.DESCRIPTION
    Collect indicators of compromise and artifacts from remote hosts
.PARAMETER Computers
    Target hosts / computer
.PARAMETER Password
    Password for user to log in to remote hosts
.PARAMETER Username
    Username for user to log in to remote hosts
.EXAMPLE
    .\hunt.ps1 -Computers 127.0.0.1 -Username "insertusername" -Password "insertpassword" -Action "[Hunt|Collect]"
#>

[CmdletBinding()]
Param(
	[Array]$Computers,
	[String]$Username,
	[String]$Password,
	[String]$Action
)

Function Get-IOC {

	$secure_password = ConvertTo-SecureString $Password -AsPlainText -Force

	$creds = New-Object System.Management.Automation.PSCredential ($Username, $secure_password)
	
	$session = New-PSSession -ComputerName $Computers -Credential $creds
	
	#Copy-Item -Recurse -Path "C:\Users\Vande\Documents\Tools\yara-v4.5.2-2326-win64" -Destination "C:\Temp\yara" -ToSession $session

	#$persistence_artifacts_csv_headers = '"Hostname","Artifact","ArtifactPath","ArtifactHash","Payload","ATT&CK Technique (ID)","TI Result","RegistryPath","TaskName","EventConsumerName","User"'

	#$persistence_artifacts_csv_headers | Out-File -FilePath "C:\Users\Vande\Documents\Scripts\security-coding\Blue-Team-Scripts\persistence-artifacts.csv"
	
	#$cmd_execution_artifacts_csv_headers = 'Hostname,Process Name,Process Id,Process Command Line,Process Parent,Process Parent Id,Artifact,ArtifactPath,ArtifactHash,IOC Pattern,Yara Rule,ATT&CK Technique (ID),TI Result,User'
	
	#$cmd_execution_artifacts_csv_headers | Out-File -FilePath "C:\Users\Vande\Documents\Scripts\security-coding\Blue-Team-Scripts\cmd-execution-artifacts.csv"
	
	#$network_connection_artifacts_csv_headers = 'Hostname,Detected Date,Event Source,Image(Artifact),ArtifactPath,ProcessId,User,Initiated,SourceHostname,SourceIP,SourcePort,DestinationHostname,DestinationIP,DestinationPort'
	
	#$network_connection_artifacts_csv_headers | Out-File -FilePath "C:\Users\Vande\Documents\Scripts\security-coding\Blue-Team-Scripts\network-connection-artifacts.csv"

	#Invoke-Command -Session $session -FilePath .\persistence-artifacts.ps1 | Out-File -FilePath .\persistence-artifacts.csv -Append

	#Invoke-Command -Session $session -FilePath .\persistence-artifacts.ps1 | foreach {($_ -split ",")[3]}

	#Invoke-Command -Session $session -FilePath .\cmd-execution-artifacts.ps1 | Out-File -FilePath .\cmd-execution-artifacts.csv -Append
	
	#Invoke-Command -Session $session -FilePath .\network-connection-artifacts.ps1 | Out-File -FilePath .\network-connection-artifacts.csv -Append
	
}

Function Get-Artifacts {
	
	$secure_password = ConvertTo-SecureString $Password -AsPlainText -Force

	$creds = New-Object System.Management.Automation.PSCredential ($Username, $secure_password)
	
	$artifacts_categories = @("persistence-artifacts", "cmd-execution-artifacts", "network-connection-artifacts")
	
	ForEach ($computer in $Computers){
		mkdir -Name $computer -ErrorAction SilentlyContinue
		ForEach ($artifacts_category in $artifacts_categories){
			mkdir -Name ".\$computer\$artifacts_category" -ErrorAction SilentlyContinue
		}
	}
	
	ForEach ($artifacts_category in $artifacts_categories){
		$artifacts = Import-Csv ".\$artifacts_category.csv"
		ForEach ($artifact in $artifacts){
			$session = New-PSSession -ComputerName $artifact.Hostname -Credential $creds
			Copy-Item -FromSession $session -Path $artifact.ArtifactPath -Destination (".\" + $artifact.Hostname + "\" + $artifacts_category)
		}
	}
}

Function Run {
	
	if ($Action -eq "Hunt")
	{
		Get-IOC
	}
	else if ($Action -eq "Collect")
	{
		Get-Artifacts
	}
	
}

Run