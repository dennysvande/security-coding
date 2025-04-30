[CmdletBinding()]
Param(
	[String]$ComputerName,
	[String]$Password,
	[String]$Username
)

Function Hunt {

	$secure_password = ConvertTo-SecureString $Password -AsPlainText -Force

	$creds = New-Object System.Management.Automation.PSCredential ($Username, $secure_password)

	$csv_headers = '"Hostname","Artifact","ArtifactPath","ArtifactHash","Payload","Technique","RegistryPath","TaskName","EventConsumerName","User"'

	$csv_headers | Out-File -FilePath "C:\Users\Vande\Documents\Scripts\security-coding\Blue-Team-Scripts\persistence-artifacts.csv"

	Invoke-Command -ComputerName $ComputerName -Credential $creds -FilePath .\persistence-artifacts-hunt.ps1 | Out-File -FilePath .\persistence-artifacts.csv -Append
}

Hunt