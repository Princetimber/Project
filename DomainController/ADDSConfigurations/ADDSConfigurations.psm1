$ErrorActionPreference = "Stop"
$PSDefaultParameterValues = @{
  'New-ADDSForest:DomainMode' = 'WinThreshold'
  'New-ADDSForest:ForestMode' = 'WinThreshold'
  'New-ADDSForest:DatabasePath' = "$env:SystemDrive\Windows\"
  'New-ADDSForest:LogPath' = "$env:SystemDrive\Windows\NTDS\"
  'New-ADDSForest:SysvolPath' = "$env:SystemDrive\Windows\"
  'New-ADDSForest:Force' = $true
}
$RegisteredSecretVault = $null
$AzureConnection = $null
# Import the required modules
function Install-RequiredModule {
  param(
    [string[]]$Name = @( 'Microsoft.PowerShell.SecretManagement', 'az.keyvault')
  )
  $Name | ForEach-Object {
    if(-not (Get-Module -Name $_ -ListAvailable)){
      try {
        Set-PSResourceRepository -Name PSGallery -Trusted
        Install-PSResource -Name $_ -Repository PSGallery -Scope AllUsers -Confirm:$false
        Write-Output "Module $_ installed successfully"
      }
      catch {
        Write-Error -Message "Failed to install module $_. Please see the error message below.:$_"
      }
    }
    else {
      Write-Output "Module $_ is already installed"
    }
  }
}
function Install-RequiredADModule {
  [string]$Name = 'AD-Domain-Services'
  if (-not (Get-WindowsFeature -Name $Name | Where-Object { $_.Installed -eq $true })) {
    try {
      install-WindowsFeature -Name $Name -IncludeManagementTools
    }
    catch {
      throw "Failed to install the required module $ModuleName. Please see the error message below.:$_"
    }
  }
  else {
    Write-Output "Module $ModuleName is already installed"
  }
}
# Add keys to a hashtable
function Add-keys{
  param($hash, $keys)
  $keys.GetEnumerator() | ForEach-Object {
    $hash.Add($_.Key, $_.Value)
  }
}
# Create a new environment path
function New-EnvPath {
  param(
    [string]$Path,
    [string]$ChildPath
  )
  return Join-Path @PSBoundParameters
}
function Test-Paths {
  param(
    [string[]]$Paths 
  )
  $paths | ForEach-Object {
    if (-not (Test-Path -Path $_)) {
      throw "Path $_ does not exist"
    }
  }
}
# function to connect to Azure
function Connect-ToAzure {
  if($null -eq $AzureConnection){
    try {
      # Check if there is an existing connection
      $existingConnection = Get-AzContext -ErrorAction SilentlyContinue
      if($existingConnection){
        Write-Output "Already connected to Azure"
        return
      }
      # Connect to Azure
      if($null -eq $AzureConnection){
        Connect-AzAccount -UseDeviceAuthentication
        $timeout = New-TimeSpan -Minutes 90
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($stopwatch.Elapsed -lt $timeout){
          $Context = (Get-AzContext -ErrorAction SilentlyContinue).Account
          $AzureConnection = $Context
          if($AzureConnection){
            write-output "Connected to Azure"
            return
          }
        }
      }
    }
    catch {
      Write-Error "Failed to connect to Azure. Please see the error message below.:$_"
    }
  }
}
# function to get the vault in Azure
function Get-Vault {
  param(
    [string]$keyVaultName,
    [string]$ResourceGroupName
  )
  Get-AzKeyVault @PSBoundParameters
}
# function to add the registered secret vault using SecretManagement module
function Add-RegisteredSecretVault {
  param(
    [string]$Name = (Get-Vault).VaultName,
    [string]$ModuleName = "az.keyvault",
    [hashtable]$VaultParameters = @{
      AZKVaultName = $Name
      SubscriptionId = (Get-AzContext).Subscription.Id
    }
  )
  # Check if the vault is already registered
  $existingVault = Get-SecretVault -Name $Name -ErrorAction SilentlyContinue
  if($existingVault){
    Write-Output "Secret vault $Name is already registered"
    return
  }
  if($null -eq $RegisteredSecretVault){
    try {
      Register-SecretVault -Name $Name -ModuleName $ModuleName -VaultParameters $VaultParameters -Confirm:$false
      $Context = (Get-SecretVault -Name $Name).Name
      $RegisteredSecretVault = $Context
      if($RegisteredSecretVault){
        write-output "Secret vault $Name registered successfully"
        return
      }
    }
    catch {
      Write-Error "Failed to register the secret vault. Please see the error message below.:$_"
    }
  }
}
# function to remove the registered secret vault
function Remove-RegisteredSecretVault {
  param(
    [string]$Name = (Get-Vault).VaultName
  )
  if(!$RegisteredSecretVault){
    try {
      Unregister-SecretVault -Name $Name -Confirm:$false
      write-output "Secret vault $Name unregistered successfully"
    }
    catch {
      Write-Error "Failed to unregister the secret vault. Please see the error message below.:$_"
    }
  }
}
# function to disconnect from Azure
function Disconnect-FromAzure {
  try {
    if(!$AzureConnection){
      Disconnect-AzAccount -Confirm:$false
      $AzureConnection = $null
      write-output "Disconnected from Azure"
    }
  }
  catch {
    Write-Error "Failed to disconnect from Azure. Please see the error message below.:$_"
  }
}
# function to create a new AD Forest
function New-ADDSForest {
  param(
    [string]$DomainName,
    [string]$DomainNetBiosName,
    [string]$DomainMode = 'WinThreshold',
    [string]$ForestMode = 'WinThreshold',
    [string]$DatabasePath = "$env:SystemDrive\Windows\",
    [string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [string]$SysvolPath = "$env:SystemDrive\Windows\",
    [string]$KeyVaultName,
    [string]$ResourceGroupName,
    [string]$secretName
  )
  # set the paths
  $LOG_PATH = New-EnvPath -Path $LogPath -ChildPath 'logs'
  $DATABASE_PATH = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
  $SYSVOL_PATH = New-EnvPath -Path $SysvolPath -ChildPath 'SYSVOL'
  # install required modules
  Install-RequiredModule
  Install-RequiredADModule
  # connect to Azure
  Connect-ToAzure
  # get the vault
  Get-Vault
  Add-RegisteredSecretVault
  # define common parameters
  $commonParams = @{
    InstallDNS = $true
    DomainName = $DomainName
    DomainNetBiosName = $DomainNetBiosName
    DomainMode = $DomainMode
    ForestMode = $ForestMode
    DatabasePath = $DATABASE_PATH
    LogPath = $LOG_PATH
    SysvolPath = $SYSVOL_PATH
    Force = $true
  }
  # retrieve the safe mode administrator password
  $vaultName = (Get-Vault).VaultName
  [securestring]$safeModeAdministratorPassword = Get-Secret -Name $secretName -Vault $vaultName
  $param = $commonParams.Clone()
  $keys = @{
    SafeModeAdministratorPassword = $safeModeAdministratorPassword
  }
  Add-keys -hash $param -keys $keys
  # create the new AD Forest
  Install-ADDSForest @param
  # remove the registered secret vault
  Remove-RegisteredSecretVault
  # disconnect from Azure
  Disconnect-FromAzure
}
#  nested function to wrap the New-ADDSForest function
function New-ADForest {
  <#
  .SYNOPSIS
    This function is used to create a new Active Directory Forest in on-premises or Azure.
  .DESCRIPTION
    This module is used to create a new Active Directory Forest in on-premises or Azure.
    It installs the required modules, connects to Azure, gets the vault, adds the registered secret vault, defines common parameters, retrieves the safe mode administrator password, creates the new AD Forest, removes the registered secret vault, and disconnects from Azure after the operation.
  .PARAMETER DomainName
    The fully qualified domain name of the new AD Forest.
  .PARAMETER DomainNetBiosName
    The NetBIOS name of the new AD Forest.
  .PARAMETER DomainMode
    The domain functional level of the new AD Forest. This is set to 'WinThreshold' by default.
  .PARAMETER ForestMode
    The forest functional level of the new AD Forest. This is set to 'WinThreshold' by default.
  .PARAMETER DatabasePath
    The path to the database folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER LogPath
    The path to the log folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER SysvolPath
    The path to the sysvol folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER KeyVaultName
    The name of the key vault in Azure.
  .PARAMETER ResourceGroupName
    The name of the resource group in Azure where the key vault is located.
  .PARAMETER secretName
    The name of the secret in the key vault that contains the safe mode administrator password.
  .PARAMETER Force
    This is a switch parameter that forces the operation to continue without prompting for confirmation.    
  .NOTES
    File Name      : New-ADForest
    Author         : Olamide Olaleye
    Prerequisite   : PowerShell 7.2 and above.
  .LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
  .EXAMPLE
    New-ADForest -DomainName "contoso.com" -DomainNetBiosName "CONTOSO" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -secretName "safemodeadminpassword"
    This example creates a new Active Directory Forest with the specified parameters.
    The function assumes default values for the DomainMode, ForestMode, DatabasePath, LogPath, and SysvolPath parameters.
  .EXAMPLE
  New-ADForest -DomainName "contoso.com" -DomainNetBiosName "CONTOSO" -DatabasePath "D:\" -LogPath "e:\" -SysvolPath "F:\" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -secretName "safemodeadminpassword" -Force
    This example creates a new Active Directory Forest with the specified parameters.
    The function specifies the DatabasePath, LogPath, and SysvolPath parameters.
    There is no requirement to specify the database, log and sysvol directory folders as the default values are used.
  .INPUTS
    System.String
  .OUTPUTS
    System.String
  #>
  
  
  [CmdletBinding(SupportsShouldProcess  = $true)]
  param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [Parameter(Mandatory = $true)]
    [string]$DomainNetBiosName,
    [Parameter(Mandatory = $false)]
    [string]$DomainMode = 'WinThreshold',
    [Parameter(Mandatory = $false)]
    [string]$ForestMode = 'WinThreshold',
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = "$env:SystemDrive\Windows\",
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [Parameter(Mandatory = $false)]
    [string]$SysvolPath = "$env:SystemDrive\Windows\",
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]$secretName,
    [Parameter(Mandatory = $false)]
    [switch]$Force
  )
  try {
    if($PSCmdlet.ShouldProcess($DomainName,"Create a new Active Directory Forest") -or $PSCmdlet.ShouldContinue("Do you want to continue?")) {
      New-ADDSForest @PSBoundParameters
    }
    else{
      Write-Output "Operation cancelled"
    }
  }
  catch {
    throw "Failed to create the new AD Forest. Please see the error message below.:$_"
  }
}
# End of the functions to install and configure new AD Forest.
#  New funtions to Add additonal Domain Controller
function Add-ADDomainController {
  param(
    [string]$DomainName,
    [string]$SiteName = 'Default-First-Site-Name',
    [string]$DatabasePath = "$env:SystemDrive\Windows\",
    [string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [string]$SysvolPath = "$env:SystemDrive\Windows\",
    [string]$KeyVaultName,
    [string]$ResourceGroupName,
    [string]$SafeModeAdminSecretName,
    [string]$DomainAdminSecretName,
    [string]$DomainAdminUser
  )
  # set paths
  $DatabasePath = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
  $LogPath = New-EnvPath -Path $LogPath -ChildPath 'ntds'
  $SysvolPath = New-EnvPath -Path $SysvolPath -ChildPath 'sysvol'
  # install required modules
  Install-RequiredModule
  Install-RequiredADModule
  # connect to azure
  Connect-ToAzure
  # get the vault
  Get-Vault
  Add-RegisteredSecretVault
  # define common parameters
  $commonParams = @{
    DomainName = $DomainName
    SiteName = $SiteName
    DatabasePath = $DatabasePath
    LogPath = $LogPath
    SysvolPath = $SysvolPath
    Force = $true
  }
  # retrieve the safe mode admin password
  $vaultName = (Get-Vault).VaultName
  $credential = New-Object System.Management.Automation.PSCredential ($DomainAdminUser, (Get-Secret -Name $DomainAdminSecretName -Vault $vaultName))
  [securestring]$safeModeAdministratorPassword = Get-Secret -Name $SafeModeAdminSecretName -Vault $vaultName
  $param = $commonParams.Clone()
  $keys = @{
    SafeModeAdministratorPassword = $safeModeAdministratorPassword
    Credential = $credential
  }
  Add-keys -hash $param -keys $keys  
  
  try {
    # add the domain controller6-**
    Install-ADDSDomainController @param
  }
  catch {
    Write-Error "Failed to add the domain controller. Please see the error message below.:$_"
  }
  finally {
    # remove the registered secret vault
    Remove-RegisteredSecretVault
    # disconnect from azure
    Disconnect-FromAzure
  }
}
function New-ADDSDomainController{
  <#
  .SYNOPSIS
    This function is used to add an additional domain controller to an existing forest/domain.
  .DESCRIPTION
    This module is used to add an additional domain controller to an existing forest/domain.
    It installs the required modules, connects to Azure, gets the vault, adds the registered secret vault, defines common parameters, retrieves the safe mode administrator password, creates a secure credential object, retrieves the domain admin password, adds the domain controller, removes the registered secret vault, and disconnects from Azure after the operation.
  .PARAMETER DomainName
    The fully qualified domain name of the existing forest/domain.
  .PARAMETER SiteName
    The name of the site where the new domain controller will be located. This is set to 'Default-First-Site-Name' by default.
  .PARAMETER DatabasePath
    The path to the database folder of the new domain controller. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER LogPath
    The path to the log folder of the new domain controller. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER SysvolPath
    The path to the sysvol folder of the new domain controller. This is set to the default path of the system drive by default. But you can specify a different path (recommended).
  .PARAMETER KeyVaultName
    The name of the key vault in Azure.
  .PARAMETER ResourceGroupName
    The name of the resource group in Azure where the key vault is located.
  .PARAMETER SafeModeAdminSecretName
    The name of the secret in the key vault that contains the safe mode administrator password.
  .PARAMETER DomainAdminSecretName
    The name of the secret in the key vault that contains the domain administrator password.
  .PARAMETER DomainAdminUser
    The username of the domain administrator.
  .PARAMETER Force
    This is a switch parameter that forces the operation to continue without prompting for confirmation.
  .NOTES
    File Name      : Add-ADDomainController
    Author         : Olamide Olaleye
    Prerequisite   : PowerShell 7.2 and above.
  .LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
  .EXAMPLE
 New-ADDSDomainController -DomainName "contoso.com" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -SafeModeAdminSecretName "safemodeadminpassword" -DomainAdminSecretName "domainadminpassword" -DomainAdminUser "domainadmin"
    This example adds an additional domain controller to an existing forest/domain with the specified parameters.
    The function assumes default values for the SiteName, DatabasePath, LogPath, and SysvolPath parameters.
  .EXAMPLE
  New-ADDSDomainController -DomainName "contoso.com" -SiteName "NewSite" -DatabasePath "D:\" -LogPath "e:\" -SysvolPath "F:\" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -SafeModeAdminSecretName "safemodeadminpassword" -DomainAdminSecretName "domainadminpassword" -DomainAdminUser "domainadmin" -Force
    This example adds an additional domain controller to an existing forest/domain with the specified parameters.
    The function specifies the SiteName, DatabasePath, LogPath, and SysvolPath parameters.
    There is no requirement to specify the database, log and sysvol directory folders as the default values are used.
  .INPUTS
    System.String
  .OUTPUTS
    System.String
  #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter (Mandatory = $true)][string]$DomainName,
    [Parameter (Mandatory = $false)][string]$SiteName = 'Default-First-Site-Name',
    [Parameter (Mandatory = $false)][string]$DatabasePath = "$env:SystemDrive\Windows\",
    [Parameter (Mandatory = $false)][string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [Parameter (Mandatory = $false)][string]$SysvolPath = "$env:SystemDrive\Windows\",
    [Parameter (Mandatory = $true)][string]$KeyVaultName,
    [Parameter (Mandatory = $true)][string]$ResourceGroupName,
    [Parameter (Mandatory = $true)][string]$SafeModeAdminSecretName,
    [Parameter (Mandatory = $true)][string]$DomainAdminSecretName,
    [Parameter (Mandatory = $true)][string]$DomainAdminUser,
    [Parameter (Mandatory = $false)][switch]$Force
  )
  try {
    if($PSCmdlet.ShouldProcess($DomainName,"Add a new domain controller") -or $PSCmdlet.ShouldContinue("Do you want to continue?")){
      Add-ADDomainController @PSBoundParameters
    }
    else{
      Write-Output "Operation cancelled"
    }
  }
  catch {
    Write-Error "Failed to add the domain controller. Please see the error message below.:$_"
  }
}
# Export the functions in the module.
Export-ModuleMember -Function New-ADForest -Cmdlet New-ADForest
Export-ModuleMember -Function New-ADDSDomainController -Cmdlet Add-ADDomainController