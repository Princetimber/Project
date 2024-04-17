# Active Directory Domain Service Configuration Module using PowerShell

>
## SYNOPSIS

    This function is used to create a new Active Directory Forest in on-premises or Azure.

### DESCRIPTION

    This module is used to create a new Active Directory Forest in on-premises or Azure.
    It installs the required modules, connects to Azure, gets the vault, adds the registered secret vault, defines common parameters, retrieves the safe mode administrator password, creates the new AD Forest, removes the registered secret vault, and disconnects from Azure after the operation.

    This module is used to add an additional domain controller to an existing forest/domain.
    It installs the required modules, connects to Azure, gets the vault, adds the registered secret vault, defines common parameters, retrieves the safe mode administrator password, creates a secure credential object, retrieves the domain admin password, adds the domain controller, removes the registered secret vault, and disconnects from Azure after the operation.

#### PARAMETER DomainName

    The fully qualified domain name of the new AD Forest.

#### PARAMETER DomainNetBiosName

    The NetBIOS name of the new AD Forest.

#### PARAMETER DomainMode

    The domain functional level of the new AD Forest. This is set to 'WinThreshold' by default.

#### PARAMETER ForestMode

    The forest functional level of the new AD Forest. This is set to 'WinThreshold' by default.

#### PARAMETER DatabasePath

    The path to the database folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).

#### PARAMETER LogPath

    The path to the log folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).

#### PARAMETER SysvolPath

    The path to the sysvol folder of the new AD Forest. This is set to the default path of the system drive by default. But you can specify a different path (recommended).

#### PARAMETER KeyVaultName

    The name of the key vault in Azure.

#### PARAMETER ResourceGroupName

    The name of the resource group in Azure where the key vault is located.

#### PARAMETER secretName

    The name of the secret in the key vault that contains the safe mode administrator password.

#### PARAMETER SiteName

    The name of the site where the new domain controller will be located. This is set to 'Default-First-Site-Name' by default.

#### PARAMETER DomainAdminSecretName

    The name of the secret in the key vault that contains the domain administrator password.

#### PARAMETER DomainAdminUser

    The username of the domain administrator.

#### PARAMETER Force

    This is a switch parameter that forces the operation to continue without prompting for confirmation.    

### NOTES

    File Name      : New-ADForest, Add-ADDSDomainController
    Author         : Olamide Olaleye
    Prerequisite   : PowerShell 7.2 and above.

### LINK

    Specify a URI to a help page, this will show when Get-Help -Online is used.

### EXAMPLE 1

    New-ADForest -DomainName "contoso.com" -DomainNetBiosName "CONTOSO" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -secretName "safemodeadminpassword"
    - This example creates a new Active Directory Forest with the specified parameters.
    - The function assumes default values for the DomainMode, ForestMode, DatabasePath, LogPath, and SysvolPath parameters.

### EXAMPLE 2

    New-ADForest -DomainName "contoso.com" -DomainNetBiosName "CONTOSO" -DatabasePath "D:\" -LogPath "e:\" -SysvolPath "F:\" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -secretName "safemodeadminpassword" -Force
    - This example creates a new Active Directory Forest with the specified parameters.
    - The function specifies the DatabasePath, LogPath, and SysvolPath parameters.
    - There is no requirement to specify the database, log and sysvol directory folders as the default values are used.

#### EXAMPLE 3

    New-ADDSDomainController -DomainName "contoso.com" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -SafeModeAdminSecretName "safemodeadminpassword" -DomainAdminSecretName "domainadminpassword" -DomainAdminUser "domainadmin"
    - This example adds an additional domain controller to an existing forest/domain with the specified parameters.
    - The function assumes default values for the SiteName, DatabasePath, LogPath, and SysvolPath parameters.

#### EXAMPLE 4

    New-ADDSDomainController -DomainName "contoso.com" -SiteName "NewSite" -DatabasePath "D:\" -LogPath "e:\" -SysvolPath "F:\" -KeyVaultName "mykeyvault" -ResourceGroupName "myresourcegroup" -SafeModeAdminSecretName "safemodeadminpassword" -DomainAdminSecretName "domainadminpassword" -DomainAdminUser "domainadmin" -Force
    - This example adds an additional domain controller to an existing forest/domain with the specified parameters.
    - The function specifies the SiteName, DatabasePath, LogPath, and SysvolPath parameters.
    - There is no requirement to specify the database, log and sysvol directory folders as the default values are used.

### INPUTS

    System.String

### OUTPUTS

    System.String
