```powershell
<# 
 
.SYNOPSIS
    Script to create a differencing list between Guest accounts in an Azure AD tenant and an on-prem Active Directory OU
    Includes options to 
    - create users in the OU who exist in AAD and are members of a specified group but are not present in the AD
    - optionally disable and move  accounts in the OU who no longer exist in Azure AD to a different OU
    - optionally delete accounts in the OU who no longer exist in Azure AD

    This would be used to create shadow accounts in AD for use by Application Proxy for KCD delegation for B2B Guest accounts.

    The shadow account will be created with the following properties:
            -AccountPassword = random strong password
            -ChangePasswordAtLogon = $false
            –PasswordNeverExpires = $true
            -SmartcardLogonRequired = $true

    NOTE - this does not have support for nesting in the AAD Group

.DESCRIPTION

    Version: 1.0.2

    This is currently a beta level script and intended to be used as a demonstration script

.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>

<#
Recommended ToDo/caveats for production deployments
- add certificate based authentication for Service Principal ne
- decide on where and whether to filter on active/disabled AAD status
- At the moment script takes first 20 characters of the UPN
- if the B2B user is re-invited after having been deleted and the shadow account is archived, recreation of a new shadow accounn will fail. 
- there is no error handling if Add-AdUser call fails
- add reporting - should be off by default but available for troubleshooting
/ToDo/caveats
#>


<# FUNCTIONS #>
function InitEventLog {
    process {
        if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false) { 
            Write-Host "Creating event source $source on event log $log" 
            [System.Diagnostics.EventLog]::CreateEventSource($source, $log)
            Write-Host -foregroundcolor green "Event source $source created"
        } 
    }
}

function WriteInfo($message) {
    process {
        Write-Host $message -foregroundColor Blue -backgroundcolor White
        Write-EventLog –Logne $log –Source $source –EntryType Information –EventID 1 –Message $message
    }
}

function WriteError($error) {
    process {
        Write-Host "`nError: $error`n" -Foregroundcolor white -Backgroundcolor darkred
        Write-EventLog –Logne $log –Source $source –EntryType Error –EventID 1 –Message "Synchronization Run Script Error: $error"
    }
}

<# MAIN #>

# Define the event log source
$source = "AAD-B2B.Guest.Synchronization"
$log = "Application"
$debug = $true

# Initialize the Event Log (i.e. create it if it doesn't exist)
InitEventLog

# Define application title
$title = "AAD B2B Guest Account"

# Define AAD B2B variables
$aadB2bGroups = @("GMB,282")

$adShadowAccountOU = "<DEFINIR>" #Organizational Unit for placing shadow accounts
$adShadowAccountOUArchive = "<DEFINIR>" #Organizational Unit for moving disabled shadows
$createMissingAdShadowAccounts = $true

# Only one of the following should be true. If both are True then the "disable" action takes precedence
$disableOrphanedAdShadowAccounts = $true
$deleteOrphanedAdShadowAccounts = $false

# Requires Azure AD configuration
$aadB2bAppID = "<DEFINIR>" # Insert your application's Client ID, a Globally Unique ID (registered by Global Admin)
$aadB2BAppSecret = "<DEFINIR>"  # Insert your application's Client Key/Secret string
$aadTenantDomain = "<DEFINIR>"    # AAD Tenant; for example, contoso.onmicrosoft.com
$aadTenantID = "<DEFINIR>" # Identifier of the tenant domain

# Variable initialization
$aadTenantGuestUsersHash = @{} 
$usersInAadB2bGroupsHash = @{}
$adShadowAccountsHash = @{}
$loginURL = "https://login.microsoftonline.com/" # AAD Instance; for example https://login.microsoftonline.com for public or https://login.microsoftonline.us for government cloud
$resource = "https://graph.windows.net"

try {
    WriteInfo ("Beginning {0} synchronization run: {1}" -f $title, (Get-Date))

    # Connect to Azure AD through the app registration w/ app secret
    $body = @{grant_type = "client_credentials"; resource = $resource; client_id = $aadB2BAppID; client_secret = $aadB2BAppSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$aadTenantDomain/oauth2/token?api-version=1.5 -Body $body 
    Connect-AzureAD -AadAccessToken $oauth.access_token -TenantId $aadTenantID -AccountId $aadB2BAppID

    # Populate hash table with all Guest users from AAD tenant using object ID as key
    if ($debug) { WriteInfo "Retrieving Guest users from AAD tenant..." }
    Get-AzureADUser -All $true -Filter "userType eq 'Guest'" |  `
        ForEach-Object {$aadTenantGuestUsersHash[$_.ObjectId] = $_}

    # Populate hash table with membership of target Azure AD groups using object ID as key
    # we will then reference across into the Guest user hash table as needed.
    if ($debug) { WriteInfo "Retrieving memberships from defined AAD groups..." }
    foreach ($group in $aadB2bGroups) {
        if ($debug) { WriteInfo ("Retrieving Guest users from AAD group '{0}'..." -f ($group.Split(',')[0])) }
        
        $aadB2bGroupsId = $group.Split(',')[1]
        Get-AzureADGroupMember -ObjectId $aadB2bGroupsId -all $true | `
            ForEach-Object {$usersInAadB2bGroupsHash[$_.ObjectId] = $_}
    }

    # Populate hash table with all accounts in shadow account OU using UPN as key
    # consider setting value to Null instead of the object as we don't use this
    if ($debug) { WriteInfo ("Retrieving shadow AD accounts from AD OU '{0}..." -f $adShadowAccountOU) }
    Get-AdUser -filter * -SearchBase $adShadowAccountOU -SearchScope OneLevel | `
        Select-Object UserPrincipalne, ne, Description | ` 
        ForEach-Object {$adShadowAccountsHash[$_.UserPrincipalne] = $_}

    # For each tenant Guest account UPN in the group check if it exists in SHadow OU hash table
    # If exists then remove from both lists
    # End state of B2B Group list will be all tenant guest accounts in the group not in the shadow OU
    # End state of shadow account list will be all shadow accounts without a matching tenant guest account
    if ($debug) { WriteInfo "Comparing list of Guest users against list of AD shadow accounts..." }
    ForEach ($key in $($usersInAadB2bGroupsHash.Keys)) {
        # remove non-guest users from the AAD Group list
        if ($aadTenantGuestUsersHash.ContainsKey($key) -eq $false) {
            # if we want to output anything about non-Guest users it needs to pull from the Group Membership hash 
            # as these users will not be in the guest users hash table e.g. 
            # $usersInAadB2bGroupsHash[$key].emailaddress
            $usersInAadB2bGroupsHash.Remove($key)
        }
        # B2B guest user already has a shadow account remove from both lists
        # we'll then end up with 2 differencing lists
        elseif ($adShadowAccountsHash.ContainsKey($aadTenantGuestUsersHash[$key].userprincipalne)) {
            # $aadtenantGuestUsersHash[$key].userprincipalne
            # Write-Host $key "account exists in both AAD group and AD OU - removing from both lists"
            $usersInAadB2bGroupsHash.Remove($key)
            $adShadowAccountsHash.Remove($aadtenantGuestUsersHash[$key].userprincipalne)
        }
    }
    
    # Write out the expected changes
    if ($debug) { 
        WriteInfo "Guest Accounts (Object ID) that need AD shadow accounts created:"
        if ($usersInAadB2bGroupsHash.Count -gt 0) { WriteInfo $usersInAadB2bGroupsHash.Keys } else { WriteInfo "N/A" }
        WriteInfo "AD shadow accounts with no matching AAD Guest account that need to be deprovisioned (disabled/deleted):"
        if ($adShadowAccountsHash.Count -gt 0) { WriteInfo $adShadowAccountsHash.Keys } else { WriteInfo "N/A" }
    }

    # Create the missing AD shadow accounts
    if ($createMissingAdShadowAccounts -eq $true) {
        if ($usersInAadB2bGroupsHash.Count -gt 0) {
            if ($debug) { WriteInfo "Creating AD shadow accounts..." }
            foreach ($key in $($usersInAadB2bGroupsHash.keys)) {
                $userPrincipalne = $aadtenantGuestUsersHash[$key].UserPrincipalne
                $email = $aadtenantGuestUsersHash[$key].Mail
                $samAccountne = $aadtenantGuestUsersHash[$key].UserPrincipalne.Substring(0, 20)
                $samAccountne = $samAccountne.Replace('@', '_')
                if ($samAccountne.EndsWith('.')) {
                    $samAccountne = $samAccountne.Substring(0, 19) + "_"
                }

                if ($debug) { (WriteInfo "Creating AD shadow account w/ UPN '{0}', email '{1}' and account ne '{2}'..." -f $userPrincipalne, $email, $samAccountne) }

                # generate random password
                $bytes = New-Object Byte[] 32
                $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $rand.GetBytes($bytes)
                $rand.Dispose()
                $RandPassword = [System.Convert]::ToBase64String($bytes)
            
                New-ADUser -ne $email `
                    -SamAccountne $samAccountne `
                    -Path $adShadowAccountOU `
                    -UserPrincipalne $userPrincipalne `
                    -Displayne $email `
                    -Description "(Guest User) $email" `
                    -AccountPassword (ConvertTo-SecureString $RandPassword -AsPlainText -Force) `
                    -ChangePasswordAtLogon $false `
                    –PasswordNeverExpires $true `
                    -SmartcardLogonRequired $true `
        
                Enable-ADAccount -Identity $samAccountne
            }
        }
    }

    # Clean up time for any Shadow Accounts where the AAD guest account no longer exists
    if ($disableOrphanedAdShadowAccounts -eq $true -or $deleteOrphanedAdShadowAccounts -eq $true) {
        if ($adShadowAccountsHash.Count -gt 0) {
            if ($debug) { WriteInfo "Deactivating AD shadow accounts..." }

            foreach ($shadow in $($adShadowAccountsHash.keys)) {
                # $upn = the key from adShadowAccountsHash = $shadow
                # disable operation takes precedence over deletion
                if ($debug) { WriteInfo ("Deactivating AD shadow account '{0}'..." -f $shadow) }
                if ($disableOrphanedAdShadowAccounts -eq $true) {
                    $user = Get-AdUser -Filter {UserPrincipalne -eq $shadow} -SearchBase $adShadowAccountOU -Properties Description
                    $upn = ("x_{0}" -f $user.UserPrincipalne)
                    $accountne = ("x_{0}" -f $user.SamAccountne)
                    if ($accountne -gt 20) { $accountne = $accountne.Substring(0,20) }
                    $desc = ("{0} - {1}" -f $user.Description, ("Disabled pending removal: {0}" -f (Get-Date -Format U)))

                    Set-ADUser -Identity $user.ObjectGuid -UserPrincipalne $upn -SamAccountne $accountne -Enabled $false -Description $desc
                    Move-ADObject -Identity $user.ObjectGuid -TargetPath $adShadowAccountOUArchive

                    #Get-AdUser -Filter {UserPrincipalne -eq $shadow} -SearchBase $adShadowAccountOU | Set-ADUser -Enabled $false -Description ("'Disabled {0} pending removal" -f () 
                    #Get-AdUser -Filter {UserPrincipalne -eq $shadow} -SearchBase $adShadowAccountOU | Move-ADObject -TargetPath $adShadowAccountOUArchive            
                }
                elseif ($deleteOrphanedAdShadowAccounts = $true) {
                    Get-AdUser -Filter {UserPrincipalne -eq $shadow} -SearchBase $adShadowAccountOU | Remove-AdUser
                }
            }
        }
    }

    WriteInfo ("{0} synchronization run completed: {1}" -f $title, (Get-Date))

    Exit 0
}
catch {
    WriteError $($_.Exception.Message)

    WriteInfo ("{0} synchronization run failed: {1}" -f $title, (Get-Date))

    Exit -1
}
```