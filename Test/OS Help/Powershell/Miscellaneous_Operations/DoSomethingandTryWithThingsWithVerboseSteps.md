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

# Filter instances for 'aur' in the ne

$aurInstances = $instances | Where-Object { $_ -match 'aur' }

Write-Host "Filtered instances for 'aur' in the ne."


# Check if aurInstances variable is null or empty

if ([string]::IsNullOrEmpty($aurInstances)) {

    Write-Host "Error: No instances containing 'aur' in the ne found."

    exit

}

# Credentials for the attempts

$credentials = @(

    @{ Userne = 'aurasysadmin'; Password = 'ps3]qcMr-cd~pnMNg3X[z2wEyuuTyPur_QJd+qsE9vEr[@!9TCAbzY_A5jnT-b33j82FfCexjP$!W]s_x6aY(W2FhzNkB*(venAqw4HW+7cXX2w9TEZuU-S]|S-qu*q' },

    @{ Userne = 'aurasysadmin'; Password = 'mX(1_nZRmyS3a{8MabVUbktAEJgBa~FKqGFN6yK9ANv_uKzpXp}ynXtQMUYmQkw7FzZaTu]fCAxW0NqRpweBrRGSU[uh5PzyDSDLwmDw|dEKzh4puR2BttgHj!gmj)y' }

)

Write-Host "Credentials prepared for connection attempts."

# Iterate through filtered instances and credentials

foreach ($instance in $aurInstances) {

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