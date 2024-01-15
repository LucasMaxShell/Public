<# 
TDX_ADGroupSync.ps1 Overview

    This script's primary function is to synchronize members between an Active Directory group and a TeamDynamics (TDX) group. It operates as follows:

    1. Retrieves members from the Active Directory group specified by $GroupName (see line 55).
    2. Fetches members from the TDX group identified by $groupid (see line 98).
    3. Compares the two lists of members and identifies discrepancies.
    4. If a member is in the AD group but not in the TDX group, they are added to the $Add2TDX variable. Conversely, if a member is in the TDX group but not in the AD group, they are added to the $RemoveFrom variable.

    The UIDFetch function then takes these variables and fetches the corresponding UIDs (User IDs) from TDX using the primary email as the username. These UIDs are stored in either $UIDAddArray or $UIDRemoveArray. This step is necessary because the TDX API requires UIDs for adding or removing members.

    Special formatting is required if there's only a single UID in the array (refer to the if-statement on lines 168-174 for an example).

    Post-main function of the script, the script validates the success of the synchronization:
    
    - The TestSync function ensures a clean run by clearing out variables and rerunning the ADPull, TDXPull, and Sorting functions.
    - It then checks the count of $UIDAddArray and $UIDRemoveArray. If these counts are not zero, it indicates that the sync was unsuccessful, and the script logs the remaining discrepancies.
    - The script includes error-catching mechanisms within the logging system for process failure detection.

    The log file is named "(time)_Sync_Success" or "(time)_Sync_Failure", based on the $syncStatus variable.
    This variable is set to $true only if the counts of the arrays ($UIDAddArray and $UIDRemoveArray) are both zero, indicating a successful synchronization.
#>
# Define the directory path for logs
# Update these paths to your desired log file location
$logDirPath = "C:\temp\TDXsync"
$logFileName = "Sync_Log.txt"
Initialize-Logging -LogDirPath $logDirPath -LogFileName $logFileName

# Function to initialize logging
function Initialize-Logging {
    param(
        [string]$LogDirPath,
        [string]$LogFileName
    )
    New-Item -ItemType Directory -Path $LogDirPath -Force | Out-Null
    $script:logFilePath = Join-Path $LogDirPath $LogFileName
    $startTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log "***Starting Sync***"
    Write-Log "Sync started at: $startTimestamp"
    Write-Log ""
}

# Function to write a log entry
function Write-Log {
    param(
        [string]$Message
    )
    Add-Content -Path $script:logFilePath -Value "$Message"
}

# Update needed within this function
function ADPull {
    # Update this with the desired group
    param([string]$global:GroupName = 'TDX-Test-Lucas')

    # Fetch the AD Group and members within
    $Group = Get-ADGroup -Identity $GroupName -Properties *
    if ($Group -ne $null) {
        $GroupMembers = Get-ADGroupMember -Identity $Group
        $ADMemberarray = @()
        foreach ($Member in $GroupMembers) {
            $ADMembers = $Member.name + "@cmich.edu"
            $ADMemberarray += $ADMembers
        }
        return $ADMemberarray
    } else {
        Write-Log "Group '$GroupName' not found."
        return @()
    }
}

# Updates needed within this function
function TdxPull {
    # API Call to TDX for Group Membership
    # This is currently pointed at the SB
    $global:baseuri = "https://apiLink.com/apiConnector"
    $authurl = $baseuri + "api/auth/loginadmin"

    # Currently using LM-API Test API account for this test, be sure to update for Prod.
    $body = New-Object -TypeName psobject -Property @{
        BEID="ID" 
        WebServicesKey="Key"
    } | Convertto-Json -Depth 2

    $authResponse = Invoke-RestMethod -Uri $authurl -Method Post -Body $body -ContentType "application/json"

    $bearerToken = $authResponse

     # Headers must be set as global
    $global:headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
        "Authorization" = "Bearer " + $bearerToken
        }
    # Update this to the desired TDX Group, currently this is group TDXGroup-Test-Lucas
    # groupid must be set as global
    $global:groupid = '####'

    $memberuri = $baseuri + "api/groups/$groupid/members"

    $TDXResult = Invoke-RestMethod -Uri $memberuri -Method Get -Headers $headers
    $tdxusers = $TDXResult | ForEach-Object { $_.Username }

    return $tdxusers
}

function Sorting {
        param(
        [Parameter(Mandatory)]
        [array]$tdxusers,
        [Parameter(Mandatory)]
        [array]$ADMemberarray
    )
    $differences = $null
    $RemoveFrom = $null
    $Add2TDX = $null
    # Comparing the results
    $differences = Compare-Object -ReferenceObject $tdxusers -DifferenceObject $ADMemberarray
    
    # Determine who needs to be removed from the TDX group
    $RemoveFrom = $differences | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject

    # Determine who needs to be added to the TDX group
    $Add2TDX = $differences | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
    
    # Return the lists
    return @{
        RemoveFrom = $RemoveFrom
        Add2TDX = $Add2TDX
    }
}

function UIDfetch {
    param(
        [Parameter(Mandatory)]
        [array]$Usernames,
        [Parameter(Mandatory)]
        [string]$baseuri,
        [Parameter(Mandatory)]
        [hashtable]$headers
    )
    
    $UIDArray = @()
    foreach ($User in $Usernames) {
        $global:searchuri = $baseuri + "api/people/lookup?searchText=$User&maxResults=1"
        $TDXSearch = Invoke-RestMethod -Uri $searchuri -Method Get -Headers $headers
        $UIDArray += $TDXSearch.uid
    }

    return $UIDArray
}

function RemoveUsers {
    param(
        [Parameter(Mandatory)]
        [array]$UIDRemoveArray,
        [Parameter(Mandatory)]
        [string]$baseuri,
        [Parameter(Mandatory)]
        [string]$groupid,
        [Parameter(Mandatory)]
        [hashtable]$headers
    )

    $body = $null

    if ($UIDRemoveArray.Count -eq 1) {
        # Encapsulate the single UID in an array
        $formattedRemoveUID = '["' + $($UIDRemoveArray -join '","') + '"]'  
    } else {
        # If not a single element, return the array as is
        $formattedRemoveUID = $UIDRemoveArray | ConvertTo-Json
    }

    $body = $formattedRemoveUID 

    $Removeuri = $baseuri + "api/groups/$groupid/members"

    try {
        $TDXRemove = Invoke-RestMethod -Uri $Removeuri -Method Delete -Headers $headers -Body $body
    } catch {
        Write-Log "Error: $($_.Exception.Message)" 
    }
}

function AddUsers {
    param(
        [Parameter(Mandatory)]
        [array]$UIDAddArray,
        [Parameter(Mandatory)]
        [string]$baseuri,
        [Parameter(Mandatory)]
        [string]$groupID,
        [Parameter(Mandatory)]
        [hashtable]$headers
    )
    $body = $null

    if ($UIDAddArray.Count -eq 1) {
        # Encapsulate the single UID in an array
        $formattedAddUID = '["' + $($UIDAddArray -join '","') + '"]'  
    } else {
        # If not a single element, return the array as is
        $formattedAddUID = $UIDAddArray | ConvertTo-Json
    }

    $body = $formattedAddUID 
   
    # Construct the URI for adding users to the TDX group
    $Adduri = $baseuri + "api/groups/$groupID/members"

    try {
        # Invoke the API request to add users
        $TDXAdd = Invoke-RestMethod -Uri $Adduri -Method Post -Headers $headers -Body $body
        } catch {
       Write-Log  "Error: $($_.Exception.Message)"
    }
}

# TestSync clear variables and validate by repeating steps 1-3 of Main then checking for sorted results greater than 0 to determine $syncStatus
function TestSync {
    # Reset variables
    $ADMemberarray = $null
    $TDXResult = $null
    $tdxusers = $null
    $sortResult = $null
    $differences = $null
    $RemoveFrom = $null
    $Add2TDX = $null

    Write-Log "***Validating Sync***"
    Write-Log ""

        try {
        # 1. Call ADPull to get AD group members
        $ADMemberarray = ADPull -GroupName '$GroupName' -ErrorAction Stop

        # 2. Call TdxPull to get TDX group members
        $tdxusers = TdxPull -ErrorAction Stop

        # 3. Call Sorting to compare AD and TDX members
        $sortResult = Sorting -tdxusers $tdxusers -ADMemberarray $ADMemberarray -ErrorAction Stop

        Write-Log "Post Sync Number of Users to remove from TDX: $($sortResult.RemoveFrom.Count)"
        Write-Log "Post Sync Number of Users to Add to TDX Group: $($sortResult.Add2TDX.Count)"
        Write-Log ""

        #4. Check that there are no users to be added/removed
        if ((-not $sortResult.RemoveFrom -or $sortResult.RemoveFrom.Count -eq 0) -and
                (-not $sortResult.Add2TDX -or $sortResult.Add2TDX.Count -eq 0)) {
                $syncStatus = $true

                Write-Log "Success: No users to remove or add to TDX group."

            } else {
                $syncStatus = $false
            if ($sortResult.RemoveFrom -and $sortResult.RemoveFrom.Count -gt 0) {
                Write-Log "Failure: Issue with sync - Users to remove exist."
            }
            if ($sortResult.Add2TDX -and $sortResult.Add2TDX.Count -gt 0) {
                Write-Log "Failure: Issue with sync - Users to add exist."
            }
        }
        return $syncStatus
        Write-Log ""
    } catch {
        Write-Log "An error occurred in TestSync: $($_.Exception.Message)"
    }
}

#Main process
try {

    # 1. Call ADPull to get AD group members
    $ADMemberarray = ADPull -GroupName '$GroupName' -ErrorAction Stop

    Write-Log "Current AD Group Members: $($ADMemberarray.Count)"

    # 2. Call TdxPull to get TDX group members
    $tdxusers = TdxPull -ErrorAction Stop

    Write-Log "Current TDXGroup Members: $($tdxusers.Count)"
    Write-Log ""
    
    # 3. Call Sorting to compare AD and TDX members
    $sortResult = Sorting -tdxusers $tdxusers -ADMemberarray $ADMemberarray -ErrorAction Stop

    # 4. Fetch UIDs for users to be removed from TDX group
    $UIDRemoveArray = $null
    if ($sortResult.RemoveFrom -and $sortResult.RemoveFrom.Count -gt 0) {
        $UIDRemoveArray = UIDfetch -Usernames $sortResult.RemoveFrom -baseuri $baseuri -headers $headers -ErrorAction Stop

        Write-Log "Number of Users to remove from TDX: $($UIDRemoveArray.Count)"

    } else {

        Write-Log "No users to remove from TDX group."
    }
    # 5. Fetch UIDs for users to be added to TDX group
    $UIDAddArray = $null
    if ($sortResult.Add2TDX -and $sortResult.Add2TDX.Count -gt 0) {
        $UIDAddArray = UIDfetch -Usernames $sortResult.Add2TDX -baseuri $baseuri -headers $headers -ErrorAction Stop

        Write-Log "Number of Users to Add to TDX Group: $($UIDAddArray.count)"
            
    } else {

        Write-Log "No users to add to TDX group."
    }
    # 6. Call RemoveUsers (passing the UIDs) to remove users from TDX group
    if ($UIDRemoveArray -and $UIDRemoveArray.Count -gt 0) {
        RemoveUsers -UIDRemoveArray $UIDRemoveArray -baseuri $baseuri -groupid $groupid -headers $headers -ErrorAction Stop
    }
    else {

        Write-Log ""
    }
    # 7. Call AddUsers (passing the UIDs) to add users to TDX group
    if ($UIDAddArray -and $UIDAddArray.Count -gt 0) {
        AddUsers -UIDAddArray $UIDAddArray -baseuri $baseuri -groupID $groupid -headers $headers -ErrorAction Stop
    }
    else {

        Write-Log ""
    }
} catch {
    Write-Log "An error occurred: $($_.Exception.Message)"
}

# Post Main process validation
$syncStatus = TestSync

# Final logging steps
$endTimestamplog = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Log ""
Write-Log "Sync ended at: $endTimestamplog"

$endTimestampFN = Get-Date -Format "yyyy-MM-dd"
$newLogFileName = if ($syncStatus) {
    "$($endTimestampFN)_Sync_Success.txt"
} else {
    "$($endTimestampFN)_Sync_Failure.txt"
}
$newLogFilePath = [System.IO.Path]::Combine((Split-Path $logFilePath -Parent), $newLogFileName)

# Rename the log file
if (Test-Path -Path $newLogFilePath) {
    # If a file with the same name exists, delete or handle it
    Remove-Item -Path $newLogFilePath -Force
}
Rename-Item -Path $logFilePath -NewName $newLogFileName
