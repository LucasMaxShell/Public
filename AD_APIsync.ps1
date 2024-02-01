<# TDX_ADGroupSync.ps1 Overview

    Purpose:
    This PowerShell script automates the synchronization of user memberships between an Active Directory (AD) group and a TeamDynamics (TDX) group. It ensures that the memberships in both systems are consistent.

    Key Processes:
    1. Member Retrieval: Extracts member lists from both AD and TDX groups.
    2. Comparison: Identifies discrepancies between the two member lists.
    3. Synchronization Actions: Based on the comparison, it determines members to add to or remove from the TDX group.
    4. UID Handling: Fetches User IDs (UIDs) from TDX for synchronization actions since TDX API requires UIDs.
    5. Update TDX Group: Executes API calls to add or remove members in the TDX group as needed.
    6. Validation and Logging: After the synchronization, the script validates the results and logs the process. Logs are named based on the synchronization status (success or failure).

    Error Handling:
    The script includes robust error-catching mechanisms to log any issues during the synchronization process.

    Email Notifications:
    In case of a sync failure, an email alert is sent with the log file attached for further analysis.

    Usage:
    The script iterates through each row in a CSV file to process multiple groups. Variables such as group names and IDs are defined in the CSV.

    Customization:
    - Logging paths, CSV file path, SMTP server details, and email addresses for notifications are configurable.
#>

#region Defining Variables
    # Define the directory path for logs
        $logDirPath = "TDXsync"
        $logFileName = "Sync_Log.txt"
        $script:logFilePath = Join-Path $LogDirPath $LogFileName
#endregion

#region Importing UID's through CSV
    # Define the path to your CSV file
        $csvPath = "TDXsync\Groups.csv"
    # Import the CSV file
        $csvData = Import-Csv -Path $csvPath
#endregion

#region Functions

# Function to write a log entry
    function Write-Log {
    param(
            [string]$Message
        )
        Add-Content -Path $script:logFilePath -Value "$Message"
    }

# Function to initialize logging
    function Initialize-Logging {
        param(
            [string]$LogDirPath,
            [string]$LogFileName
        )
        New-Item -ItemType Directory -Path $LogDirPath -Force | Out-Null

        $startTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Log ""
        Write-Log "***Starting Sync***"
        Write-Log ""
        Write-Log "Sync started at: $startTimestamp"
        Write-Log ""
    }
# Call to ActiveDirctory to fetch group members
    function ADPull {
        # Fetch the AD Group and members within, including nested groups
        $Group = Get-ADGroup -Identity $GroupName -Properties *
        if ($Group -ne $null) {
            # The -Recursive parameter is used to get members of nested groups
            $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive
            $ADMemberArray = @()

            foreach ($Member in $GroupMembers) {
                # Check if the member is a user
                if ($Member.objectClass -eq 'user') {
                    $ADMember = $Member.name + "@cmich.edu"
                    $ADMemberArray += $ADMember
                }
            }
            return $ADMemberArray
        } else {
            Write-Log "Group '$GroupName' not found."
            return @()
        }
    }

# Updates needed within TDXPull function
# API Call to TDX to fetch group members
    function TdxPull {
    # This is currently pointed at the SB
        $global:baseuri = "https://teamdynamix.com/SBTDWebApi/"
        $authurl = $baseuri + "api/auth/loginadmin"
    # Currently using LM-API Test API account for this test, be sure to update for Prod.
    # BEID & WEBKEY val passed through Jenkins
        $body = New-Object -TypeName psobject -Property @{
            BEID=$env:BEID
            WebServicesKey=$env:WEBKEY
        } | ConvertTo-Json -Depth 2
        $authResponse = Invoke-RestMethod -Uri $authurl -Method Post -Body $body -ContentType "application/json"
        $bearerToken = $authResponse
        # Headers must be set as global
        $global:headers = @{
            "Content-Type" = "application/json"
            "Accept" = "application/json"
            "Authorization" = "Bearer " + $bearerToken
            }
        $memberuri = $baseuri + "api/groups/$groupid/members"
        $TDXResult = Invoke-RestMethod -Uri $memberuri -Method Get -Headers $headers
        $tdxusers = $TDXResult | ForEach-Object { $_.Username }

        return $tdxusers
    }

# Powershell process to sort members to Add or Remove variables
    function Sorting {
            param(
            [Parameter(Mandatory)]
            [array]$tdxusers,
            [Parameter(Mandatory)]
            [array]$ADMemberarray
        )

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

# TDX ADD/REMOVE API calls wont accept GIDS, so here we fetch UID from TDX based on GID from AD
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
# API call to remove users from TDX Group
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
        # Clearing some values to avoid unintentionally stored values being passed during the looped process
        $body = $null
        $formattedRemoveUID = $null

        # Due to how Powershell handles arrays with only a single value, special formatting has to occur because otherwise, it is 'unboxed' and doesn't get properly converted to JSON for the API
        if ($UIDRemoveArray.Count -eq 1) {
            # Encapsulate the single UID in an array
            $formattedRemoveUID = '["' + $($UIDRemoveArray -join '","') + '"]'  
        } else {
            # If not a single element, return the array as is
            $formattedRemoveUID = $UIDRemoveArray | ConvertTo-Json
        }

        $body = $formattedRemoveUID 

        # Construct the URI for removing users from the TDX Group
        $Removeuri = $baseuri + "api/groups/$groupid/members"

        try {
            # Invoke the API request to remove users
            $TDXRemove = Invoke-RestMethod -Uri $Removeuri -Method Delete -Headers $headers -Body $body
        } catch {
            Write-Log "Error: $($_.Exception.Message)" 
        }
    }
# API call to remove users from TDX Group
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
        # Clearing some values to avoid unintentionally stored values being passed during the looped process
        $body = $null
        $formattedAddUID = $null

        # Due to how Powershell handles arrays with only a single value, special formatting has to occur because otherwise, it is 'unboxed' and doesn't get properly converted to JSON for the API
        if ($UIDAddArray.Count -eq 1) {
            # Encapsulate the single UID in an array
            $formattedAddUID = '["' + $($UIDAddArray -join '","') + '"]'  
        } else {
            # If not a single element, return the array as is
            $formattedAddUID = $UIDAddArray | ConvertTo-Json
        }

        $body = $formattedAddUID 
    
        # Construct the URI for adding users to the TDX Group
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
        
        #region Reset variables to prevent false readings during the TestSync process
        $ADMemberarray = $null
        $TDXResult = $null
        $tdxusers = $null
        $sortResult = $null
        $differences = $null
        $RemoveFrom = $null
        $Add2TDX = $null
        #endregion

        Write-Log ""
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
            # Passing syncStatus value so the success or failure can be logged and notifications can be sent if needed
            return $syncStatus
            Write-Log ""
        } catch {
            Write-Log "An error occurred in TestSync: $($_.Exception.Message)"
        }
        # In step 3 of the main loop, if zero members are pulled from AD then the Flag gets set to 1, this is only to initate the error message below for better visibility.
        if ($Flag -eq 1) {
            Write-Log ""
            Write-Log "No members in Active Directory $($GroupName), check spelling of group in $($csvPath), otherwise you might need to manually remove all group members in TDX."
            Write-Log ""
        }
    }

# Email functionality contained, to edit sender/destination change variables contained within Send-LogEmail.
    function Send-LogEmail {
       param(
           [string]$LogFilePath  # Changed parameter to accept full file path
       )
       # Verifing log path so it can be attached to the failure email
       $FullLogPath = Join-Path -Path $logDirPath -ChildPath $LogFileName

       # Define fixed email parameters
       $Subject = "TDX to AD Sync Failure Alert"
       $Body = "The synchronization has failed. Please see the attached log."
       $SmtpServer = "smtp.0365.com"
       $From = "Notification@domain.com"
       $To = "monitoringEmail@domain.com"

       # Send the email
       Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $Body -Attachments $LogFilePath
    } 
#endregion

#region Main Process

#region Loop

    # Clear the log file at the start of the script
    if (Test-Path -Path $script:logFilePath) {
        # This will clear the file if it exists
        Clear-Content -Path $script:logFilePath
    }

    # Loop through each row in the Groups CSV
    foreach ($row in $csvData) {
        # Check if either value is missing or empty
        if ([string]::IsNullOrWhiteSpace($row.ActiveDirectoryGroupName) -or [string]::IsNullOrWhiteSpace($row.TeamDynamicsGroupNumber)) {
            Write-Log "Skipping incomplete row: AD Group Name - $($row.ActiveDirectoryGroupName), TDX Group ID - $($row.TeamDynamicsGroupNumber)"
            continue
        }

        # Assign values to variables
        $GroupName = $row.ActiveDirectoryGroupName
        $groupid = $row.TeamDynamicsGroupNumber
        Write-Log "Processing AD group: $GroupName with TDX GROUP ID: $groupid"

            #region Sync process
            Initialize-Logging -LogDirPath $logDirPath -LogFileName $logFileName
            try {
            
                # Reset variables
                $ADMemberarray = $null
                $TDXResult = $null
                $tdxusers = $null
                $sortResult = $null
                $differences = $null
                $RemoveFrom = $null
                $Add2TDX = $null
                $Flag = 0
            
                # 1. Call ADPull to get AD group members
                $ADMemberarray = ADPull -GroupName '$GroupName' -ErrorAction Stop
            
                Write-Log "Current AD Group Members: $($ADMemberarray.Count)"
            
                # 2. Call TdxPull to get TDX group members
                $tdxusers = TdxPull -ErrorAction Stop
            
                Write-Log "Current TDXGroup Members: $($tdxusers.Count)"
                Write-Log ""

                # 3. Call Sorting to compare AD and TDX members
                if ($ADMemberArray.count -eq 0) {
                    Write-Log "No members in Active Directory $($GroupName), check spelling of group in $($csvPath), otherwise you might need to manually remove all group members in TDX."
                    Write-Log ""
                    # Setting $Flag eq to 1 to initiate the same error message in a friendlier location on the log just to improve visibility
                    $Flag = 1
                } elseif ($tdxusers.count -eq 0) {
                    # Set $sortResult.RemoveFrom to $null and adjust $sortResult.Add2TDX, this is to push AD group members into an empty TDX group 
                    $sortResult = New-Object PSObject -Property @{
                        RemoveFrom = $null
                        Add2TDX = $ADMemberarray
                    }
                } else {
                    # If $tdxusers is not empty, proceed with normal sync functionality
                    $sortResult = Sorting -tdxusers $tdxusers -ADMemberarray $ADMemberarray -ErrorAction Stop
                }
            
                # 4. Fetch UIDs for users to be removed from TDX group
                $UIDRemoveArray = $null
                if ($sortResult.RemoveFrom -and $sortResult.RemoveFrom.Count -gt 0) {
                    $UIDRemoveArray = UIDfetch -Usernames $sortResult.RemoveFrom -baseuri $baseuri -headers $headers -ErrorAction Stop
                
                    Write-Log "Number of Users to remove from TDX: $($UIDRemoveArray.Count)"
                    Write-Log ($sortResult.RemoveFrom -join "`n")
                
                } else {
                
                    Write-Log "No users to remove from TDX group."
                }
                # 5. Fetch UIDs for users to be added to TDX group
                $UIDAddArray = $null
                if ($sortResult.Add2TDX -and $sortResult.Add2TDX.Count -gt 0) {
                    $UIDAddArray = UIDfetch -Usernames $sortResult.Add2TDX -baseuri $baseuri -headers $headers -ErrorAction Stop
                
                    Write-Log "Number of Users to Add to TDX Group: $($UIDAddArray.count)"
                    Write-Log ($sortResult.Add2TDX -join "`n")

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
            #endregion

                #region Post Main validation
                $syncStatus = TestSync
                #endregion

                    #region Final logging and wrap-up steps
                    $endTimestamplog = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Write-Log ""
                    Write-Log "Sync ended at: $endTimestamplog"
                    $endTimestampFN = Get-Date -Format "yyyy-MM-dd"
                    $newLogFileName = if ($syncStatus) {
                        "$($GroupName)_Sync_Success.txt"
                    } else {
                        "$($GroupName)_Sync_Failure.txt"
                    }

                    $newLogFilePath = [System.IO.Path]::Combine((Split-Path $logFilePath -Parent), $newLogFileName)

                    # Rename the log file
                    if (Test-Path -Path $newLogFilePath) {
                        # If a file with the same name exists, delete or handle it
                        Remove-Item -Path $newLogFilePath -Force
                    }
                    Rename-Item -Path $logFilePath -NewName $newLogFileName

                    # Check sync status and send an email if there's a failure
                    if (-not $syncStatus) {
                        Send-LogEmail -LogFilePath $newLogFilePath
                    }

                    #endregion
    }
#endregion
#endregion
