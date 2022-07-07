# RenWeb <-> Active Directory Student User Provisioning Script
# Written By: Joshua Packard

# TODO: 'Class Of' or 'Grade Level' to use for determining Elementary School, High School, or TGA and filling in the Description automatically

# The first part of this script takes an exported list of district wide students from RenWeb and creates Active Directory and 
# Google Apps accounts (automatically done by GADS once they are moved into the appropriate OU). It will also prompt to re-enable 
# accounts for students that have re-enrolled.


# The second part of this script takes all of the AD staff accounts and compares them to a RenWeb exported list of Staff, disabling any staff that are no longer active.


########################################
# Variables To Update Before Executing #
########################################

#NOTE!! From the staff export from Renweb, make sure the column names don't have a trailing space in them, change 'staff ID' to 'StaffID', and sanitize acuña to acuna
# And then move that CSV file to the location below (and rename it here to the correct date)
$csvFile = '\\hsfs1\it$\PowerShell\Data\GBHS Students2.csv'

$campus = "Grace Brethren Jr/Sr High School"

########################################
# Variables To Update Before Executing #
########################################




# Fix the CSV headers
#$csvRaw = Get-Content $csvFile
#$csvRaw
#$csvRaw = $csvRaw -replace "Count,Last Name ,First Name ,Class Of ,Student ID (System) ", "Count,Last,First,Class,StudentID"
#$csvRaw | Out-File $csvFile

$users = Import-Csv $csvFile | Where-Object { $_.Email -ne "" }

$users | ForEach-Object {

    $user = $_
    $first = $user.First
    $last = $user.Last
    $classOf = $user.Class
    $studentID = $user.StudentID

    # Get AD User if exists
    $ad = Get-ADUser -Filter { Surname -eq $last -and GivenName -eq $first } -SearchBase "dc=gbs,dc=com" -Properties EmailAddress

    if($ad)
    {
        $ademail = $ad.EmailAddress
        if($ademail -and $ad.Enabled -eq $true)
        {
            Write-Host "$first $last [$ad.DistinguishedName] is enabled in Active Directory with email: $ademail"

            if($ad.DistinguishedName -like "*Elementary*")
            {
                $ok = Read-Host "Promote $($ad.SamAccountName) to High School? (y/N)"
                if($ok -eq "y" -or $ok -eq "Y")
                {
                    Write-Host "Promoting..."

                    Move-ADObject $ad.DistinguishedName -TargetPath 'OU=Students,OU=Users,OU=HighSchool,DC=gbs,DC=com' -Confirm
                    
                    Remove-ADGroupMember -Identity "elstudents" -Member $ad.SamAccountName
                    Add-ADGroupMember -Identity "hsstudents" -Member $ad.SamAccountName
                    Add-ADGroupMember -Identity "gbhsstudents" -Member $ad.SamAccountName

                    Set-ADUser -Identity $ad.SamAccountName -Description "Class of $classOf" -EmployeeID $studentID -Office $campus -ChangePasswordAtLogon $True

                    $fileServer = "HSFS1"; 
                    $shares = "F:\students"
            
                    $SAM = $ad.SamAccountName

                    invoke-command -computername $fileServer {
        
                        param($shares, $SAM)
        
                        Set-Location $shares

                        if (test-path $SAM) {
                            if (test-path "$($SAM)\Documents") {
                                Write-Host "User Folder exists. Skipping creating home share."
                                return
                                }
                            }

                        # create folder on disk and documents subfolder
                        New-Item $SAM -ItemType Directory | Out-Null
                        New-Item "$($SAM)\Documents" -ItemType Directory | Out-Null
    
                        # create smb share with full access for everyone
                        New-SmbShare –Name "$SAM$" –Path $shares\$SAM –FullAccess Everyone
   
                        # set modify permissions for user to new share
                        $acl = Get-Acl $SAM
                        $permission = "$domain\$SAM","Modify","ContainerInherit,ObjectInherit”,”None”,”Allow” 
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
                        $acl.SetAccessRule($accessRule) 
                        $acl | Set-Acl $SAM 
                    } -Args $shares, $SAM 
                }
            }

            # Nothing More To Do
        }
        elseif ($ad.Enabled -eq $false)
        {
            Write-Host "$first $last exists in Active Directory but is disabled"
            # Enable user?
            $ok = Read-Host "Enable AD account $($ad.SamAccountName)? (y/N)"
            if($ok -eq "y" -or $ok -eq "Y")
            {
                Add-ADGroupMember -Identity "hsstudents" -Member $ad.SamAccountName
                Add-ADGroupMember -Identity "gbhsstudents" -Member $ad.SamAccountName

                Set-ADUser -Identity $ad.SamAccountName -Enabled $true -Description "Class of $classOf" -EmployeeID $studentID -Office $campus -ChangePasswordAtLogon $True

                Write-Host "AD User enabled for $first $last "
            }
        }

        if(!$ademail -and $ad.Enabled -eq $true)
        {
            Write-Host "$first $last exists in Active Directory with no email address"
            # Update email field for user?
            $ok = Read-Host "Set email address for $first $($last)? (y/N)"
            if($ok -eq "y" -or $ok -eq "Y")
            {
                $ad | Set-ADUser -EmailAddress $email
                Write-Host "Email Address for $first $last set to $email"
            }
        }
    }
    else
    {
        Write-Host "$first $last does NOT exist in Active Directory"
        # Create new AD user?
        $ok = "Y"
        #$ok = Read-Host "Create Active Directory account for $first $($last)? (y/N)"
        if($ok -eq "y" -or $ok -eq "Y")
        {
            # Check for duplicate SAM/Email Address

            #generate the user's full name (first + last) as well as their AD account name
            $detailedName = "$first $last"
            $SAM =  "$($first).$($last)"

            #remove common non-alphanumeric characters
            $SAM = $SAM -replace "-", ""
            $SAM = $SAM -replace "'", ""
            $SAM = $SAM -replace " ", ""

            #truncate the username after 20 characters (SAM names cannot be longer than 20 characters for compatibility reasons)
            if ($SAM.length -gt 20)
            {
	            $SAM = $SAM.substring(0,20)
                Write-Host "Warning: Username truncated"
            }

            if(Get-ADUser -Filter { SAMAccountName -like $SAM } -SearchBase "dc=gbs,dc=com")
            {
                $newSAM = $null
                while($newSAM -eq $null)
                {
                    $newSAM = Read-Host "Conflicting username: $($SAM). Please enter a unique account name to use:"
                }

                $SAM = $newSAM
                
                #remove common non-alphanumeric characters
                $SAM = $SAM -replace "-", ""
                $SAM = $SAM -replace "'", ""
                $SAM = $SAM -replace " ", ""

                #truncate the username after 20 characters (SAM names cannot be longer than 20 characters for compatibility reasons)
                if ($SAM.length -gt 20)
                {
	                $SAM = $SAM.substring(0,20)
                    Write-Host "Warning: Username truncated to $SAM"
                }
            }            

            if($SAM -like "*grace*") {
                $password = "Brethren1234"
            }
            else {
                $password = "Grace1234"
            }

            # create the user and set their password and description
            New-ADUser -Name $detailedName -SamAccountName $SAM -UserPrincipalName $SAM -DisplayName $detailedName -GivenName $first -Surname $last `
                        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Enabled $true -Path "OU=Import,DC=gbs,DC=com" -EmailAddress "$SAM@gracebrethren.com"


            Add-ADGroupMember -Identity "hsstudents" -Member $SAM
            Add-ADGroupMember -Identity "gbhsstudents" -Member $SAM

            Set-ADUser -Identity $SAM -Description "Class of $classOf" -EmployeeID $studentID -Office $campus -ChangePasswordAtLogon $True

             
            $fileServer = "HSFS1"; 
            $shares = "F:\students"
            
            invoke-command -computername $fileServer {
        
                    param($shares, $SAM)
        
                Set-Location $shares

                if (test-path $SAM) {
                    if (test-path "$($SAM)\Documents") {
                        Write-Host "User Folder exists. Skipping creating home share."
                        return
                        }
                    }

                # create folder on disk and documents subfolder
                New-Item $SAM -ItemType Directory | Out-Null
                New-Item "$($SAM)\Documents" -ItemType Directory | Out-Null
    
                # create smb share with full access for everyone
                New-SmbShare –Name "$SAM$" –Path $shares\$SAM –FullAccess Everyone
   
                # set modify permissions for user to new share
                $acl = Get-Acl $SAM
                $permission = "$domain\$SAM","Modify","ContainerInherit,ObjectInherit”,”None”,”Allow” 
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
                $acl.SetAccessRule($accessRule) 
                $acl | Set-Acl $SAM 
            } -Args $shares, $SAM            
        }
    }
}
