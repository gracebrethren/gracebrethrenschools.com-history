# Get all the properties from AD for one computer:
Get-ADComputer -Identity HSHYPERV5 -Properties *

# Get specific properties from AD for all computers, and export to CSV
Get-ADComputer -Filter {Name -like "*"} -Properties Created,CN,DNSHostName,IPv4Address,LastLogonDate,Enabled,Deleted,ObjectClass,OperatingSystem,OperatingSystemVersion |
Export-Csv -Path .\ad-computers.csv -NoTypeInformation

# Login to computers and use WMI to retrieve specs (needs some cleanup)
$pingConfig = @{
    “count” = 1
    “bufferSize” = 15
    “delay” = 1
    “EA” = 0 }
$computer = $cn = $null
$cred = Get-Credential
Get-ADComputer -Filter {Name -like "IT*"} -Credential $cred |
ForEach-Object {
    if(Test-Connection -ComputerName $_.dnshostname @pingConfig)
        { $computer += $_.dnshostname + "`r`n" }
    }
$computer = $computer -split "`r`n"
$property = “systemname”,”maxclockspeed”,”addressWidth”,“numberOfCores”,“NumberOfLogicalProcessors”,"Name"
foreach($cn in $computer)
{
 if($cn -match $env:COMPUTERNAME)
   {
   Get-WmiObject -class win32_processor -Property $property |
   Select-Object -Property $property 
   Get-CimInstance -ClassName Win32_ComputerSystem
   }
 elseif($cn.Length -gt 0)
   {
   Get-WmiObject -class win32_processor -Property $property -cn $cn -cred $cred |
   Select-Object -Property $property
   Get-WmiObject -ClassName Win32_ComputerSystem -cn $cn -cred $cred
   } 
}

# get the current computer's physical mem in GBs
(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb 
