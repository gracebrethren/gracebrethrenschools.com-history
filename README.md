# IT automation scripts

This project contains instructions and scripts for automating IT tasks at Grace Brethren Schools.

## Examples:
Get information from an active directory server about specific computers.
```
$cred = Get-Credential
Set-Variable -Name dc_ip_addr -Value x.x.x.x
Get-ADComputer -Filter {Name -like "pscam*"} -Server $dc_ip_addr -Credential $cred
```