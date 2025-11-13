$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$file = "$env:TEMP\dns_cache_$env:COMPUTERNAME`_$stamp.txt"

ipconfig /displaydns | Out-File -Encoding UTF8 $file
Write-Output "DNS cache saved to $file"
