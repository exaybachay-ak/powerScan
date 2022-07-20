param(
  [Parameter(Mandatory=$False)]$ports,
  [Parameter(Mandatory=$False)][Boolean]$sequential,
  [Parameter(Mandatory=$False)][Boolean]$random,
  [Parameter(Mandatory=$False)][Boolean]$resolveDns,
  [Parameter(Mandatory=$False)][Boolean]$slow,
  [Parameter(Mandatory=$False)][Boolean]$allports
)

# Configure logging
$logname = "$((pwd).path)\powerScan_$(get-date -format "yyyyMMMd")_$(get-date -format "hhmmsss").log"

# Set parameters if not provided
if(!($ports)){ $ports = @(22,23,80,135,443,8080) }
if(!($slow)){ write-output "--->>>   Slow parameter not set, defaulting to faster scan" | tee-object -filepath $logname -append} 
if(!($sequential) -and !($random)){ write-output "--->>>   Sequential and random parameterers not set, defaulting to pseudo random scan" | tee-object -filepath $logname -append }
write-output " " | tee-object -filepath $logname -append

function fastping{
  [CmdletBinding()]
  param(
  [String]$computername,
  [int]$delay = 10
  )

  $ping = new-object System.Net.NetworkInformation.Ping  # see http://msdn.microsoft.com/en-us/library/system.net.networkinformation.ipstatus%28v=vs.110%29.aspx
  try {
    if ($ping.send($computername,$delay).status -ne "Success") {
      return $false;
    }
    else {
      return $true;
    }
  } catch {
    return $false;
  }
}

function testPort ($comp, $port, $delay) {
  # Improving speed of timeouts
  #   https://superuser.com/questions/805621/test-network-ports-faster-with-powershell
  $requestCallback = $state = $null
  $tcpClient = New-Object System.Net.Sockets.TCPClient
  $beginConnect = $tcpClient.BeginConnect($comp,$port,$requestCallback,$state)
  Start-sleep -milli $delay
  if($tcpClient.Connected) { $open = $True } else { $open = $False }
  $tcpClient.Close()
  [pscustomobject]@{computername=$comp;port=$port;open=$open}
}

$ipinfo = get-wmiobject win32_networkadapterconfiguration | ? {$_.ipenabled}

#Trimming IP info down - only grabbing adapters that have a default gateway
$activeIP = get-wmiobject win32_networkadapterconfiguration | ? {$_.ipenabled} | `
Where-Object {$_.DefaultIPGateway -NotLike '' -and $_.ServiceName -NotLike 'wintun'} 

if ($activeIP.ipsubnet -eq "255.255.255.0"){
  $classCPattern = "\b(?:[0-9]{1,3}\.){2}[0-9]{1,3}\."
  $classCIpAddr = ($activeIP.ipAddress | sls -Pattern $classCPattern).Matches.Value

  $usermessage = $classCIpAddr + "0/24"
  write-output "Scanning entire $usermessage subnet..." | tee-object -filepath $logname -append
  write-output "Ports selected are: $ports" | tee-object -filepath $logname -append
  write-output "=========================================" | tee-object -filepath $logname -append
  write-output " " | tee-object -filepath $logname -append

  $scanrange = @(1..255)
  $randomrange = @(1..255)
  $scanprogress = 0
  foreach ($ipaddr in $scanrange){
    $scanIp = $classCIpAddr + $ipaddr
    $endofrange = 256 - $ipaddr # first is 254, $ipaddr first is 1
    write-progress -Activity "Scanning for active hosts" -PercentComplete (($ipaddr / 255) * 100)

    if($sequential){
      $pingStatus = fastping $scanIp 
    } elseif($random) {
      $randomIp = Get-Random -min 1 -max 255
      write-output "Testing IP $randomIp" 
      #while($($scanrange.Contains($randomIp)) -eq $False) {

      while($randomIp -notin $randomrange){
        $randomIp = Get-Random -min 1 -max 255 
        if($randomrange.Count -eq 1){ $randomIp = $randomrange[0] }
        write-output "New random IP is $randomIp"
      }
      $scanIp = $classCIpAddr + $randomIp
      $randomrange = $randomrange | Where-Object { $_ -ne $randomIp }
      $pingStatus = fastping $scanIp
    } else {
      if($ipaddr % 2 -eq 0){ 
        $pingStatus = fastping $scanIp
      } else { 
        $scanIp = "$classCIpAddr$endofrange" 
        $pingStatus = fastping $scanIp
      }
    }
    if ($pingStatus -eq $True){
      write-output "Scanning $scanIp..." | tee-object -filepath $logname -append
      if($resolveDns){
        $hn = Resolve-DnsName $scanIp | tee-object -filepath $logname -append
        $hn = $hn.namehost | tee-object -filepath $logname -append
      }
      $notlistening = 0
      if ($allports) {
        (1..65535) | %{
          write-progress -Activity "Scanning ports on $scanIp" -PercentComplete (($_ / 65535) * 100)
          if($slow){
            $test = testPort $scanIp $_ 50
          } else {
            $test = testPort $scanIp $_ 10
          }
          if($test.open){
            write-output "$scanIp is listening on port $_!" | tee-object -filepath $logname -append
          } else {
            $notlistening += 1
            if($notlistening -eq 65535){
              write-output "$scanIp is not listening on any ports" | tee-object -filepath $logname -append
            }
          }
        }
      } else {
        foreach($port in $ports){
          if($slow){
            $test = testPort $scanIp $port 50
          } else {
            $test = testPort $scanIp $port 10
          }
          if($test.open){
            write-output "$scanIp is listening on $port!" | tee-object -filepath $logname -append
          } else {
            $notlistening += 1
            if($notlistening -eq $ports.count ){
              write-output "$scanIp is not listening on any of the selected ports" | tee-object -filepath $logname -append
            }
          }
        }
      }
    }
  }
}
