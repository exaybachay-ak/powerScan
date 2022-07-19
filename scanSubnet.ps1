### Subnet port scanner 
#  Arg[0] is PORT array

function fastping{
  [CmdletBinding()]
  param(
  [String]$computername,
  [int]$delay = 10,
  [String]$sequential
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

function testPort ($comp, $port) {
  # Improving speed of timeouts
  #   https://superuser.com/questions/805621/test-network-ports-faster-with-powershell
  $requestCallback = $state = $null
  $tcpClient = New-Object System.Net.Sockets.TCPClient
  #$tcpClient.Connect($comp,$port) | out-null
  $beginConnect = $tcpClient.BeginConnect($comp,$port,$requestCallback,$state)
  Start-sleep -milli 100
  if($tcpClient.Connected) { $open = $True } else { $open = $False }
  $tcpClient.Close()
  #return $tcpClient.Connected   
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
  write-output "Scanning entire $usermessage subnet..."
  write-output "========================================="
  write-output " "

  $scanrange = (1..255)
  foreach ($ipaddr in $scanrange){
    $scanIp = $classCIpAddr + $ipaddr
    $endofrange = 256 - $ipaddr # first is 254, $ipaddr first is 1

    if($sequential){
      $pingStatus = fastping $scanIp 
    } else {
      $pingStatus = if($ipaddr % 2){ fastping $scanIp; $ip = $scanIp } else { fastping $endofrange; $ip = $endofrange }
    }

    if ($pingStatus -eq "True"){
      #$hn = Resolve-DnsName $scanIp
      #$hn = $hn.namehost
      if($args){
        foreach($port in $args[0]){
          # Start at end of 255 range and bounce around
          $test = testPort $ip $port
          if($test.open -eq $True){ 
            write-output "$ip is listening on $port!"
          }
          else { 
            #pass 
          }
        }
      } else {
          foreach($port in @(22,23,80,135,443,8080)){
            $test = testport $ip $port
            if($test.open -eq $True){
              write-output "$ip is listening on $port!"
            } else {
              #pass
            }
          }
        }
      }
    }
  }
