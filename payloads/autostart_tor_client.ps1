# Install and auto-start tor whenever windows starts; 
# Work needed in the script to hide 'tor browser' directory

function Start-Tor {

    # Configuration
    $torBrowser     = "D:\Tor Browser"       # Put address of root folder of Tor Browser here
    $TOR_Password   = "PasswordHere"         # Input Tor network password here
    $TOR_HOST       = "127.0.0.1"            # Host of local Tor network
    $TOR_PORT       = 9150                   # The port number where Tor runs
    $CTRL_PORT      = 9151                   # The controller port number of Tor

    # Do not modify these
    $tor_location   = "$torBrowser\Browser\TorBrowser\Tor"
    $torrc_defaults = "$torBrowser\Browser\TorBrowser\Data\Tor\torrc-defaults"
    $torrc          = "$torBrowser\Browser\TorBrowser\Data\Tor\torrc"      
    $tordata        = "$torBrowser\Browser\TorBrowser\Data\Tor"
    $geoIP          = "$torBrowser\Browser\TorBrowser\Data\Tor\geoip"
    $geoIPv6        = "$torBrowser\Browser\TorBrowser\Data\Tor\geoip6"
    $torExe         = "$tor_location\tor.exe"
    $controllerProcess = $PID
    function Get-OneToLastItem { param ($arr) return $arr[$arr.Length - 2]}

    Write-Host "Generating hash for your Tor password..."
    $TOR_HashPass_RAW  = & "$torExe" --hash-password $TOR_Password | more
    $Tor_HashPass      = Get-OneToLastItem($TOR_HashPass_RAW)

    $TOR_VERSION_RAW   = & "$torExe" --version | more
    $Tor_Version       = Get-OneToLastItem($TOR_VERSION_RAW)

    Write-Host "Running $Tor_Version" -ForegroundColor DarkGray
    Write-Host "Press [Ctrl+C] to stop Tor service."
    & "$torExe" --defaults-torrc $torrc_defaults -f $torrc DataDirectory $tordata GeoIPFile $geoIP GeoIPv6File $geoIPv6 HashedControlPassword $Tor_HashPass +__ControlPort $CTRL_PORT +__SocksPort "${TOR_HOST}:$TOR_PORT IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth" __OwningControllerProcess $controllerProcess | more
}
