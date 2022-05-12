**Payloads:**

  - Death.exe
    "Raises an error that causes a Blue Screen of Death on Windows. It does this without
    requiring administrator privileges and queries the registry for crash dump settings so that we'll have some idea 
    what type of dump we're going to generate, and where it will be."
  - Screen.exe
    "The screen melt is an effect seen when Doom changes scene, for example, when starting or exiting a level. The screen appears to "melt" away to the new screen. The
    effect is not particularly complicated. The "melting" screen is subdivided into vertical slices, two pixels wide. Each slice moves down the screen at a uniform
    speed, but they do not all begin moving at the same time, each slice given a random yet short delay.
    Referred this code of doom to understand working:
    https://doom.fandom.com/wiki/Screen_melt#:~:text=The%20screen%20melt%20is%20an,vertical%20slices%2C%20two%20pixels%20wide" 
  - evil-preprocessor.h 
    "Add some of these preprocessor, preferably into the same commit where victim do a large merge"
  
  
**Anonymizing C2 with Tor**
- A high-level overview of this is that the C2 server and client mutually agree on a relay designated the Rendezvous Point, which is chosen at random. The server and client then build a three-hop path and rendezvous at this aptly-named relay. They are then free to exchange data with neither side needing to know the other's IP. 
- Plan was to connect and access C2 via Tor circuit, which would provide anonymity both to clients as well as to servers using its hidden service. The protocol would allow a client to connect to a server knowing only an identifier and never needing to know the C2 IP.
- To do so, we tested binding the tor.exe with other files but AV detects it as malicious file; other way around was to download tor portable exe, and auto-start it powershell script with autorun by changing the registry entry in client machine, which works on local system when tested.


**Redirector Server**
- Secure and easy way to anonymize the C2 would be to use Redirector in-between the C2 and target, doing so will reflect in netstat results that the target is connected with Redirector on 8080/tcp, forwarding all request to C2 while the Redirector only listen on port 22 and 8080, allowing the C2 to connect, and C2 will allow 22/tcp for SSH from anywhere and outgoing 8080/tcp to connect with Redirector, denying all other outgoing connections.

