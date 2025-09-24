# Incident Response Scenario: Suspicious Powershell Web Requests
- [Scenario Creation] - input later

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

After gaining access to a system, attackers often use PowerShell to download and execute malicious scripts while blending in with normal activity. Commands like Invoke-WebRequest or Invoke-RestMethod are common, often paired with -ExecutionPolicy Bypass, -ExecutionPolicy Unrestricted, -ep Bypass, or -EncodedCommand to evade defenses. This post-exploitation tactic enables malware deployment, data exfiltration, or C2 communication, making detection critical.

### High-Level Suspicious Powershell Activity Discovery Plan

- **Check `DeviceProcessEvents`** for any signs of web requests with defense bypasses

---

## Incident Reponse Steps

### 1. Created the alert with the `DeviceProccessEvents` Table

Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when PowerShell is detected using `Invoke-WebRequest` (and appropriate aliases) to download content. Include `-ExecutionPolicy Bypass` (and appropriate alieases) to evade defenses.

**Query used to create alert**

```kql
let targetMachine = "st-vm";
DeviceProcessEvents
| where DeviceName == targetMachine and AccountDomain != "nt authority" // avoids system accounts, only  detecting user activity
| where InitiatingProcessFileName == "powershell.exe" or InitiatingProcessCommandLine has "pwsh"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr", "Invoke-RestMethod", "irm") // catches invoke web requests and the aliases
     and ProcessCommandLine has_any ("-ExecutionPolicy Bypass", "ep Bypass", "-ExecutionPolicy Unrestricted", "-EncodedCommand") // catches execution bypasses and the aliases
| order by TimeGenerated desc
```

---

### 2. Create the Schedule Query Rule in: Sentinel → Analytics → Schedule Query Rule

**Steps:**

<table>
  <tr>
    <td><img width="1200" height="1050" alt="image" src="https://github.com/user-attachments/assets/13fd1aea-8cfc-4b50-acc5-b5b02ad136d8" /></td>
    <td><img width="1400" height="1250" alt="image" src="https://github.com/user-attachments/assets/999c308f-4b3b-4a63-b535-266c96bcfe9f" /></td>
    <td><img width="1200" height="1050" alt="image" src="https://github.com/user-attachments/assets/79778791-163d-4b83-9976-60d183cde346" /></td>
  </tr>
</table>

<table>
  <tr>
    <td><img width="700" height="500" alt="image" src="https://github.com/user-attachments/assets/4a15670a-cc54-4ab6-9644-f28a88332be9" /></td>
    <td><img width="918" height="640" alt="image" src="https://github.com/user-attachments/assets/0673e59a-ee1d-48d9-a3e4-52f8c14144eb" /></td>
  </tr>
</table>

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for outbound connections from the machine to known TOR ports. At Sep 22, 2025 11:51:39 PM, an employee on the "939st" device successfully established a connection to the remote IP address `185.162.249.126` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `C:\Users\939st\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. There were a couple of other connections to sites over port `9150` by the process `firefox.exe`.

**Query used to locate events:**

```kql
// proof of outbound connections over tor ports
let target_machine = "939st";
DeviceNetworkEvents
| where DeviceName == target_machine
| where ActionType == "ConnectionSuccess" // only filtering successfull connections
| where RemotePort in (9050, 9150, 9001, 9030, 9040) // commonly used TOR ports
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1179" height="343" alt="image" src="https://github.com/user-attachments/assets/d69eb685-f60e-4a6e-976d-e73d20d2e3d4" />

---

## Chronological Event Timeline 

### 1. Tor Browser Installation

- 11:50:01 PM: On device 939st, `tor-browser-windows-x86_64-portable-14.5.7.exe` was executed from C:\Users\939st\Downloads\... using a silent install (/S). Process created via `cmd.exe`, initiated by `explorer.exe`.
- 11:50:23 PM: File `tor.exe` created at `C:\Users\939st\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` (Tor core executable).


### 2. Network Connection - TOR Network

- 11:51:39 PM: tor.exe connected successfully to remote IP `185.162.249.126` on port `9001` (Tor relay port).
- 11:51:41 PM: tor.exe connected to remote IPs `65.21.94.13` and `185.162.249.126` on port `9001`.
- 11:52:39 PM: firefox.exe connected to `127.0.0.1:9150` (Tor SOCKS proxy localhost connection).

### 3. Additional Network Connections - TOR Browser Activity

- 7:45:40 PM: firefox.exe connected again to `127.0.0.1:9150` (Tor browsing session initiated).

### 4. File Creation - TOR Shopping List

- 7:53:08 PM: A Windows shortcut `tor-shopping-list.lnk` was created in `C:\Users\939st\AppData\Roaming\Microsoft\Windows\Recent\`, suggesting the user accessed/opened a file or application named `tor-shopping-list` through Tor.

---

## Summary

- On the evening of September 22, 2025, the Tor Browser was installed on device 939st. This installation was done in a way that didn’t require user interaction (a “silent” install). Soon after, the program began connecting to the Tor network, which is commonly used to browse the internet anonymously.
- The browser was successfully set up and started routing traffic through Tor. The following day, September 23, 2025, the browser was used again. During this activity, a shortcut called `tor-shopping-list` was created on the computer, showing that the user opened or interacted with a file or link while using Tor.

---

## Response Taken

TOR usage was confirmed on the endpoint `939st`. The device was isolated, and the user's direct manager was notified.

---

