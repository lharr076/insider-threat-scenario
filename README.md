<img width="400" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/insider_threat_image.jpg" alt="Insider Threat image"/>

# Threat Hunt Report: Insider Threat
- [Scenario Creation](https://github.com/lharr076/insider-threat-scenario/blob/main/insider_threat_exfil_sensitve_data_template.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Outlook

##  Scenario

Management suspects that an employee may be exfiltrating PII data via email. Additionally, there have been anonymous reports of the employee being disgruntled after performance evaluation. The goal is to detect any files or folders that have been created and/or moved and analyze related security incidents to mitigate potential risks. If any data is found, notify management.

### High-Level Insider Threat IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `PII` file events.
- **Check `DeviceProcessEvents`** for any signs of Microsoft Outlook usage.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "PII" in it and discovered what looks like the user "employee" created a PII file in Notepad, moved the file into a folder called PII on the desktop, and then created a zip file called `PII.zip` in the Windows Temp folder at `2025-03-25T10:41:03`. These events began at `2025-03-25T10:32:22`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName startswith target_machine
| where FileName contains "PII"
| where ActionType in ("FileCreated", "FileRenamed")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/DeviceFileEvents.jpg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "olk.exe". Based on the logs returned, at `2025-03-25T05:48:35`, an employee on the "training-vm-118" device ran `olk.exe` which is Microsoft Outlook outside operation hours of the company. Between `2025-03-25T10:34:32` and `2025-03-25T10:37:09` multiple Outlook processes are created possibly signaling preparation for exfiltration. At `2025-03-25T18:40:54` the `olk.exe` process is created again afterhours.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == target_machine
| where FileName == "olk.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/DeviceProcessEvents.jpg">

---

## Chronological Event Timeline 

### 1. File Created - PII Data Text File

- **Timestamp:** `2025-03-25T10:33:01`
- **Event:** The user "Training-vm-1186" created a file named `PII Data.txt` to the Documents folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Training-vm-1186\Documents\Fake PII Data.txt`

### 2. Folder Created - PII Folder 

- **Timestamp:** `2025-03-25T10:33:34`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
