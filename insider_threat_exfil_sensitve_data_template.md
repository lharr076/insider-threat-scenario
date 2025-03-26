# Threat Event (Insider Threat Exfiltrate Sensitive Data)
**Data exfiltration and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Copy sensitive files and put in a folder called ```company PII```
2. Move folder into temp folder in attempt to hide
3. Open email app to exfil data

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for file and folder activities on endpoints. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect activity using cmd.exe, powershell.exe, olk.exe and explorer.exe.|

---

## Related Queries:
```kql
// Detect the folder being created
// Detect files being moved into folder
// Detect folder being moved into temp folder
// Detect folder compressed into zip file
DeviceFileEvents
| where DeviceName startswith target_machine
| where FileName contains "PII"
| where ActionType in ("FileCreated", "FileRenamed")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

// Detect Microsoft Outlook service was launched
DeviceProcessEvents
| where DeviceName == target_machine
| where FileName == "olk.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Larry Harris Jr
- **Author Contact**: https://www.linkedin.com/in/larryharrisjr/
- **Date**: March 25, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 5, 2025`  | `Larry Harris Jr`   
