# Threat Hunt Report: Unauthorized TOR Usage

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

- [Scenario Creation](https://github.com/abdul4210/Threat-Hunting-Scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

<img width="572" height="308" alt="image" src="https://github.com/user-attachments/assets/690bd4b3-e0b0-4272-8bca-03fefbc0a09e" />

---

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

---

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "aliadmin" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-02-23T01:19:00.744233Z`. These events began at `2026-02-22T22:24:57.5369744Z`.

**Query used to locate events:**

<img width="1158" height="181" alt="step 1 query" src="https://github.com/user-attachments/assets/f813a441-7c64-469d-97c2-3b71590baa07" />
<img width="1436" height="301" alt="step 1 results" src="https://github.com/user-attachments/assets/9ffb8331-191d-44d3-a135-926008c5829d" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.6.exe". Based on the logs returned, at `2026-02-23T00:58:55.8483898Z`, an employee on the "ali-threat-hunt" device ran the file `tor-browser-windows-x86_64-portable-15.0.6.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

<img width="1052" height="112" alt="step 2 query" src="https://github.com/user-attachments/assets/0d6f321c-b9ae-49fa-91ed-9f45830a55fd" />
<img width="1767" height="232" alt="step 2 results" src="https://github.com/user-attachments/assets/258ba55b-a5c7-4d9c-91bb-41e28a1f299a" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "aliadmin" actually opened the TOR browser. There was evidence that they did open it at `2026-02-22T22:28:20.9561271Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

<img width="1057" height="131" alt="step 3 query" src="https://github.com/user-attachments/assets/02ad5eb4-2717-4f9d-93b2-6f6a3f6580b9" />
<img width="1721" height="576" alt="step 3 results" src="https://github.com/user-attachments/assets/9504f58b-a2c1-4bc7-803a-6d6fae80b7c9" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-23T01:00:58.7965783Z`, an employee on the "ali-threat-hunt" device successfully established a connection to the remote IP address `85.215.206.21` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\aliadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

<img width="1263" height="132" alt="step 4 query" src="https://github.com/user-attachments/assets/20e1ea7f-a1a4-41d7-89e2-70ef37710352" />
<img width="1862" height="502" alt="step 4 results" src="https://github.com/user-attachments/assets/118cd066-4400-48b4-b01d-6f12c8c78e5f" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-22T22:24:57.5369744Z`
- **Event:** The user "aliadmin" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\aliadmin\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-23T00:58:55.8483898Z`
- **Event:** The user "aliadmin" executed the file `tor-browser-windows-x86_64-portable-15.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.6.exe /S`
- **File Path:** `C:\Users\aliadmin\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-22T22:28:20.9561271Z`
- **Event:** User "aliadmin" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\aliadmin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-23T01:00:58.7965783Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "aliadmin" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\aliadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-23T01:01:51.5637069Z` - Connected to `193.46.56.106` on port `443`.
  - `2026-02-23T01:01:42.2925311Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "aliadmin" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-23T01:19:00.744233Z`
- **Event:** The user "aliadmin" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\aliadmin\Desktop\tor-shopping-list.txt`

---

## Summary

The user "aliadmin" on the "ali-threat-hunt" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ali-threat-hunt` by the user `aliadmin`. The device was isolated, and the user's direct manager was notified.

---

