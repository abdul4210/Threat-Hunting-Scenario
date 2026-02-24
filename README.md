# Threat Hunt Report: Unauthorized TOR Usage

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

<img width="572" height="308" alt="image" src="https://github.com/user-attachments/assets/690bd4b3-e0b0-4272-8bca-03fefbc0a09e" />

---

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.6.exe". Based on the logs returned, at `2026-02-23T00:58:55.8483898Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.6.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

<img width="1052" height="112" alt="step 2 query" src="https://github.com/user-attachments/assets/0d6f321c-b9ae-49fa-91ed-9f45830a55fd" />
<img width="1767" height="232" alt="step 2 results" src="https://github.com/user-attachments/assets/258ba55b-a5c7-4d9c-91bb-41e28a1f299a" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-02-22T22:28:20.9561271Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

<img width="1057" height="131" alt="step 3 query" src="https://github.com/user-attachments/assets/02ad5eb4-2717-4f9d-93b2-6f6a3f6580b9" />
<img width="1721" height="576" alt="step 3 results" src="https://github.com/user-attachments/assets/9504f58b-a2c1-4bc7-803a-6d6fae80b7c9" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-23T01:00:58.7965783Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `85.215.206.21` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\aliadmin\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

<img width="1263" height="132" alt="step 4 query" src="https://github.com/user-attachments/assets/20e1ea7f-a1a4-41d7-89e2-70ef37710352" />
<img width="1862" height="502" alt="step 4 results" src="https://github.com/user-attachments/assets/118cd066-4400-48b4-b01d-6f12c8c78e5f" />

---



