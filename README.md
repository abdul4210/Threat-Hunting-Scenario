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


