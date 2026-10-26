# Windows Security Event Log Triage Tool

A beginner-friendly, educational browser application that helps students inspect Windows Event Viewer CSV exports and build a simple SOC-style triage report. It uses transparent rules to identify activity that may deserve investigation. It does **not** prove that a system is compromised.

## Privacy and security

- CSV parsing and analysis happen locally in the browser using the browser File API and JavaScript.
- The application does not send CSV contents to a server, AI provider, analytics platform, or external API.
- There are no external scripts, frameworks, fonts, tracking, cookies, telemetry, advertisements, databases, or backend services.
- The sample buttons use demo data embedded in `script.js`, so they work when `index.html` is opened directly with `file://` and do not make network requests.
- Uploaded event data is kept in page memory while the page is open. The application does not write it to local storage or cookies. Clear the data or close the tab to remove the page's in-memory copy.
- The downloadable HTML report is generated locally in the browser. The report can contain sensitive log details; store and share it carefully.
- Uploaded CSV values are displayed as text rather than inserted as raw HTML. The parser has a 15 MB file limit and 50,000-row limit to reduce the risk of accidental browser overload.

The application cannot make guarantees about browser extensions, operating-system malware, or the web host's handling of ordinary website requests if you host the application publicly. The application itself contains no code that transmits log data.

## Run locally (no installation required)

1. Download or copy the `windows-security-triage` folder to your Windows laptop.
2. Open the folder.
3. Double-click `index.html` to open it in Microsoft Edge, Chrome, or another modern browser.
4. Click **Load Normal Sample** to explore the dashboard, or choose a CSV exported from a system you own or are authorised to investigate.
5. Use filters, review the findings and click **Download SOC report** to create a local HTML report.

No Node.js, Python, database, package manager, API key, or internet connection is needed for core use. The demo buttons are embedded in the JavaScript and work offline. The separate files in `samples/` are provided for inspection, testing, and independent upload demonstrations.

## Project files

```text
windows-security-triage/
├── index.html
├── styles.css
├── script.js
├── README.md
├── TESTING-GUIDE.md
└── samples/
    ├── normal-windows-events.csv
    ├── repeated-failed-logons.csv
    ├── password-guessing.csv
    ├── account-persistence.csv
    └── suspicious-admin-activity.csv
```

## What are Windows Event Logs?

Windows records operating-system and application activity as events. The Security log can contain authentication activity, account management, group membership changes, process creation, and other security-relevant records. What is recorded depends on Windows edition, audit policy, permissions, and system configuration.

## What does SOC triage mean?

Security Operations Center (SOC) triage is an initial review of activity to decide what needs further investigation, what context is missing, and what evidence to collect next. Triage prioritises work; it is not the same as confirming an incident.

## Exporting suitable data from Event Viewer

1. Open **Event Viewer** on the Windows system you are authorised to examine.
2. Navigate to **Windows Logs → Security**.
3. Use **Filter Current Log…** to reduce the event range or Event IDs if appropriate.
4. Choose **Save All Events As…**. If your version offers CSV as an export type, select it and save the file.
5. Upload the `.csv` file in this tool.

Windows versions and Event Viewer workflows differ. Some exports or dialogs may not expose the exact CSV layout expected by this application. If CSV is unavailable, an optional PowerShell export can be used in an authorised environment. Example for a small, recent sample (run PowerShell as an account permitted to read the Security log):

```powershell
$start = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $start } |
  Select-Object TimeCreated, Id, ProviderName, MachineName, LevelDisplayName, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8
```

This exports the selected events into a CSV with a `Message` column. It may not include every field needed for every correlation. Avoid collecting more data than necessary and follow your organisation's policy. The tool does not parse raw `.evtx` files in Version 1.

## CSV parser behaviour

The parser accepts common variations such as `Event ID`, `EventID`, and `event_id`, as well as common time, computer, user, source IP, and message headers. It supports quoted fields, commas and line breaks inside quoted messages, and doubled quote escapes. Event ID is required; missing or invalid Event IDs produce a clear error or warning instead of a crash.

Useful fields may be separate columns or embedded in the event `Message`. The parser tries to extract common details such as account name, source network address, logon type, group name, process name, parent process, and command line. Message wording varies across Windows versions and event providers, so extraction is best-effort. Missing values are shown as unavailable rather than guessed.

Timestamps are parsed using the browser's date parser. Date formats can be locale-dependent; check the displayed event time if an export uses an unfamiliar format. Time-based correlation is skipped when a usable timestamp is unavailable.

## Supported Event IDs

| Event ID | Meaning | Default treatment |
|---|---|---|
| 4624 | Successful logon | Informational context |
| 4625 | Failed logon | Low individually; repeated patterns may alert |
| 4688 | Process created | Context only |
| 4720 | User account created | Medium |
| 4726 | User account deleted | Low |
| 4728 | Member added to global security group | Medium; higher if group appears privileged |
| 4732 | Member added to local security group | Medium; higher if group appears privileged |
| 1102 | Security audit log cleared | High investigative priority |
| 4104 | PowerShell script block logging | Context; basic encoding indicators only |
| 7045 | Service installed | Context / Medium investigative priority |

The tool may show other Event IDs in the event table, but does not have specific detection rules for them.

## Detection and correlation rules

### Repeated failed logons

- Default threshold: **5 failed logons**.
- Configurable range: 3–20.
- The account view counts failures for the same account.
- The source view counts failures for the same account and source IP (unknown source values are grouped as unknown).
- With the default five-minute window, at least five timestamped failures must fit inside that interval. The finding includes per-source counts so analysts can compare account-wide and source-specific patterns.
- Duplicate findings are suppressed when the account-level rule already covers the same group of failures.
- Suggested severity: Medium, unless a related successful logon raises priority.

### Failed logons followed by success

The tool looks for the same account's failed logon sequence followed by a successful logon within the selected time window. Default window: **5 minutes**. Available source IP and computer details are shown as context. A match is not proof that the failures caused the successful login.

The window setting also applies to failed-logon clustering and account-creation-to-group-change correlation. Choosing “No time limit” removes the maximum interval but still requires parseable timestamps and correct event order.

### New account followed by group membership change

Event ID 4720 is correlated with Event ID 4728 or 4732 for the same affected account when the group event follows within the configured time window. Groups with names such as `Administrators`, `Domain Admins`, `Enterprise Admins`, and `Backup Operators` receive higher investigative priority. Group-name matching is a simple educational heuristic, not a complete privilege model.

### Privileged group membership changes

Group membership events are shown even without a matching account-creation event. The tool attempts to identify the affected member and group from the message. If details are missing, the finding will state that context is unavailable.

### Security audit log cleared

Event ID 1102 always generates a High-priority finding. Legitimate maintenance is a possible explanation, but the event should normally be reviewed.

### Service installation and PowerShell context

Event ID 7045 generates a review finding because service creation can be legitimate or persistence-related. Event ID 4104 is recognised; only a few obvious encoded-command/Base64 indicators produce an additional review hint. PowerShell itself is not treated as malicious. Event ID 4688 is counted and displayed as context, not used for advanced malware detection.

## Investigation score

Scores are explainable points, for example +10 for repeated failed logons, +20 when a successful logon follows within the configured window, +25 for a newly created account followed by a group change, and +30 for a cleared Security log. Each finding shows its contributing points. These points are **an educational prioritisation mechanism, not a mathematical probability of compromise**. Scores from different rules should not be interpreted as a calibrated risk scale.

## Sample datasets

- `normal-windows-events.csv`: ordinary logons, process creation, account lifecycle activity and a sample service installation. It should not generate authentication-correlation alerts.
- `repeated-failed-logons.csv`: repeated failed logons from reserved documentation IP `192.0.2.45` without a later success, for a focused threshold demonstration.
- `password-guessing.csv`: the same repeated failures followed by a successful logon for the same account.
- `account-persistence.csv`: fictional account creation followed by addition to the local `Administrators` group.
- `suspicious-admin-activity.csv`: repeated authentication failures, success, account creation, privilege change, Security log clearing, service installation and process creation.

All sample identities and hosts are fictional. The IP ranges `192.0.2.0/24` and `198.51.100.0/24` are reserved for documentation examples.

## False positives and limitations

- A user may mistype a password or a service may have stale credentials.
- Account creation and group membership changes may be approved administration.
- Audit logs may be cleared during authorised maintenance.
- Service installation and PowerShell activity are common in legitimate environments.
- A successful logon near failed logons does not prove the failures caused that success.
- CSV exports differ by Windows configuration, language, provider, and export workflow.
- Some events do not contain source IPs, target account names, or process details.
- Logging and audit policy determine which events exist in the first place. Absence of an event does not prove that activity did not happen.
- Message parsing is heuristic and can miss fields or interpret unfamiliar wording incorrectly.
- Time zones and locale-specific timestamps can complicate ordering.
- The tool analyses only the supplied dataset and has limited cross-event correlation. It does not query identity providers, MFA, EDR, a SIEM, or other endpoint telemetry.
- Windows Event IDs alone cannot determine intent.
- This tool does not replace an EDR, SIEM, incident response process, or professional SOC platform.

## Accessibility

The interface uses semantic headings, labels, buttons, keyboard-accessible upload controls, visible focus styles, responsive tables, live status messages, and reduced-motion preferences. Tables are horizontally scrollable on small screens.

## Future improvements (not implemented in Version 1)

- Raw `.evtx` parsing
- Sysmon support
- Deeper PowerShell 4104 analysis
- Process-tree visualisation
- MITRE ATT&CK mapping
- More detailed timeline analysis
- Login-time baselining
- Scheduled task monitoring
- Windows Defender event analysis
- Richer service creation detection
- More export formats and SIEM integration

## Educational and authorised use

Only analyse logs from systems you own or are authorised to investigate. Findings are investigative leads, not accusations or proof of compromise. Validate the underlying event in the original Windows logs and gather additional evidence before escalating or taking action.
