# Testing Guide — Windows Security Event Log Triage Tool

Use this guide to test the project locally. All sample data is fictional and intended for demonstration.

## Before testing

1. Open `index.html` in a modern browser.
2. Keep the browser developer console available if you are comfortable doing so.
3. Confirm the privacy notice is visible.
4. Use the demo buttons first; they are embedded in the page and should work offline.

## Scenario tests

| Test | Action | Expected result |
|---|---|---|
| 1. Normal activity | Click **Load Normal Sample** | Five events; no repeated failed-logon finding; normal logons and process creation appear as context. The sample includes a service installation review finding by design. |
| 2. Repeated failures | Click **Load Repeated Failed Logons** | Repeated Failed Logons finding for `jsmith`; account and source-specific views are represented without duplicate incident noise. |
| 3. Failure then success | Keep the five-minute window and click **Load Password Guessing → Success** | A High-priority Possible Password Guessing Followed By Successful Login finding; the report explains legitimate alternatives. |
| 4. Account then privilege | Click **Load Privilege Escalation** | A High-priority finding linking `temp-admin` account creation to addition to the `Administrators` group. |
| 5. Audit log cleared | Click **Load Mixed SOC Sample** | A High-priority Security Audit Log Cleared finding, plus authentication and administrative findings. |
| 6. Threshold setting | Change threshold to 10, then load Repeated Failed Logons | Eight failures should not trigger the repeated-failure threshold alert. |
| 7. Time window | Set 5 minutes, load the password sample | The successful login occurs within the window and should correlate. |
| 8. Filters | Load Mixed SOC Sample; select Event ID 1102 | Only audit-log-clearing event rows remain in the table. |
| 9. Report download | Load a sample and click **Download SOC report** | Browser downloads `windows-security-triage-report.html`; report includes findings and limitations. |
| 10. Clear data | Click **Clear data** | Dashboard is hidden and current in-memory events are cleared. |

## CSV validation tests

Create copies of a sample CSV and test the following:

- Rename the Event ID header to `EventID` or `event_id`; parsing should still succeed.
- Remove the Event ID column; the tool should show a clear required-column error.
- Remove the Message column; parsing should succeed with a warning and reduced extraction capability.
- Include a quoted message containing commas and doubled quotes; the parser should preserve the field.
- Include a quoted message containing a newline; the parser should preserve it as one CSV cell.
- Leave an unterminated quoted field; the tool should show a malformed CSV error.
- Include blank rows or rows without numeric Event IDs; blank rows should be ignored and invalid-ID rows skipped with a warning.
- Try a non-CSV file; the tool should reject it.
- Try a file over 15 MB or a CSV with more than 50,000 rows; the tool should refuse it with an explanation.

## Safe-rendering test

Make a copy of a sample CSV and put this literal string into a Message field:

```html
<img src=x onerror="alert('test')"><script>alert('test')</script>
```

Upload the edited CSV. The text should be displayed literally or escaped in the report. No alert dialog should appear, and no new HTML element should be created from that content.

## Privacy review

1. Open the browser developer tools and select the Network panel.
2. Reload `index.html` while online or offline.
3. Click each demo button and analyse a local CSV.
4. Confirm the application does not initiate requests to external domains. There should be no network request for demo datasets because demo data is embedded in `script.js`.
5. Search the source for `fetch`, `XMLHttpRequest`, `sendBeacon`, analytics SDKs, external `<script src>` URLs, or remote storage calls. None should be required by this project.
6. Remember that a publicly hosted website necessarily makes a normal request to its host to load the website files. The application does not send uploaded log contents to the host.

## Expected limitations to record

- Date parsing is based on the browser's date parser; unfamiliar locale formats may be ambiguous.
- Correlation requires a parseable timestamp and usable account fields.
- Group and process details may be embedded in provider-specific messages, and extraction is best-effort.
- The application is a static educational triage tool, not a replacement for a SIEM or EDR.

Record any unexpected behaviour before using the project in a recruiter demonstration. Do not present a successful test as proof that a dataset is malicious or benign; the tests validate the application's rule behaviour only.
