'use strict';

/* Windows Security Event Log Triage Tool
 * All analysis runs in this page. No network calls, external libraries, storage, or telemetry.
 */
(() => {
  const MAX_FILE_BYTES = 15 * 1024 * 1024;
  const MAX_ROWS = 50000;
  const DEFAULT_THRESHOLD = 5;
  const DEFAULT_WINDOW_MINUTES = 5;
  const $ = (id) => document.getElementById(id);
  const state = { events: [], findings: [], filename: '', demo: false, rawRowCount: 0, parseWarnings: [] };

  const EVENT_INFO = {
    '4624': { name: 'Successful logon', severity: 'Informational', type: 'Authentication', explanation: 'A Windows account successfully logged on. This is useful context and is not automatically suspicious.' },
    '4625': { name: 'Failed logon', severity: 'Low', type: 'Authentication', explanation: 'A Windows account failed to log on. Repeated failures can have benign causes or may deserve investigation.' },
    '4688': { name: 'Process created', severity: 'Informational', type: 'Process activity', explanation: 'A new process was created. Process creation is useful context when process auditing is enabled.' },
    '4720': { name: 'User account created', severity: 'Medium', type: 'Account management', explanation: 'A new user account was created. Confirm that the creation was authorised.' },
    '4726': { name: 'User account deleted', severity: 'Low', type: 'Account management', explanation: 'A user account was deleted. This may be normal account lifecycle work or account manipulation.' },
    '4728': { name: 'Member added to global security group', severity: 'Medium', type: 'Privilege change', explanation: 'A member was added to a global security group. Verify the group and whether the change was authorised.' },
    '4732': { name: 'Member added to local security group', severity: 'Medium', type: 'Privilege change', explanation: 'A member was added to a local security group. Privileged groups deserve closer review.' },
    '1102': { name: 'Security audit log cleared', severity: 'High', type: 'Audit activity', explanation: 'The Windows Security audit log was cleared. This can be legitimate maintenance, but it should normally be investigated.' },
    '4104': { name: 'PowerShell script block logged', severity: 'Informational', type: 'PowerShell activity', explanation: 'PowerShell script block logging can provide visibility into commands and scripts executed on the endpoint.' },
    '7045': { name: 'Service installed', severity: 'Medium', type: 'Service activity', explanation: 'A Windows service was installed. This may be normal software installation or activity worth reviewing for persistence.' }
  };

  // Fictional sample data is embedded so demo buttons work even when index.html is opened via file://.
  const DEMO_ROWS = {
    'normal-windows-events.csv': [
      ['Information','10/21/2026 9:00:00 AM','Microsoft-Windows-Security-Auditing','4624','Logon','LAB\\maya','LAB-WS01','Audit Success','An account was successfully logged on. Account Name: maya; Logon Type: 2; Workstation Name: LAB-WS01; Source Network Address: -'],
      ['Information','10/21/2026 9:04:00 AM','Microsoft-Windows-Security-Auditing','4688','Process Creation','LAB\\maya','LAB-WS01','Audit Success','A new process has been created. New Process Name: C:\\Windows\\System32\\notepad.exe; Creator Process Name: C:\\Windows\\explorer.exe; Process Command Line: notepad.exe'],
      ['Information','10/21/2026 9:10:00 AM','Microsoft-Windows-Security-Auditing','4624','Logon','LAB\\svc-backup','LAB-SRV01','Audit Success','An account was successfully logged on. Account Name: svc-backup; Logon Type: 5; Workstation Name: -; Source Network Address: -'],
      ['Information','10/21/2026 9:15:00 AM','Microsoft-Windows-Security-Auditing','4726','User Account Management','LAB\\admin','LAB-DC01','Audit Success','A user account was deleted. Target Account Name: retired-temp; Subject Account Name: admin;'],
      ['Information','10/21/2026 9:20:00 AM','Service Control Manager','7045','Service Control Manager','SYSTEM','LAB-WS01','Information','A service was installed in the system. Service Name: DemoUpdater; Service File Name: C:\\Program Files\\DemoApp\\updater.exe; Service Start Type: demand start']
    ],
    'password-guessing.csv': [
      ['Information','10/21/2026 10:00:00 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:00:30 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:01:00 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:01:30 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:02:00 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:02:30 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:03:00 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:03:30 AM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\jsmith','LAB-DC01','Audit Failure','An account failed to log on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45; Failure Reason: Unknown user name or bad password.'],
      ['Information','10/21/2026 10:04:00 AM','Microsoft-Windows-Security-Auditing','4624','Logon','LAB\\jsmith','LAB-DC01','Audit Success','An account was successfully logged on. Account Name: jsmith; Logon Type: 3; Workstation Name: DEMO-CLIENT; Source Network Address: 192.0.2.45;']
    ],
    'account-persistence.csv': [
      ['Information','10/21/2026 11:00:00 AM','Microsoft-Windows-Security-Auditing','4720','User Account Management','LAB\\admin','LAB-DC01','Audit Success','A user account was created. Target Account Name: temp-admin; Target Domain Name: LAB; Subject Account Name: admin;'],
      ['Information','10/21/2026 11:02:00 AM','Microsoft-Windows-Security-Auditing','4732','Security Group Management','LAB\\admin','LAB-WS02','Audit Success','A member was added to a security-enabled local group. Member Name: temp-admin; Group Name: Administrators; Subject Account Name: admin;'],
      ['Information','10/21/2026 11:03:00 AM','Microsoft-Windows-Security-Auditing','4624','Logon','LAB\\temp-admin','LAB-WS02','Audit Success','An account was successfully logged on. Account Name: temp-admin; Logon Type: 2; Workstation Name: LAB-WS02; Source Network Address: -']
    ],
    'suspicious-admin-activity.csv': [
      ['Information','10/21/2026 12:00:00 PM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\opsuser','LAB-DC01','Audit Failure','An account failed to log on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:00:30 PM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\opsuser','LAB-DC01','Audit Failure','An account failed to log on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:01:00 PM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\opsuser','LAB-DC01','Audit Failure','An account failed to log on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:01:30 PM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\opsuser','LAB-DC01','Audit Failure','An account failed to log on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:02:00 PM','Microsoft-Windows-Security-Auditing','4625','Logon','LAB\\opsuser','LAB-DC01','Audit Failure','An account failed to log on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:03:00 PM','Microsoft-Windows-Security-Auditing','4624','Logon','LAB\\opsuser','LAB-DC01','Audit Success','An account was successfully logged on. Account Name: opsuser; Logon Type: 3; Workstation Name: BUILD-07; Source Network Address: 198.51.100.23;'],
      ['Information','10/21/2026 12:04:00 PM','Microsoft-Windows-Security-Auditing','4720','User Account Management','LAB\\admin','LAB-DC01','Audit Success','A user account was created. Target Account Name: temp-maint; Target Domain Name: LAB; Subject Account Name: admin;'],
      ['Information','10/21/2026 12:05:00 PM','Microsoft-Windows-Security-Auditing','4732','Security Group Management','LAB\\admin','LAB-WS02','Audit Success','A member was added to a security-enabled local group. Member Name: temp-maint; Group Name: Administrators; Subject Account Name: admin;'],
      ['Information','10/21/2026 12:07:00 PM','Microsoft-Windows-Security-Auditing','1102','Microsoft-Windows-Eventlog','LAB\\admin','LAB-DC01','Audit Success','The audit log was cleared. Subject Account Name: admin; Subject Domain Name: LAB;'],
      ['Information','10/21/2026 12:08:00 PM','Service Control Manager','7045','Service Control Manager','SYSTEM','LAB-WS02','Information','A service was installed in the system. Service Name: DemoRemoteSupport; Service File Name: C:\\Program Files\\DemoRemoteSupport\\service.exe; Service Start Type: auto start'],
      ['Information','10/21/2026 12:09:00 PM','Microsoft-Windows-Security-Auditing','4688','Process Creation','LAB\\temp-maint','LAB-WS02','Audit Success','A new process has been created. New Process Name: C:\\Windows\\System32\\cmd.exe; Creator Process Name: C:\\Windows\\explorer.exe; Process Command Line: cmd.exe /c whoami']
    ]
  };

  function normaliseHeader(value) {
    return String(value || '').replace(/^\uFEFF/, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function parseCSV(text) {
    // RFC-4180-style parser: supports quoted commas, escaped quotes, and newlines inside quoted cells.
    const rows = [];
    let row = [], cell = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
        else if (ch === '"') quoted = false;
        else cell += ch;
      } else if (ch === '"') {
        if (cell.length === 0) quoted = true; else cell += ch;
      } else if (ch === ',') { row.push(cell); cell = ''; }
      else if (ch === '\n') { row.push(cell.replace(/\r$/, '')); rows.push(row); row = []; cell = ''; }
      else cell += ch;
      if (rows.length > MAX_ROWS + 2) throw new Error(`This CSV contains more than ${MAX_ROWS.toLocaleString()} rows. Please export a smaller selection.`);
    }
    if (quoted) throw new Error('The CSV appears malformed: a quoted field was not closed. Re-export the file and try again.');
    if (cell.length || row.length) { row.push(cell.replace(/\r$/, '')); rows.push(row); }
    while (rows.length && rows[rows.length - 1].every(v => !String(v).trim())) rows.pop();
    if (rows.length < 2) throw new Error('The CSV contains a header but no event rows, or the file is empty.');
    const header = rows.shift().map(v => String(v).replace(/^\uFEFF/, '').trim());
    if (header.length < 2) throw new Error('Could not identify CSV columns. Please export a comma-separated CSV file.');
    const records = rows.filter(r => r.some(v => String(v).trim())).map((values, idx) => {
      const obj = {};
      header.forEach((h, i) => { obj[normaliseHeader(h)] = String(values[i] ?? '').trim(); });
      obj.__rowNumber = idx + 2;
      return obj;
    });
    return { headers: header, records };
  }

  function firstValue(record, aliases) {
    for (const alias of aliases) {
      const value = record[normaliseHeader(alias)];
      if (value !== undefined && value !== null && String(value).trim() !== '') return String(value).trim();
    }
    return '';
  }

  function fieldFromMessage(message, labels) {
    if (!message) return '';
    for (const label of labels) {
      const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp('(?:^|[\\r\\n;])\\s*' + escaped + '\\s*:\\s*([^;\\r\\n]+)', 'i');
      const match = message.match(re);
      if (match && match[1].trim()) {
        const value = match[1].trim();
        if (!['-', 'n/a', 'not available', ''].includes(value.toLowerCase())) return value;
      }
    }
    return '';
  }

  function parseTimestamp(value) {
    if (!value) return null;
    const s = String(value).trim();
    // ISO timestamps are interpreted directly. Windows locale timestamps use browser Date parsing.
    const date = new Date(s);
    if (Number.isNaN(date.getTime())) return null;
    return date;
  }

  function accountKey(value) { return String(value || '').trim().toLowerCase(); }
  function cleanAccount(value) {
    const v = String(value || '').trim();
    return v && !['-', 'n/a', 'not available', 'unknown'].includes(v.toLowerCase()) ? v : '';
  }
  function normaliseIP(value) {
    const v = String(value || '').trim();
    if (!v || ['-', '::1', '127.0.0.1', 'n/a', 'unknown'].includes(v.toLowerCase())) return v === '127.0.0.1' || v === '::1' ? v : '';
    return v;
  }

  function normaliseRecords(parsed) {
    const headers = parsed.headers.map(normaliseHeader);
    const eventIdAliases = ['Event ID', 'EventID', 'event_id', 'ID'];
    const hasEventId = eventIdAliases.some(a => headers.includes(normaliseHeader(a)));
    if (!hasEventId) throw new Error('Required column missing: Event ID. Expected a column such as “Event ID”, “EventID”, or “event_id”.');
    const timestampAliases = ['Date and Time', 'TimeCreated', 'Timestamp', 'DateTime', 'Time Created', 'Time'];
    const messageAliases = ['Message', 'Description', 'Event Message', 'Details'];
    const events = [];
    const warnings = [];
    let skippedNoId = 0;
    for (const record of parsed.records) {
      const eventId = firstValue(record, eventIdAliases).replace(/\.0$/, '');
      if (!/^\d{1,6}$/.test(eventId)) { skippedNoId++; continue; }
      const message = firstValue(record, messageAliases);
      const rawTime = firstValue(record, timestampAliases);
      const timestamp = parseTimestamp(rawTime);
      const rawUser = firstValue(record, ['User', 'Account', 'Account Name', 'Target Account Name', 'Subject Account Name', 'User Name']);
      let account = cleanAccount(rawUser);
      let subjectAccount = cleanAccount(firstValue(record, ['Subject Account Name', 'SubjectUserName', 'Subject Account', 'Initiating Account']));
      let targetAccount = cleanAccount(firstValue(record, ['Target Account Name', 'TargetUserName', 'Target Account', 'Member Name', 'Account Name']));
      const sourceIP = normaliseIP(firstValue(record, ['Source IP', 'Source Network Address', 'IpAddress', 'Client Address', 'Client IP', 'Source Address'])) || normaliseIP(fieldFromMessage(message, ['Source Network Address', 'Source IP Address', 'IpAddress', 'Client Address', 'Source Address', 'Source Network Address']));
      const computer = firstValue(record, ['Computer', 'Computer Name', 'Hostname', 'Host']) || '';
      const workstation = firstValue(record, ['Workstation Name', 'Workstation', 'WorkstationName']) || fieldFromMessage(message, ['Workstation Name', 'Workstation']);
      const groupName = firstValue(record, ['Group Name', 'Group']) || fieldFromMessage(message, ['Group Name', 'Group']);
      const processName = firstValue(record, ['New Process Name', 'Process Name', 'Process']) || fieldFromMessage(message, ['New Process Name', 'Process Name']);
      const parentProcess = firstValue(record, ['Creator Process Name', 'Parent Process Name', 'Parent Process']) || fieldFromMessage(message, ['Creator Process Name', 'Parent Process Name']);
      const commandLine = firstValue(record, ['Process Command Line', 'Command Line']) || fieldFromMessage(message, ['Process Command Line', 'Command Line']);
      const logonType = firstValue(record, ['Logon Type', 'LogonType']) || fieldFromMessage(message, ['Logon Type']);
      const info = EVENT_INFO[eventId] || { name: 'Other Windows event', severity: 'Informational', type: 'Other', explanation: 'This Event ID is not covered by the current educational detection rules.' };
      // For authentication events, account name is the target identity where possible.
      if (['4624', '4625'].includes(eventId)) account = targetAccount || cleanAccount(fieldFromMessage(message, ['Account Name', 'Target Account Name'])) || account;
      // For group-change events, member is the account being changed; actor remains separate.
      if (['4728', '4732'].includes(eventId)) account = targetAccount || cleanAccount(fieldFromMessage(message, ['Member Name', 'Target Account Name', 'Account Name'])) || account;
      if (eventId === '4720') account = targetAccount || cleanAccount(fieldFromMessage(message, ['Target Account Name', 'New Account Name', 'Account Name'])) || account;
      if (eventId === '4726') account = targetAccount || cleanAccount(fieldFromMessage(message, ['Target Account Name', 'Account Name'])) || account;
      const combined = [message, processName, commandLine].join(' ');
      const obfuscated = eventId === '4104' && /-enc(?:odedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string|\[convert\]::frombase64string/i.test(combined);
      events.push({
        index: events.length, rowNumber: record.__rowNumber, eventId, timestamp, rawTimestamp: rawTime,
        source: firstValue(record, ['Source', 'Provider', 'Event Source']), level: firstValue(record, ['Level', 'Severity']),
        task: firstValue(record, ['Task Category', 'Task']), keywords: firstValue(record, ['Keywords']),
        account: account || '', subjectAccount: subjectAccount || cleanAccount(fieldFromMessage(message, ['Subject Account Name', 'SubjectUserName'])) || '',
        targetAccount: targetAccount || cleanAccount(fieldFromMessage(message, ['Target Account Name', 'New Account Name', 'Member Name'])) || '',
        sourceIP: sourceIP || '', computer, workstation: workstation || '', groupName: groupName || '', processName: processName || '', parentProcess: parentProcess || '', commandLine: commandLine || '', logonType: logonType || '', message,
        name: info.name, severity: info.severity, type: info.type, explanation: info.explanation, obfuscated,
        searchText: [eventId, info.name, account, subjectAccount, targetAccount, sourceIP, computer, workstation, message, processName, commandLine, groupName].join(' ').toLowerCase()
      });
    }
    if (!events.length) throw new Error('No valid event IDs were found in the CSV. Check that the Event ID column contains numeric Windows event IDs.');
    if (skippedNoId) warnings.push(`${skippedNoId} row(s) without a valid numeric Event ID were skipped.`);
    if (!headers.some(h => ['dateandtime','timecreated','timestamp','datetime','timecreated','time'].includes(h))) warnings.push('No recognised timestamp column was found. Time-based correlations may be unavailable.');
    if (!headers.some(h => ['message','description','eventmessage','details'].includes(h))) warnings.push('No Message/Description column was found. Detection is limited to available columns.');
    if (events.some(e => !e.timestamp)) warnings.push('Some timestamps could not be parsed. Those events will not participate in time-based correlation.');
    return { events, warnings };
  }

  function isWithinWindow(a, b, windowMinutes) {
    if (!a.timestamp || !b.timestamp) return false;
    const diff = (b.timestamp.getTime() - a.timestamp.getTime()) / 60000;
    return diff >= 0 && (windowMinutes === 0 || diff <= windowMinutes);
  }
  function thresholdCluster(group, threshold, windowMinutes) {
    const sorted = group.filter(e => e.timestamp).slice().sort((a,b)=>a.timestamp.getTime()-b.timestamp.getTime());
    if (windowMinutes === 0) return sorted.length >= threshold ? sorted : [];
    for (let start = 0; start <= sorted.length - threshold; start++) {
      const end = start + threshold - 1;
      const spanMinutes = (sorted[end].timestamp.getTime() - sorted[start].timestamp.getTime()) / 60000;
      if (spanMinutes <= windowMinutes) return sorted.slice(start, end + 1);
    }
    return [];
  }
  function uniqueValues(values) { return [...new Set(values.filter(Boolean))]; }
  function groupBy(items, keyFn) {
    const map = new Map();
    items.forEach(item => { const key = keyFn(item); if (!key) return; if (!map.has(key)) map.set(key, []); map.get(key).push(item); });
    return map;
  }
  function isPrivilegedGroup(groupName) {
    return /administrators|domain admins|enterprise admins|schema admins|backup operators|server operators|account operators|print operators|remote desktop users|hyper-v administrators/i.test(groupName || '');
  }
  function eventTime(event) { return event.timestamp ? event.timestamp.toLocaleString() : event.rawTimestamp || 'Time unavailable'; }
  function accountOrUnknown(event) { return event.account || event.targetAccount || event.subjectAccount || 'Unknown / not available'; }
  function makeFinding(data) {
    const eventIds = uniqueValues((data.events || []).map(e => e.eventId));
    const accounts = uniqueValues((data.events || []).map(e => e.account || e.targetAccount));
    const times = (data.events || []).filter(e => e.timestamp).map(e => e.timestamp.getTime()).sort((a,b)=>a-b);
    const sources = uniqueValues((data.events || []).map(e => e.sourceIP));
    const computers = uniqueValues((data.events || []).map(e => e.computer || e.workstation));
    return { id: data.id, title: data.title, severity: data.severity, events: data.events || [], eventIds, account: data.account || accounts.join(', ') || 'Unknown / not available', start: times.length ? new Date(times[0]) : null, end: times.length ? new Date(times[times.length - 1]) : null, sourceIP: sources.join(', ') || 'Not available', computer: computers.join(', ') || 'Not available', observed: data.observed, why: data.why, benign: data.benign, steps: data.steps || [], score: data.score || 0, scoreReasons: data.scoreReasons || [], category: data.category || 'Detection', type: data.type || 'Finding' };
  }

  function analyse(events) {
    const threshold = Math.max(3, Math.min(20, Number.parseInt($('threshold-input').value, 10) || DEFAULT_THRESHOLD));
    const windowMinutes = Math.max(0, Number.parseInt($('window-input').value, 10) || 0);
    const findings = [];
    const failed = events.filter(e => e.eventId === '4625');
    const success = events.filter(e => e.eventId === '4624');
    const byAccount = groupBy(failed, e => accountKey(e.account || e.targetAccount));
    const byAccountIP = groupBy(failed, e => accountKey(e.account || e.targetAccount) + '|' + (e.sourceIP || '[unknown-source]'));
    const accountAlertKeys = new Set();
    const correlatedFailIndexes = new Set();

    for (const [key, group] of byAccount) {
      const sorted = thresholdCluster(group, threshold, windowMinutes);
      if (sorted.length < threshold) continue;
      accountAlertKeys.add(key);
      const matchingSuccess = success.filter(s => accountKey(s.account || s.targetAccount) === key && sorted.some(f => isWithinWindow(f, s, windowMinutes)));
      sorted.forEach(e => correlatedFailIndexes.add(e.index));
      const bestSuccess = matchingSuccess.sort((a,b)=>(a.timestamp?.getTime() ?? 0)-(b.timestamp?.getTime() ?? 0))[0];
      const relatedEvents = bestSuccess ? [...sorted, bestSuccess] : sorted;
      const sources = uniqueValues(sorted.map(e => e.sourceIP));
      const sourceBreakdown = countBy(sorted, e => e.sourceIP || 'Unknown source').map(([source, count]) => `${source}: ${count}`).join(', ');
      const scoreReasons = [{ points: 10, reason: `+10 repeated failed logons (threshold ${threshold})` }];
      if (bestSuccess) scoreReasons.push({ points: 20, reason: '+20 a successful logon followed the failures within the configured window' });
      findings.push(makeFinding({
        id: bestSuccess ? 'fail-success-' + key : 'repeated-fail-' + key,
        title: bestSuccess ? 'Possible Password Guessing Followed By Successful Login' : 'Repeated Failed Logons',
        severity: bestSuccess ? 'High' : 'Medium', events: relatedEvents, account: sorted[0].account || sorted[0].targetAccount || 'Unknown / not available',
        observed: `${sorted.length} failed logon event(s) for this account${bestSuccess ? ', followed by a successful logon within the configured time window' : ''}. Source IPs observed: ${sources.join(', ') || 'not available'}. Source-specific counts: ${sourceBreakdown || 'not available'}.`,
        why: bestSuccess ? 'Multiple failed authentication attempts followed by a successful login may indicate that a password was eventually guessed. Matching account and time are supporting context, not proof that the success resulted from the failures.' : 'Repeated authentication failures can occur during password guessing, but may also result from a forgotten password, mistyped credentials, or an application using stale credentials.',
        benign: 'A legitimate user may have entered the wrong password several times, or a service/application may be using outdated credentials.',
        steps: ['Verify the source device and whether the source IP is expected.', 'Confirm the affected account with its owner or administrator.', ...(bestSuccess ? ['Review activity after the successful login and check endpoint or MFA telemetry.'] : ['Check whether failures were followed by a successful login.']), 'Determine whether other accounts were targeted.', 'Review authentication policy and relevant endpoint telemetry.'],
        score: scoreReasons.reduce((n,r)=>n+r.points,0), scoreReasons, category: 'Authentication', type: bestSuccess ? 'Failed logon → success' : 'Repeated failed logons'
      }));
    }
    // Separate source-specific view, avoiding a duplicate alert when account-level grouping already covers the same failure cluster.
    for (const [key, group] of byAccountIP) {
      const sorted = thresholdCluster(group, threshold, windowMinutes);
      if (sorted.length < threshold) continue;
      const accountKeyPart = key.split('|')[0];
      const allForAccount = byAccount.get(accountKeyPart) || [];
      if (accountAlertKeys.has(accountKeyPart) && allForAccount.length >= threshold) continue;
      findings.push(makeFinding({ id: 'repeated-fail-ip-' + key, title: 'Repeated Failed Logons From One Source', severity: 'Medium', events: sorted, account: sorted[0].account || 'Unknown / not available', observed: `${sorted.length} failed logons for the same account and source IP (${sorted[0].sourceIP || 'source unavailable'}).`, why: 'A repeated failure pattern from one source can be consistent with password guessing, but it can also be caused by an incorrectly configured application or repeated user error.', benign: 'A legitimate workstation or service may repeatedly submit stale credentials.', steps: ['Verify whether the source IP belongs to an expected device.', 'Check other accounts targeted by the same source.', 'Review account lockout, MFA and endpoint telemetry.'], score: 10, scoreReasons: [{ points: 10, reason: `+10 repeated failed logons from one source (threshold ${threshold})` }], category: 'Authentication', type: 'Account + source failures' }));
    }

    // Account creation followed by privilege change: correlate target/member account, ordering, and configured window.
    const created = events.filter(e => e.eventId === '4720');
    const groupChanges = events.filter(e => ['4728','4732'].includes(e.eventId));
    const usedGroupChange = new Set();
    for (const createEvent of created) {
      const newAccount = accountKey(createEvent.targetAccount || createEvent.account || fieldFromMessage(createEvent.message, ['Target Account Name','New Account Name']));
      if (!newAccount) continue;
      const matches = groupChanges.filter(g => {
        const member = accountKey(g.targetAccount || g.account || fieldFromMessage(g.message, ['Member Name','Target Account Name']));
        return member === newAccount && isWithinWindow(createEvent, g, windowMinutes);
      });
      if (!matches.length) continue;
      matches.forEach(g => usedGroupChange.add(g.index));
      const privileged = matches.some(g => isPrivilegedGroup(g.groupName || fieldFromMessage(g.message, ['Group Name'])));
      const allEvents = [createEvent, ...matches];
      const reasons = [{points:25,reason:'+25 account creation followed by a group membership change'}];
      if (privileged) reasons.push({points:25,reason:'+25 the group name appears privileged'});
      findings.push(makeFinding({ id:'new-account-priv-'+newAccount, title: privileged ? 'New Account Granted Privileged Group Membership' : 'New Account Followed By Group Membership Change', severity: privileged ? 'High' : 'Medium', events:allEvents, account:createEvent.targetAccount || createEvent.account || 'Unknown / not available', observed:`Account creation was followed by ${matches.map(e=>e.eventId).join(', ')} group membership change event(s) within the configured time window. Group(s): ${uniqueValues(matches.map(e=>e.groupName || fieldFromMessage(e.message,['Group Name']))).join(', ') || 'not available'}.`, why:'Creating an account and quickly adding it to a security group can be legitimate administration, but if the group grants elevated access it may indicate unauthorised privilege assignment or persistence.', benign:'An administrator may be onboarding an employee, provisioning a service account, or completing an approved maintenance task.', steps:['Confirm the account creation and group change were authorised.', 'Identify the administrator or process that performed each action.', 'Review activity performed by the new account.', 'Confirm the account and privilege level are still required.'], score:reasons.reduce((n,r)=>n+r.points,0), scoreReasons:reasons, category:'Administrative / Privilege Activity', type:'Account + privilege change' }));
    }
    // Highlight privileged group changes even when there is no matching creation event.
    for (const event of groupChanges) {
      if (usedGroupChange.has(event.index)) continue;
      const groupName = event.groupName || fieldFromMessage(event.message, ['Group Name']);
      const privileged = isPrivilegedGroup(groupName);
      findings.push(makeFinding({ id:'group-change-'+event.index, title:privileged ? 'Privileged Group Membership Changed' : 'Security Group Membership Changed', severity:privileged ? 'High' : 'Medium', events:[event], account:event.targetAccount || event.account || 'Unknown / not available', observed:`Event ${event.eventId} records a group membership change. Group: ${groupName || 'not available'}.`, why:privileged ? 'The group name appears to represent elevated access. Validate the member, authorising administrator, and business reason.' : 'Security group membership can change access to resources. Confirm the change was expected.', benign:'An authorised administrator may be updating access as part of onboarding, role changes or maintenance.', steps:['Verify the affected member and group.', 'Identify the actor who made the change.', 'Confirm approval and business justification.'], score:privileged?25:15, scoreReasons:[{points:privileged?25:15,reason:privileged?'+25 privileged group membership changed':'+15 security group membership changed'}], category:'Administrative / Privilege Activity', type:'Group membership change' }));
    }

    // Audit log clearing is independently high priority.
    for (const event of events.filter(e=>e.eventId==='1102')) {
      findings.push(makeFinding({id:'audit-cleared-'+event.index,title:'Security Audit Log Cleared',severity:'High',events:[event],account:event.subjectAccount || event.account || 'Unknown / not available',observed:'Event ID 1102 indicates that the Windows Security audit log was cleared.',why:'Clearing logs can occur during legitimate administration, but attackers may also clear logs to remove evidence. The event should normally be investigated.',benign:'An authorised administrator may have cleared the log during troubleshooting or maintenance.',steps:['Confirm whether log clearing was approved and expected.', 'Identify the account and system associated with the event.', 'Review other available logs around the same time.', 'Check whether auditing or log forwarding was interrupted.'],score:30,scoreReasons:[{points:30,reason:'+30 Windows Security audit log cleared'}],category:'Administrative / Privilege Activity',type:'Audit log clearing'}));
    }

    for (const event of events.filter(e=>e.eventId==='7045')) {
      findings.push(makeFinding({id:'service-installed-'+event.index,title:'Windows Service Installed',severity:'Medium',events:[event],account:event.account || event.subjectAccount || 'Unknown / not available',observed:`A service installation event was recorded. Details: ${event.message || 'No event message available.'}`,why:'New services are normal during software installation, but services can also be used for persistence. Validate the service name, executable path and change window.',benign:'A legitimate application, driver or update may have installed the service.',steps:['Confirm the software and service were approved.', 'Review the executable path and signer using trusted endpoint tools.', 'Check whether the service account and startup mode are expected.'],score:10,scoreReasons:[{points:10,reason:'+10 service installation event requires validation'}],category:'Administrative / Privilege Activity',type:'Service installation'}));
    }
    for (const event of events.filter(e=>e.eventId==='4104' && e.obfuscated)) {
      findings.push(makeFinding({id:'powershell-obfuscation-'+event.index,title:'PowerShell Script Contains Encoding / Obfuscation Indicators',severity:'Medium',events:[event],account:event.account || 'Unknown / not available',observed:'The script block text contains a common encoded-command or Base64-decoding indicator.',why:'Encoding and obfuscation can be used in legitimate administration and in malicious scripts. This simple text match is only a review hint, not malware detection.',benign:'An administrator or software installer may use encoded content for legitimate automation.',steps:['Review the full script block in the original event.', 'Confirm the script source and intended purpose.', 'Correlate with process creation and endpoint telemetry.'],score:10,scoreReasons:[{points:10,reason:'+10 basic PowerShell encoding indicator'}],category:'Process / Script Activity',type:'PowerShell context'}));
    }

    // Add contextual event counts for process creation without treating every process as suspicious.
    findings.sort((a,b)=>({High:0,Medium:1,Low:2,Informational:3}[a.severity]-({High:0,Medium:1,Low:2,Informational:3}[b.severity]) || (b.score-a.score) || ((a.start?.getTime()||0)-(b.start?.getTime()||0))));
    return findings;
  }

  function severityForEvent(event) {
    if (event.eventId === '1102') return 'High';
    if (['4728','4732'].includes(event.eventId) && isPrivilegedGroup(event.groupName || fieldFromMessage(event.message,['Group Name']))) return 'High';
    return event.severity || 'Informational';
  }
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  }
  function fmtDate(date, raw) { return date ? date.toLocaleString() : raw || 'Unavailable'; }
  function setStatus(message, kind='') { const el=$('file-status'); el.textContent=message; el.className='status-message'+(kind?' '+kind:''); }
  function countBy(items, fn) { const m=new Map(); items.forEach(i=>{const k=fn(i)||'Unknown / not available';m.set(k,(m.get(k)||0)+1);});return [...m.entries()].sort((a,b)=>b[1]-a[1]); }
  function addMetric(label, value, note, icon) {
    const card=document.createElement('div'); card.className='metric-card';
    card.innerHTML=`<div class="metric-top"><span>${esc(label)}</span><span class="metric-icon" aria-hidden="true">${esc(icon)}</span></div><div class="metric-value">${esc(value)}</div><div class="metric-note">${esc(note)}</div>`;
    $('metric-grid').appendChild(card);
  }
  function renderMetrics() {
    const events=state.events, findings=state.findings;
    $('metric-grid').replaceChildren();
    const count=(id)=>events.filter(e=>e.eventId===id).length;
    addMetric('Total events',events.length,'Parsed event rows','▤');
    addMetric('Successful logons',count('4624'),'Event ID 4624','↗');
    addMetric('Failed logons',count('4625'),'Event ID 4625','↘');
    addMetric('Accounts created',count('4720'),'Event ID 4720','＋');
    addMetric('Privilege changes',events.filter(e=>['4728','4732'].includes(e.eventId)).length,'Group membership events','◇');
    addMetric('Audit log clearing',count('1102'),'Event ID 1102','!');
    addMetric('Process creation',count('4688'),'Event ID 4688','▣');
    addMetric('Findings to investigate',findings.filter(f=>['High','Medium'].includes(f.severity)).length,'High or Medium findings','⌕');
  }
  function renderRankList(id, entries, formatter) {
    const root=$(id); root.replaceChildren();
    if(!entries.length){const p=document.createElement('p');p.className='empty-state';p.textContent='No matching data.';root.appendChild(p);return;}
    const max=Math.max(...entries.slice(0,5).map(x=>x[1]),1);
    entries.slice(0,5).forEach(([name,n])=>{
      const row=document.createElement('div');row.className='rank-row';
      const nm=document.createElement('span');nm.className='rank-name';nm.textContent=formatter?formatter(name):name;nm.title=nm.textContent;
      const track=document.createElement('span');track.className='rank-track';const fill=document.createElement('span');fill.className='rank-fill';fill.style.display='block';fill.style.width=(n/max*100)+'%';track.appendChild(fill);
      const count=document.createElement('span');count.className='rank-count';count.textContent=String(n);
      row.append(nm,track,count);root.appendChild(row);
    });
  }
  function renderContext() {
    renderRankList('top-accounts',countBy(state.events,e=>e.account||e.targetAccount));
    renderRankList('failed-accounts',countBy(state.events.filter(e=>e.eventId==='4625'),e=>e.account||e.targetAccount));
    renderRankList('common-event-ids',countBy(state.events,e=>e.eventId),id=>`${id} · ${EVENT_INFO[id]?.name||'Other event'}`);
  }
  function renderAlerts() {
    const root=$('alerts-list');root.replaceChildren();$('finding-count').textContent=`${state.findings.length} finding${state.findings.length===1?'':'s'}`;
    if(!state.findings.length){const p=document.createElement('p');p.className='empty-state';p.textContent='No correlation-based findings were generated. Review the event table and remember that the current rules cover only a small set of event patterns.';root.appendChild(p);return;}
    state.findings.forEach(f=>{
      const article=document.createElement('article');article.className='alert-card severity-'+f.severity.toLowerCase();
      const titleRow=document.createElement('div');titleRow.className='alert-title-row';
      const title=document.createElement('div');title.className='alert-title';title.textContent=f.title;
      const badge=document.createElement('span');badge.className='severity-badge '+f.severity.toLowerCase();badge.textContent=f.severity;
      titleRow.append(title,badge);article.appendChild(titleRow);
      const meta=document.createElement('p');meta.className='alert-meta';meta.textContent=`Event ID(s): ${f.eventIds.join(', ')||'Unavailable'} · Account: ${f.account} · Time: ${f.start?fmtDate(f.start):'Unavailable'}${f.end&&f.start&&f.end.getTime()!==f.start.getTime()?' – '+fmtDate(f.end):''}`;article.appendChild(meta);
      const observed=document.createElement('p');observed.className='alert-detail';observed.textContent=f.observed;article.appendChild(observed);
      const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Why it matters, benign explanations and next steps';details.appendChild(summary);
      const body=document.createElement('div');body.className='alert-detail';
      const p1=document.createElement('p');p1.innerHTML='<strong>Why this matters:</strong> '+esc(f.why);
      const p2=document.createElement('p');p2.innerHTML='<strong>Possible benign explanation:</strong> '+esc(f.benign);
      const p3=document.createElement('p');p3.innerHTML='<strong>Available context:</strong> '+esc(`Source IP: ${f.sourceIP}; Computer/workstation: ${f.computer}.`);
      const p4=document.createElement('p');p4.innerHTML='<strong>Suggested investigation:</strong>';
      const ol=document.createElement('ol');f.steps.forEach(s=>{const li=document.createElement('li');li.textContent=s;ol.appendChild(li);});
      const score=document.createElement('p');score.className='score-line';score.textContent=`Educational investigation score: ${f.score} · ${f.scoreReasons.map(r=>r.reason).join('; ')}. This is prioritisation, not a probability of compromise.`;
      body.append(p1,p2,p3,p4,ol,score);details.appendChild(body);article.appendChild(details);root.appendChild(article);
    });
  }
  function fillSelect(id, values, label) {
    const select=$(id), prior=select.value;
    while(select.options.length>1)select.remove(1);
    values.filter(Boolean).sort((a,b)=>String(a).localeCompare(String(b))).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;select.appendChild(o);});
    if([...select.options].some(o=>o.value===prior))select.value=prior;else select.value='';
  }
  function refreshFilters() {
    fillSelect('event-filter',uniqueValues(state.events.map(e=>e.eventId)));
    fillSelect('account-filter',uniqueValues(state.events.map(e=>e.account||e.targetAccount)));
    fillSelect('source-filter',uniqueValues(state.events.map(e=>e.sourceIP)));
    fillSelect('type-filter',uniqueValues(state.events.map(e=>e.type)));
  }
  function filteredEvents() {
    const q=$('search-input').value.trim().toLowerCase(), eventId=$('event-filter').value, account=$('account-filter').value, severity=$('severity-filter').value, source=$('source-filter').value, type=$('type-filter').value;
    return state.events.filter(e=>(!q||e.searchText.includes(q))&&(!eventId||e.eventId===eventId)&&(!account||(e.account||e.targetAccount)===account)&&(!severity||severityForEvent(e)===severity)&&(!source||e.sourceIP===source)&&(!type||e.type===type));
  }
  function renderEvents() {
    const body=$('events-table-body');body.replaceChildren();const filtered=filteredEvents();$('visible-events-count').textContent=`${filtered.length} / ${state.events.length} events`;
    if(!filtered.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.className='empty-state';td.textContent=state.events.length?'No events match these filters.':'No events loaded.';tr.appendChild(td);body.appendChild(tr);$('filter-status').textContent='';return;}
    filtered.slice(0,1500).forEach(e=>{
      const tr=document.createElement('tr');
      const vals=[fmtDate(e.timestamp,e.rawTimestamp),e.eventId,severityForEvent(e),e.account||e.targetAccount||'Unavailable',e.sourceIP||'Unavailable',e.computer||e.workstation||'Unavailable',e.name+(e.message?' — '+e.message:'')];
      vals.forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===6)td.className='event-summary';if(i===1)td.title=e.explanation;tr.appendChild(td);});body.appendChild(tr);
    });
    $('filter-status').textContent=filtered.length>1500?`Showing first 1,500 of ${filtered.length} matching events for responsiveness.`:'';
  }
  function renderTimeline() {
    const root=$('timeline-list');root.replaceChildren();
    const noteworthy=state.events.filter(e=>['4625','4720','4726','4728','4732','1102','7045','4104'].includes(e.eventId)).sort((a,b)=>(a.timestamp?.getTime()??0)-(b.timestamp?.getTime()??0)).slice(0,30);
    if(!noteworthy.length){const li=document.createElement('li');li.className='empty-state';li.textContent='No noteworthy events in the supported set.';root.appendChild(li);return;}
    noteworthy.forEach(e=>{const li=document.createElement('li');const time=document.createElement('div');time.className='timeline-time';time.textContent=fmtDate(e.timestamp,e.rawTimestamp);const title=document.createElement('div');title.className='timeline-title';title.textContent=`${e.eventId} · ${e.name}`;const desc=document.createElement('div');desc.className='timeline-description';desc.textContent=`Account: ${accountOrUnknown(e)} · Computer: ${e.computer||'Unavailable'}`;li.append(time,title,desc);root.appendChild(li);});
  }
  function renderAll() {
    state.findings=analyse(state.events);
    $('results-section').classList.remove('hidden');$('demo-indicator').classList.toggle('hidden',!state.demo);
    $('dataset-summary').textContent=`${state.filename} · ${state.events.length.toLocaleString()} events parsed${state.demo?' · Demo Data':''}`;
    renderMetrics();renderAlerts();renderContext();refreshFilters();renderEvents();renderTimeline();
  }
  function useParsed(name, text, isDemo=false) {
    if (text.length > MAX_FILE_BYTES) throw new Error(`File is larger than ${Math.round(MAX_FILE_BYTES/1024/1024)} MB. Please export a smaller selection.`);
    const parsed=parseCSV(text);
    const normalised=normaliseRecords(parsed);
    state.events=normalised.events;state.filename=name;state.demo=isDemo;state.parseWarnings=normalised.warnings;state.rawRowCount=parsed.records.length;
    renderAll();
    const warningText=normalised.warnings.length?' Warnings: '+normalised.warnings.join(' '):'';
    setStatus(`Successfully parsed ${state.events.length.toLocaleString()} event(s) from ${name}.${warningText}`,normalised.warnings.length?'warning':'success');
  }
  function rowsToCSV(rows) { return rows.map(row=>row.map(value=>{const s=String(value??'');return /[",\r\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;}).join(',')).join('\r\n'); }
  function demoCSV(filename) { let rows=DEMO_ROWS[filename]; if(filename==='repeated-failed-logons.csv') rows=DEMO_ROWS['password-guessing.csv'].filter(r=>r[3]==='4625'); if(!rows)throw new Error('Unknown demo dataset.');return rowsToCSV([['Level','Date and Time','Source','Event ID','Task Category','User','Computer','Keywords','Message'],...rows]); }
  function loadSample(filename) {
    try { useParsed(filename,demoCSV(filename),true); }
    catch(err) { setStatus(err.message||'Could not load demo data.', 'error'); }
  }
  function clearAll() {
    state.events=[];state.findings=[];state.filename='';state.demo=false;state.parseWarnings=[];state.rawRowCount=0;
    $('results-section').classList.add('hidden');$('demo-indicator').classList.add('hidden');$('file-input').value='';$('search-input').value='';
    ['event-filter','account-filter','source-filter','type-filter','severity-filter'].forEach(id=>$(id).value='');
    setStatus('Data cleared from the current page. No uploaded file was saved by this application.');
  }
  function downloadReport() {
    if(!state.events.length)return;
    const escHTML=esc;
    const rows=state.findings.map(f=>`<article class="finding"><h2>${escHTML(f.title)} <span class="sev">${escHTML(f.severity)}</span></h2><p><b>Event IDs:</b> ${escHTML(f.eventIds.join(', '))} · <b>Account:</b> ${escHTML(f.account)}</p><p><b>Time range:</b> ${escHTML(f.start?fmtDate(f.start):'Unavailable')}${f.end&&f.start&&f.end.getTime()!==f.start.getTime()?' – '+escHTML(fmtDate(f.end)):''}</p><p><b>Source IP / computer:</b> ${escHTML(f.sourceIP)} / ${escHTML(f.computer)}</p><p><b>Observed activity:</b> ${escHTML(f.observed)}</p><p><b>Why this matters:</b> ${escHTML(f.why)}</p><p><b>Possible benign explanation:</b> ${escHTML(f.benign)}</p><p><b>Suggested investigation:</b></p><ol>${f.steps.map(s=>'<li>'+escHTML(s)+'</li>').join('')}</ol><p><b>Educational prioritisation score:</b> ${f.score}. ${escHTML(f.scoreReasons.map(r=>r.reason).join('; '))}. Not a probability of compromise.</p></article>`).join('\n');
    const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SOC Triage Report</title><style>body{font:14px/1.55 Arial,sans-serif;color:#172033;max-width:960px;margin:35px auto;padding:0 20px}h1{font-size:26px}h2{font-size:18px;border-bottom:1px solid #ccd4df;padding-bottom:8px}.muted{color:#566579}.finding{border:1px solid #cbd5e1;border-left:5px solid #6688ad;padding:15px;margin:16px 0;break-inside:avoid}.sev{font-size:12px;padding:4px 7px;border-radius:6px;background:#e8eef5}li{margin:5px 0}.notice{background:#fff4d8;padding:12px;border:1px solid #e6ca81}</style></head><body><h1>Windows Security Event Log Triage Report</h1><p class="muted">Generated locally in the browser · Dataset: ${escHTML(state.filename)} · Events analysed: ${state.events.length} · Generated: ${escHTML(new Date().toLocaleString())}</p><p class="notice"><b>Educational use:</b> Findings indicate activity that may deserve investigation and do not prove malicious behaviour. Scores prioritise investigation; they are not probabilities of compromise.</p><h2>Summary</h2><p>Successful logons: ${state.events.filter(e=>e.eventId==='4624').length} · Failed logons: ${state.events.filter(e=>e.eventId==='4625').length} · Accounts created: ${state.events.filter(e=>e.eventId==='4720').length} · Privilege changes: ${state.events.filter(e=>['4728','4732'].includes(e.eventId)).length} · Audit-log clearing: ${state.events.filter(e=>e.eventId==='1102').length} · Findings: ${state.findings.length}</p><h2>Findings</h2>${rows||'<p>No correlation-based findings were generated.</p>'}<h2>Limitations</h2><p>CSV exports may omit fields; timestamps may be ambiguous; correlation depends on available account and time information; Windows Event IDs alone cannot establish intent. Validate findings with original logs and other authorised telemetry.</p><p>Only analyse logs from systems you own or are authorised to investigate.</p></body></html>`;
    const blob=new Blob([html],{type:'text/html;charset=utf-8'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='windows-security-triage-report.html';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);
  }

  $('choose-file-btn').addEventListener('click',()=> $('file-input').click());
  $('drop-zone').addEventListener('click',(event)=>{if(event.target.closest('button'))return;$('file-input').click();});
  $('file-input').addEventListener('change',async event=>{
    const file=event.target.files?.[0];if(!file)return;
    if(!file.name.toLowerCase().endsWith('.csv') && file.type!=='text/csv'){setStatus('Please select a .csv file. Raw .evtx files are not supported.', 'error');event.target.value='';return;}
    if(file.size>MAX_FILE_BYTES){setStatus(`File is larger than ${Math.round(MAX_FILE_BYTES/1024/1024)} MB. Please export a smaller selection.`, 'error');event.target.value='';return;}
    try{const text=await file.text();useParsed(file.name,text,false);}catch(err){setStatus(err.message||'Could not read this CSV. Check its format and try again.', 'error');}
  });
  const dropZone=$('drop-zone');
  ['dragenter','dragover'].forEach(name=>dropZone.addEventListener(name,event=>{event.preventDefault();dropZone.classList.add('drag-over');}));
  ['dragleave','drop'].forEach(name=>dropZone.addEventListener(name,event=>{event.preventDefault();dropZone.classList.remove('drag-over');}));
  dropZone.addEventListener('drop',async event=>{const file=event.dataTransfer?.files?.[0];if(!file)return;if(!file.name.toLowerCase().endsWith('.csv')){setStatus('Please drop a CSV file. Raw .evtx files are not supported.','error');return;}if(file.size>MAX_FILE_BYTES){setStatus('File exceeds the 15 MB safety limit. Export a smaller selection.','error');return;}try{useParsed(file.name,await file.text(),false);}catch(err){setStatus(err.message||'Could not parse this file.','error');}});
  document.querySelectorAll('.sample-btn').forEach(btn=>btn.addEventListener('click',()=>loadSample(btn.dataset.sample)));
  ['search-input','event-filter','account-filter','severity-filter','source-filter','type-filter'].forEach(id=>$(id).addEventListener(id==='search-input'?'input':'change',renderEvents));
  $('threshold-input').addEventListener('change',()=>{if(!state.events.length)return;const v=Math.max(3,Math.min(20,Number.parseInt($('threshold-input').value,10)||DEFAULT_THRESHOLD));$('threshold-input').value=String(v);renderAll();});
  $('window-input').addEventListener('change',()=>{if(state.events.length)renderAll();});
  $('reset-settings-btn').addEventListener('click',()=>{$('threshold-input').value=String(DEFAULT_THRESHOLD);$('window-input').value=String(DEFAULT_WINDOW_MINUTES);if(state.events.length)renderAll();});
  $('clear-results-btn').addEventListener('click',clearAll);
  $('download-report-btn').addEventListener('click',downloadReport);

  // Small parser sanity checks run locally at startup; they do not inspect or transmit user data.
  const selfTest=parseCSV('A,B\r\n"value, with comma","say ""hello"""');
  if(selfTest.records.length!==1 || selfTest.records[0].a!=='value, with comma' || selfTest.records[0].b!=='say "hello"') console.warn('CSV parser self-check did not pass.');
})();
