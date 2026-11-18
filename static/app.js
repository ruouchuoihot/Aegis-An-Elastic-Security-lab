'use strict';
const $ = id => document.getElementById(id);
const state = { incidents: [], scope: null, agent: null, busy: false, alerts: [], rules: new Map(), alertPage: 0, jobs: [], pending: new Set() };
const localInput = date => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
$('start').value = localInput(new Date(Date.now() - 86400000));
$('end').value = localInput(new Date(Date.now() + 60000));
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = error ? 'error' : ''; }
async function api(path, body) {
  const headers = {};
  if ($('token').value) headers.Authorization = `Bearer ${$('token').value}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw new Error(response.status === 401 ? 'Enter your gateway token, then refresh.' : typeof result.detail === 'string' ? result.detail : `Request failed (${response.status})`);
  return result;
}
function controls() {
  $('refresh').disabled = state.busy;
  $('run-rules').disabled = state.busy;
}
async function work(action) {
  if (state.busy) return;
  state.busy = true; controls();
  try { await action(); } catch (error) { notice(error.message, true); }
  finally { state.busy = false; controls(); }
}
function badge(value) { return el('span', value || 'unknown', `badge ${value || 'unknown'}`); }
function dateLabel(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString(); }
function rawDetails(value, title = 'Technical details & audit record') {
  const details = el('details'); details.append(el('summary', title), el('pre', JSON.stringify(value, null, 2))); return details;
}
function hostName(incident) { return incident.host_name || incident.alerts?.find(a => a.observed?.host_name)?.observed.host_name || incident.entity || 'Unknown host'; }
function origin(value) { return ({ endpoint_lab: 'Real lab telemetry', synthetic: 'Generated sample data', unknown: 'Origin unverified' })[value] || value; }
function assessmentLabel(value) { return ({ suspicious: 'Suspicious activity', likely_benign: 'Likely expected activity', inconclusive: 'More evidence needed' })[value] || 'Analyst review needed'; }
function ruleName(value) { return (value || '').replace(/^AiSOC:\s*/i, ''); }
function ruleMeaning(alert) {
  const technique = alert.technique?.id;
  if (technique === 'T1547.001') return 'A registry value was set under an autorun key. Review the value target and writing process to assess persistence.';
  if (technique === 'T1053.005') return alert.rule.id.includes('encoded') ? 'A newly created scheduled task contains an encoded command. This is evidence of task configuration; it does not prove the action executed.' : 'A newly created task points to an action in a writable directory. Inspect the action path, task owner and related execution.';
  if (technique === 'T1059.001') return 'PowerShell was started with an encoded command option. Decode and inspect the command and its process ancestry before deciding intent.';
  if (technique === 'T1140') return 'Certutil was started with a decode or URL-cache option. Inspect the command, output artifact and subsequent execution.';
  if (technique === 'T1033') return 'whoami.exe queries the current user identity. The rule detects process creation; it does not establish the command output or malicious intent.';
  if (technique === 'T1082') return 'A system discovery utility was started (hostname, systeminfo or reg). Check the process and its parent to distinguish the test from other administration.';
  if (technique === 'T1016') return 'A network discovery utility was started. These tools can inspect interfaces, address mappings or local network configuration; process creation alone does not prove an attack.';
  if (technique === 'T1057' || alert.rule?.id?.includes('process-discovery')) return 'The rule flags process discovery: tasklist lists running processes. This can be legitimate administration as well as attacker discovery.';
  return alert.rule?.name ? `The source event matched the rule “${ruleName(alert.rule.name)}”. A match is a reason to investigate, not a confirmed compromise.` : 'A detection rule matched this event. Review the original evidence before escalating.';
}
function facts(incident) {
  const box = el('div', undefined, 'activity-facts');
  const first = incident.alerts?.[0]; const observed = first?.observed || {};
  const processes = [...new Set(incident.alerts.map(a => a.observed?.process_name).filter(Boolean))];
  const title = processes.length > 1 ? `${processes.join(', ')} on ${hostName(incident)}` : observed.process_name ? `${observed.process_name} on ${hostName(incident)}` : `Rule match on ${hostName(incident)}`;
  box.append(el('h4', title), el('p', first?.source_event?.timestamp ? dateLabel(first.source_event.timestamp) : 'Event time unavailable'));
  if (observed.parent_process && observed.process_name) box.append(el('div', `${observed.parent_process} → ${observed.process_name}`, 'process-chain'));
  if (observed.registry_path) box.append(el('p', `Registry value: ${observed.registry_path}`));
  if (observed.task_command_path) box.append(el('p', `Task action: ${observed.task_command_path}`));
  const grid = el('dl', undefined, 'fact-grid');
  for (const [label, value] of [['Host', hostName(incident)], ['Severity', incident.severity], ['Source', origin(incident.provenance)], ['Technique', incident.techniques?.join(', ') || 'Not mapped']]) {
    grid.append(el('dt', label), el('dd', value));
  }
  box.append(grid); return box;
}
function reportSection(card, title, values) {
  if (!values?.length) return;
  const section = el('section', undefined, 'report-section'); section.append(el('h4', title));
  const list = el('ul'); for (const value of values) list.append(el('li', value));
  section.append(list); card.append(section);
}
function evidenceLabel(entry, id) {
  const alert = entry.incident.alerts.find(a => `${a.reference.index}:${a.reference.id}` === id);
  if (alert) return `Detection: ${ruleName(alert.rule.name) || 'matched rule'}`;
  const evidence = (entry.decision.agent_steps || []).flatMap(step => step.result?.evidence || []).find(row => row.evidence_id === id);
  const event = evidence?.event;
  if (event) return `${event.winlog?.provider_name?.includes('Sysmon') ? 'Sysmon' : 'Windows event'} ${event.winlog?.record_id ? '#' + event.winlog.record_id : ''}: ${event.process?.name || event.event?.action || event.event?.code || 'host activity'} · ${dateLabel(event['@timestamp'])}`;
  return 'Source reference (full ID in the audit record)';
}
function decisionCard(entry) {
  const d = entry.decision; const card = el('article', undefined, 'decision-card report');
  const isAI = ['llm-agent-v1', 'orchestrator-v1'].includes(d.engine);
  if ((isAI || d.requested_model) && d.analysis_policy !== 'telemetry-only-v1') {
    card.append(el('h3', 'Historical review · superseded analysis policy'), el('p', 'This review used an earlier policy that could include simulator metadata. Run a new telemetry-only investigation. The original audit record is preserved.', 'report-warning'), rawDetails(entry, 'Historical audit record'));
    return card;
  }
  card.append(el('div', isAI ? 'AI ASSESSMENT' : 'RULE-BASED REVIEW', 'eyebrow'), el('h3', assessmentLabel(d.assessment)));
  card.append(el('p', `${dateLabel(entry.timestamp)} · ${d.model || 'No language model used'}`, 'review-meta'));
  if (d.agent_status === 'failed') card.append(el('div', 'The AI response could not be validated. The rule-based review is shown below.', 'report-warning'));
  if (d.disagreement) card.append(el('p', 'Specialists disagreed. The final assessment remains inconclusive.', 'report-warning'));
  reportSection(card, 'AI interpretation · verify against source records', [d.rationale]);
  card.append(facts(entry.incident));
  reportSection(card, 'Why this was flagged', [ruleMeaning(entry.incident.alerts[0])]);
  if (d.observed_summary) reportSection(card, 'Verified observations', [d.observed_summary]);
  if (d.agent_status === 'partial') card.append(el('p', 'One or more AI stages failed validation. The available interpretation is partial; review the stage results.', 'report-warning'));
  const context = d.context_summary;
  if (context) {
    const coverage = `Server retrieved ${context.examined_events} source/context records${context.model_evidence_count != null ? `; AI received ${context.model_evidence_count} selected records` : ''}${context.available_events != null ? ` out of ${context.available_events} matching host events` : ''}${context.partial ? ' (bounded sample, not the full host history)' : ''}.`;
    reportSection(card, 'Evidence checked', [coverage, ...(d.evidence_ids || []).map(id => evidenceLabel(entry, id))]);
  } else if (isAI) card.append(el('p', 'Earlier review: open the audit record for its inputs, or run a new investigation for the structured source-log view.', 'muted'));
  reportSection(card, 'Still needs verification', d.missing_evidence);
  reportSection(card, 'What to do next', d.recommended_checks?.length ? d.recommended_checks : d.response?.suggested_checks);
  if (d.workflow) {
    const steps = el('details', undefined, 'report-agent-details');
    steps.append(el('summary', 'Agent execution details'), workflow(d.workflow)); card.append(steps);
  }
  card.append(el('p', `Saved review #${entry.seq} · No response action taken.`, 'muted'));
  const link = el('a', 'Open source logs in Kibana ↗', 'source-link'); link.href = '/kibana'; link.target = '_blank'; link.rel = 'noopener'; card.append(link, rawDetails(entry));
  return card;
}
async function refresh() {
  const start = new Date($('start').value); const end = new Date($('end').value);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start >= end) throw new Error('Choose a valid time window: From must be earlier than To.');
  const scope = { start: start.toISOString(), end: end.toISOString(), size: 5000, window_minutes: 30 };
  notice('Querying alerts and correlating evidence…');
  const [result, agent, alerts, operations, jobList, rules] = await Promise.all([api('/tools/incidents/correlate', scope), api('/tools/agent/status'), api('/tools/alerts', { size: 20, start: scope.start, end: scope.end }), api('/tools/operations', scope), api('/tools/investigations'), api('/tools/rules')]);
  state.rules = new Map(rules.rules.map(rule => [rule.id, rule]));
  $('run-rules').textContent = rules.management === 'elastic_security' ? 'Sync SIEM alerts' : 'Run detection rules';
  renderOperations(operations, result.incidents); renderJobs(jobList.jobs);
  renderRulePack(rules, result.incidents, result.coverage.partial);
  state.scope = scope; state.incidents = result.incidents; state.agent = agent;
  $('alert-count').textContent = result.coverage.matched_alerts.toLocaleString();
  $('incident-count').textContent = result.incident_count.toLocaleString();
  const severityCounts = result.severity_counts || {};
  $('high-count').textContent = (result.coverage.partial ? '≥ ' : '') + ((severityCounts.high || 0) + (severityCounts.critical || 0));
  state.alerts = state.incidents.flatMap(incident => incident.alerts.map(alert => ({alert, incident})));
  renderAlertQueue();
  $('agent-state').textContent = agent.configured ? 'Configured' : 'Not configured';
  $('agent-model').textContent = agent.model || 'Set an OpenAI-compatible provider';
  document.querySelector('.system').classList.add('connected'); $('connection').textContent = 'Gateway connected';
  $('alerts').replaceChildren();
  if (!alerts.hits.length) $('alerts').append(el('p', 'No stored alerts. Ingest telemetry and run your detection rules.', 'empty'));
  for (const alert of alerts.hits) {
    const item = el('article', undefined, 'alert-item'); const content = el('div');
    const selected = state.alerts.find(row => row.alert.rule.id === alert.rule?.id && row.alert.source_event.id === alert.source_event?.id && row.alert.source_event.index === alert.source_event?.index);
    const title = el(selected ? 'button' : 'p', ruleName(alert.rule?.name) || 'Unnamed alert', selected ? 'entity-button' : undefined);
    if (selected) { title.type='button'; title.addEventListener('click',() => openAlert(selected)); }
    content.append(title, el('small', `${priority(alert.kibana?.alert?.severity)} · ${alert.host?.name || alert.host?.hostname || 'Unknown host'} · ${dateLabel(alert.source_event?.timestamp || alert['@timestamp'])}`));
    item.append(badge(alert.kibana?.alert?.severity), content); $('alerts').append(item);
  }
  notice(result.coverage.partial ? 'Results exceed the query budget or include a shard failure. Narrow the window before triage.' : `Loaded ${result.incident_count} incidents from ${result.coverage.examined_alerts} alerts. Synthetic and unknown provenance stay separate.`, result.coverage.partial);
}
$('scope-form').addEventListener('submit', event => { event.preventDefault(); work(refresh); });
$('run-rules').addEventListener('click', () => work(async () => {
  notice('Running configured detection rules…');
  const result = await api('/tools/rules/run', { size: 100, create_alerts: true });
  const created = result.results.reduce((sum, row) => sum + row.alerts_created, 0);
  await refresh(); notice(result.engine === 'elastic_security' ? `Synced native SIEM alerts. Detection runs on the schedule configured in Elastic Security; edit rules there.` : `Detection complete: ${result.rules_evaluated} rules evaluated, ${created} alerts created. Repeated matches preserve the existing alert.`);
}));
function workflow(events) {
  const rail = el('div', undefined, 'workflow');
  const latest = new Map(); for (const event of events) latest.set(event.stage, event);
  for (const event of latest.values()) {
    const row = el('div', undefined, `stage ${event.status}`);
    row.append(el('strong', event.stage), el('span', `${event.kind === 'llm' ? 'LLM' : 'Server'} · ${event.status}${event.duration_ms != null ? ' · ' + (event.duration_ms / 1000).toFixed(1) + 's' : ''}`));
    if (event.failure_message) row.append(el('p', event.failure_message, 'report-warning'));
    if (event.result) { const details = el('details'); details.append(el('summary', assessmentLabel(event.result.assessment)), el('p', event.result.summary)); row.append(details); }
    rail.append(row);
  }
  return rail;
}
function renderOperations(data, incidents) {
  $('log-count').textContent = data.telemetry.count.toLocaleString() + ' events';
  $('log-status').textContent = `Last source event: ${data.telemetry.last_event?.value_as_string ? dateLabel(data.telemetry.last_event.value_as_string) : 'None in scope'} · Bars: 5 minute event counts`;
  const chart = $('event-chart'); chart.replaceChildren();
  const buckets = (data.telemetry.timeline?.buckets || []).slice(-36); const max = Math.max(1, ...buckets.map(b => b.doc_count));
  for (const bucket of buckets) { const bar = el('span', undefined, `bar level-${Math.max(1, Math.ceil(bucket.doc_count / max * 10))}`); bar.title = `${dateLabel(bucket.key)} · ${bucket.doc_count} events`; chart.append(bar); }
  $('techniques').replaceChildren(); const counts = {};
  for (const incident of incidents) for (const alert of incident.alerts) if (alert.technique?.id) counts[alert.technique.id] = (counts[alert.technique.id] || 0) + 1;
  for (const [id, count] of Object.entries(counts)) $('techniques').append(el('span', `${id} · ${count} alerts`, 'pill'));
  const schedule = data.schedule;
  $('schedule-state').textContent = schedule ? `Every ${schedule.interval_minutes} min` : 'Status unavailable';
  $('schedule-note').textContent = schedule ? `${schedule.last_batch_observed}/${schedule.last_batch_cases} tests observed in the last batch. Next scheduled: ${dateLabel(schedule.next_run)}.` : 'No runner snapshot received.';
  if (schedule) $('schedule-note').append(el('small', ` Snapshot: ${dateLabel(schedule.updated_at)}. Next time may be stale if the guest stops.`, 'muted'));
  const detector = data.detector;
  $('detection-status').textContent = detector.last_error ? `Detection sync error: ${detector.last_error}` : detector.engine === 'elastic_security' ? `Rules execute in Elastic Security · Last portal sync: ${detector.last_success ? dateLabel(detector.last_success) : 'Waiting'} · ${detector.alerts_created ?? 0} new alerts projected` : `Detector ${detector.enabled ? 'enabled' : 'disabled'} · Last success: ${detector.last_success ? dateLabel(detector.last_success) : 'Waiting'} · ${detector.alerts_created ?? 0} new alerts on last scan`;
  $('atomic-runs').replaceChildren();
  for (const run of data.runs.slice(0, 8)) { const row = el('div', undefined, 'run-row'); row.append(el('strong', run.test_name || run.technique), el('small', `${run.technique} · ${dateLabel(run.start)} · ${run.status}`)); $('atomic-runs').append(row); }
}
function renderRulePack(catalog, incidents, partial) {
  const rules = catalog.rules.filter(rule => rule.provenance?.pack === 'aisoc-windows-v1');
  $('rule-pack-state').textContent = `${rules.length} rules in pack / ${catalog.enabled_count ?? catalog.count} enabled · ${catalog.management === 'elastic_security' ? 'Managed in SIEM' : 'Bootstrap mode'}`;
  $('rule-cards').replaceChildren();
  for (const rule of rules) {
    const count = incidents.reduce((total, incident) => total + incident.alerts.filter(a => a.rule.id === rule.id).length, 0);
    const card = el('article', undefined, 'rule-card');
    card.append(badge(rule.severity), el('p', rule.enabled === false ? 'Disabled in SIEM' : 'Enabled', 'muted'));
    const heading = el('h3');
    if (rule.siem?.url) { const title = el('a', ruleName(rule.name), 'rule-title-link'); title.href = rule.siem.url; title.target = '_blank'; title.rel = 'noopener'; heading.append(title); }
    else heading.textContent = ruleName(rule.name);
    card.append(heading, el('p', `${rule.mitre.technique_id || 'Unmapped'} · ${count} alert${count === 1 ? '' : 's'}${partial ? ' in bounded results' : ' in scope'}`));
    if (rule.siem?.edit_url) { const link = el('a', 'Edit in SIEM ↗', 'source-link'); link.href = rule.siem.edit_url; link.target = '_blank'; link.rel = 'noopener'; card.append(link); }
    $('rule-cards').append(card);
  }
}
const severityRank = {critical:4, high:3, medium:2, low:1, unknown:0};
const priority = value => ({critical:'P1',high:'P2',medium:'P3',low:'P4'})[value] || '—';
function renderAlertQueue() {
  const severity = $('alert-severity').value;
  const query = $('alert-search').value.trim().toLowerCase();
  const rows = state.alerts.filter(({alert, incident}) =>
    (severity === 'all' || (severity === 'high-critical' ? ['high','critical'].includes(alert.severity) : alert.severity === severity)) &&
    (!query || [alert.rule.name, hostName(incident), alert.observed?.process_name, alert.technique?.id].join(' ').toLowerCase().includes(query))
  ).sort((a,b) => (severityRank[b.alert.severity] || 0) - (severityRank[a.alert.severity] || 0) || b.alert.source_event.timestamp.localeCompare(a.alert.source_event.timestamp));
  const pages = Math.max(1, Math.ceil(rows.length / 50));
  state.alertPage = Math.min(state.alertPage, pages - 1);
  const body = $('alert-queue-body'); body.replaceChildren();
  for (const row of rows.slice(state.alertPage * 50, (state.alertPage + 1) * 50)) {
    const {alert, incident} = row; const tr = el('tr');
    tr.append(el('td', priority(alert.severity), `priority-${alert.severity}`));
    const title = el('td'); const button = el('button', ruleName(alert.rule.name) || 'Unnamed alert', 'entity-button alert-name-button');
    button.type = 'button'; button.addEventListener('click', () => openAlert(row));
    title.append(button, el('small', `${alert.technique?.id || 'Unmapped'} · ${alert.observed?.process_name || alert.observed?.task_name || 'Endpoint event'}`, 'row-id'));
    const ai = el('td'); ai.append(analysisButton(row)); tr.append(title, ai); const sev = el('td'); sev.append(badge(alert.severity)); tr.append(sev, el('td', String(alert.risk_score ?? '—')), el('td', hostName(incident)), el('td', dateLabel(alert.source_event.timestamp)));
    const native = el('td'); const url = alert.siem?.rule_url || state.rules.get(alert.rule.id)?.siem?.url;
    if (url) { const link = el('a', 'Rule ↗', 'source-link'); link.href = url; link.target = '_blank'; link.rel = 'noopener'; native.append(link); }
    else native.append(el('span', 'Historical', 'muted'));
    tr.append(native); body.append(tr);
  }
  if (!rows.length) { const td = el('td', 'No alerts match these filters.', 'empty'); td.colSpan = 8; const tr = el('tr'); tr.append(td); body.append(tr); }
  $('triage-count').textContent = `${rows.length} matching / ${state.alerts.length} loaded alerts`;
  $('alert-page').textContent = `Page ${state.alertPage + 1} of ${pages} · 50 per page`;
  $('alerts-prev').disabled = state.alertPage === 0; $('alerts-next').disabled = state.alertPage >= pages - 1;
}
function openAlert({alert, incident}) {
  $('alert-title').textContent = ruleName(alert.rule.name) || 'Unnamed alert';
  $('alert-meta').textContent = `${priority(alert.severity)} · ${alert.severity.toUpperCase()} · Risk ${alert.risk_score ?? '—'} · ${hostName(incident)} · ${dateLabel(alert.source_event.timestamp)}`;
  const content = $('alert-content'); content.replaceChildren();
  const card = el('article', undefined, 'decision-card report');
  card.append(analysisButton({alert, incident}));
  card.append(el('p', 'Analyze this alert and nearby host logs. Other alerts in its incident group are excluded.', 'muted'));
  card.append(facts({...incident, alerts:[alert], alert_count:1, severity:alert.severity, techniques:alert.technique?.id ? [alert.technique.id] : []}));
  reportSection(card, 'Why this alert fired', [ruleMeaning(alert)]);
  reportSection(card, 'Source evidence', [`${alert.source_event.index} · ${alert.source_event.id}`, `Activity time: ${dateLabel(alert.source_event.timestamp)}`]);
  const current = state.rules.get(alert.rule.id);
  const ruleLink = alert.siem?.rule_url || current?.siem?.url;
  if (ruleLink) {
    const links = el('div', undefined, 'actions');
    for (const [label,url] of [['Open rule in SIEM ↗',ruleLink],['Edit rule in SIEM ↗',current?.siem?.edit_url || ruleLink+'/edit']]) {
      const link = el('a',label,'source-link'); link.href=url; link.target='_blank'; link.rel='noopener'; links.append(link);
    }
    card.append(links);
  }
  card.append(el('p', alert.siem ? `Elastic Security alert · status: ${alert.siem.workflow_status}` : 'Historical gateway alert. The current detection rule is managed in SIEM.', 'muted'));
  card.append(rawDetails(alert,'Alert references & saved fields')); content.append(card);
  if (!$('alert-dialog').open) $('alert-dialog').showModal();
  content.scrollTop=0; $('close-alert').focus();
}
$('close-alert').addEventListener('click',() => $('alert-dialog').close());
for (const id of ['alert-severity','alert-search']) $(id).addEventListener(id === 'alert-search' ? 'input' : 'change',() => { state.alertPage=0; renderAlertQueue(); });
$('alerts-prev').addEventListener('click',() => { state.alertPage--; renderAlertQueue(); });
$('alerts-next').addEventListener('click',() => { state.alertPage++; renderAlertQueue(); });
$('filter-high').addEventListener('click',() => { $('alert-severity').value='high-critical'; $('alert-search').value=''; state.alertPage=0; renderAlertQueue(); $('triage-queue').scrollIntoView({behavior:'smooth'}); });

let activeJobId = null;
const activeStatus = status => ['queued', 'running'].includes(status);
function jobFor(row) {
  return state.jobs.find(job => job.target?.type === 'alert' && job.target.reference?.id === row.alert.reference.id && job.target.reference?.index === row.alert.reference.index);
}
function analysisButton(row) {
  const job = jobFor(row); const pending = state.pending.has(row.alert.reference.id);
  const button = el('button', pending ? 'Queuing…' : job?.result?.seq ? 'View AI report' : job && activeStatus(job.status) ? 'View AI progress' : 'Analyze with AI', 'alert-ai');
  button.type = 'button'; button.disabled = pending || (!job?.result?.seq && !activeStatus(job?.status) && !state.agent?.configured);
  button.title = state.agent?.configured ? 'Analyze only this alert with nearby host evidence' : 'Configure an LLM provider to analyze alerts';
  button.addEventListener('click', async () => {
    if ($('alert-dialog').open) $('alert-dialog').close();
    if (job?.result?.seq) { openReport(job.result); return; }
    if (job && activeStatus(job.status)) { showJob(job); return; }
    await startAnalysis(row);
  });
  return button;
}
async function startAnalysis(row) {
  const id = row.alert.reference.id;
  if (state.pending.has(id)) return;
  state.pending.add(id); renderAlertQueue();
  try {
    const result = await api('/tools/investigations', {...state.scope, incident_id: row.incident.id, alert_id: id});
    const job = await api(`/tools/investigations/${result.job_id}`);
    showJob(job);
    const list = await api('/tools/investigations'); renderJobs(list.jobs);
  } catch (error) { notice(error.message, true); }
  finally { state.pending.delete(id); renderAlertQueue(); }
}
function showJob(job) {
  if (job.result?.seq) { openReport(job.result); return; }
  activeJobId = job.id;
  $('report-title').textContent = ruleName(job.target?.name) || 'AI analysis';
  $('report-meta').textContent = `Single alert · ${job.target?.host || 'Unknown host'} · ${job.status}`;
  const content = $('report-content'); content.replaceChildren();
  content.append(el('p', activeStatus(job.status) ? 'Analyzing the selected alert and nearby host evidence. You can close this window; the investigation will continue.' : `Analysis ${job.status}. No validated report was produced.`, activeStatus(job.status) ? 'muted' : 'report-warning'), workflow(job.events));
  if (!activeStatus(job.status)) {
    const row = state.alerts.find(row => row.alert.reference.id === job.target?.reference?.id && row.alert.reference.index === job.target?.reference?.index);
    if (row) content.append(analysisButton(row));
    content.append(rawDetails(job, 'Execution details'));
  }
  if (!$('report-dialog').open) { $('report-dialog').showModal(); $('close-report').focus(); }
}

let jobsSignature = '';
function renderJobs(jobs) {
  state.jobs = jobs; renderAlertQueue();
  const signature = jobs.map(job => `${job.id}:${job.status}:${job.events.length}:${job.result?.seq || ''}`).join('|') || 'empty';
  if (signature === jobsSignature) return;
  jobsSignature = signature;
  $('jobs').replaceChildren();
  if (!jobs.length) $('jobs').append(el('p', 'Choose Analyze with AI on an alert. Up to 3 model requests plus one shared JSON repair request.', 'muted'));
  for (const job of jobs.slice(0, 5)) {
    const historical = job.result?.decision && job.result.decision.analysis_policy !== 'telemetry-only-v1';
    if (historical) { const row = el('details', undefined, 'older-review'); row.append(el('summary', `Historical run · ${dateLabel(job.created)} · superseded policy`), rawDetails(job, 'Original audit record')); $('jobs').append(row); continue; }
    const card = el('article', undefined, 'job-card'); card.append(el('strong', `${ruleName(job.target?.name) || 'Investigation'} · ${job.status}`), el('small', dateLabel(job.created)), workflow(job.events));
    if (job.result?.seq) {
      const button = el('button', `Open report #${job.result.seq}`, 'secondary');
      button.type = 'button'; button.dataset.reportSeq = job.result.seq;
      button.addEventListener('click', () => openReport(job.result)); card.append(button);
    }
    if (activeStatus(job.status)) { const button = el('button', 'View AI progress', 'secondary'); button.type='button'; button.addEventListener('click', () => showJob(job)); card.append(button); }
    if (job.status === 'interrupted') card.append(el('p', 'Worker restarted during the run. Start a new investigation to retry.', 'report-warning'));
    $('jobs').append(card);
  }
}
function openReport(entry) {
  activeJobId = null;
  const dialog = $('report-dialog');
  // Saved reports have their own view; workspace refresh cannot replace their contents.
  try {
    const card = decisionCard(entry);
    $('report-title').textContent = `Report #${entry.seq}`;
    $('report-meta').textContent = `${entry.incident.analysis_scope?.type === 'alert' ? ruleName(entry.incident.alerts[0].rule.name) + ' · Single alert · ' : ''}${hostName(entry.incident)} · ${dateLabel(entry.timestamp)} · ${entry.decision.agent_status || entry.decision.verdict}`;
    $('report-content').replaceChildren(card);
    const row = entry.incident.analysis_scope?.type === 'alert' && state.alerts.find(row => row.alert.reference.id === entry.incident.alerts[0].reference.id && row.alert.reference.index === entry.incident.alerts[0].reference.index);
    if (row && state.agent?.configured) { const retry = el('button', 'Analyze again', 'secondary'); retry.type='button'; retry.addEventListener('click', () => { retry.disabled=true; startAnalysis(row).finally(() => { retry.disabled=false; }); }); $('report-content').append(retry); }
  } catch (error) {
    $('report-title').textContent = `Report #${entry.seq}`;
    $('report-meta').textContent = 'The structured view could not be rendered.';
    $('report-content').replaceChildren(el('p', 'The saved record is available below.', 'report-warning'), rawDetails(entry, 'Saved report record'));
  }
  if (!dialog.open) dialog.showModal();
  $('report-content').scrollTop = 0;
  $('close-report').focus();
}
$('close-report').addEventListener('click', () => $('report-dialog').close());
$('report-dialog').addEventListener('close', () => { activeJobId = null; });
let polling = false;
async function pollJobs() {
  if (polling || document.hidden) return;
  polling = true;
  try { const result = await api('/tools/investigations'); renderJobs(result.jobs); if (activeJobId) { const id = activeJobId; const job = await api(`/tools/investigations/${id}`); if (activeJobId === id) showJob(job); } }
  catch (_) { /* Explicit refresh reports connection errors. */ }
  finally { polling = false; }
}
work(refresh);
setInterval(pollJobs, 3000);
setInterval(() => { if ($('live').checked && !state.busy && !document.hidden) { $('end').value = localInput(new Date(Date.now() + 60000)); work(refresh); } }, 30000);
