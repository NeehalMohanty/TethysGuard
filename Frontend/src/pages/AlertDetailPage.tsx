import { useCallback, useEffect, useRef, useState } from "react";
import { useLiveRefresh } from "../live/useLiveRefresh";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Alert, RelatedSecurityEvent } from "../api/types";
import { SeverityBadge } from "../components/Badges";
import { InvestigationPanel } from "../components/InvestigationPanel";
import { ErrorState, LoadingState, EmptyState } from "../components/PageState";
import { formatDate, humanize } from "../utils/format";

export function AlertDetailPage() {
  const { alertId } = useParams();
  const id = Number(alertId);
  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<RelatedSecurityEvent[]>([]);
  const [error, setError] = useState("");
  const requestId = useRef(0);
  const load = useCallback(async (background = false) => {
    const current = ++requestId.current;
    if (!background) setAlert(null);
    setError("");
    if (!Number.isSafeInteger(id) || id < 1) { setError("Invalid alert ID"); return; }
    try {
      const [item, related] = await Promise.all([api.alert(id), api.alertEvents(id)]);
      if (current === requestId.current) { setAlert(item); setEvents(related.events); }
    } catch (reason) {
      if (current === requestId.current) setError(reason instanceof Error ? reason.message : "Unable to load alert");
    }
  }, [id]);
  useEffect(() => {
    const requests = requestId;
    void load();
    return () => { ++requests.current; };
  }, [load]);
  useLiveRefresh(() => load(true));

  if (error && !alert) return <><Link to="/alerts">Back to alerts</Link><ErrorState message={error} /></>;
  if (!alert) return <LoadingState />;
  return <div className="page">
    {error && <p role="alert">Refresh failed: {error}. Your draft is preserved. <button onClick={() => void load(true)}>Retry refresh</button></p>}
    <Link to="/alerts">← Back to alerts</Link>
    <header className="page-header"><div><p className="eyebrow">Investigation · Alert {alert.id}</p><h1>{alert.title}</h1><p>{alert.description}</p></div><SeverityBadge severity={alert.severity} /></header>
    <InvestigationPanel key={alert.id} alert={alert} onUpdate={updated => {
      ++requestId.current; setAlert(updated);
    }} />
    <section className="panel detail-panel"><h2>Detection context</h2><dl className="detail-grid">
      <div><dt>Rule</dt><dd>{alert.rule_id ?? "Legacy"} · {alert.rule_name ?? "Unavailable"}</dd></div>
      <div><dt>Source</dt><dd>{humanize(alert.detection_source)}</dd></div>
      <div><dt>Risk / Confidence</dt><dd>{alert.risk_score ?? "—"} / {alert.confidence ?? "—"}</dd></div>
      <div><dt>Detected</dt><dd>{formatDate(alert.detected_at ?? alert.timestamp)}</dd></div>
      <div><dt>MITRE ATT&CK</dt><dd>{alert.mitre_technique_id ?? "Unmapped"} {alert.mitre_technique_name}</dd></div>
      <div><dt>Tactic</dt><dd>{alert.mitre_tactic ?? "Unavailable"}</dd></div>
    </dl><h3>Evidence at detection</h3><pre>{JSON.stringify(alert.evidence ?? {}, null, 2)}</pre></section>
    <section className="panel"><div className="panel-heading"><h2>Related events</h2><span>{events.length} events</span></div>
      {events.length === 0 ? <EmptyState message="No related events available" /> : <div className="table-wrap"><table><thead><tr><th>Event</th><th>Source / Host</th><th>Relationship</th><th>Observed</th><th>Message</th></tr></thead><tbody>{events.map(event => <tr key={event.id}><td>{humanize(event.event_type)}<small>#{event.id}</small></td><td>{event.source_ip}<small>{event.host ?? event.destination_ip ?? "—"}</small></td><td>{humanize(event.relationship)}</td><td>{formatDate(event.timestamp)}</td><td className="event-message">{event.message ?? "—"}</td></tr>)}</tbody></table></div>}
    </section>
  </div>;
}
