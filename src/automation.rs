//! Server-side background automation.
//!
//! One `tokio::time::interval` ticks at a base cadence (60s by
//! default) and walks a `Vec<Box<dyn Scanner>>`. Each scanner
//! declares its own cadence — heavier scans (e.g. audit-log
//! rotation) can run every Nth tick instead of every tick.
//!
//! This is the home for the things roadmap-v1 calls "Phase 3
//! Workflow automation": dispatch escalation, peer-drop notice,
//! finding-SLA, memory-history-prune, audit-log-rotate. New
//! scanners are added by implementing the trait and pushing into
//! the registry at boot — no edits to the loop itself.
//!
//! Why a shared tick (per operator dispatch 1779031875): one
//! `interval` is cheaper than N intervals; one log line per tick
//! is easier to grep than N; and scanners that need to see each
//! other's state (e.g. peer-drop reading from the dispatch table
//! before notifying) share the same `tracing` span.

use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;
use crate::Message;
use dashmap::{DashMap, DashSet};
use tokio::sync::broadcast;

/// Context handed to every scanner on each tick. Currently just the
/// store, but designed to accept additional handles (broadcast
/// senders for synthetic messages, peer presence map, config) as
/// scanners need them. Adding a field here is a no-cost change for
/// scanners that don't touch it.
#[derive(Clone)]
pub struct AutomationCtx {
    pub store: Option<Store>,
    /// Configured peer-status-history TTL in seconds. Mirrors
    /// `Config::peer_history_ttl`. Stored as secs so scanners can
    /// compare directly against unix timestamps without re-deriving.
    pub peer_history_ttl_secs: u64,
    /// Dispatch escalation threshold — open dispatches older than
    /// this (sent_at < now - secs) get the auto-ping. Per
    /// roadmap-v1 F5 default = 15 minutes (900s).
    pub dispatch_sla_secs: u64,
    /// Set of dispatch `message_id`s the escalation scanner has
    /// already pinged. Prevents re-pinging on every tick while the
    /// dispatch stays unacked. Cleared when the dispatch acks (the
    /// row leaves the open set so the dedup is naturally bounded
    /// by open-dispatch count).
    pub escalated: Arc<DashSet<String>>,
    /// Shared handle to the server's per-channel broadcast senders.
    /// Lets scanners publish synthetic messages (escalation auto-
    /// ping, `__peer_left__` event) into the same channels peers
    /// are already subscribed to via `/stream/{channel}`. Each
    /// broadcast::Sender has its own bounded ring buffer so a slow
    /// subscriber doesn't pressure the scanner — lagged events
    /// surface in the existing `sse_lag_drops` counter (Group D6).
    pub senders: Arc<DashMap<String, broadcast::Sender<Message>>>,
    /// Snapshot of the server's known peers — cloned into the ctx
    /// on each tick so the peer-drop notifier can detect transitions
    /// without racing on the live map. The closure pushed at
    /// `spawn_loop` time decides the snapshot policy (full vs only
    /// names + last_seen); for now we surface last_seen alongside
    /// the peer's last-known channel so the notifier can post into
    /// the right thread.
    pub peers_snapshot:
        Arc<dyn Fn() -> Vec<(String, u64, String)> + Send + Sync>,
    /// Routing-engine emit callback (F17 Phase 3). Scanners fire
    /// triggers through this — argument shape mirrors
    /// `server::fire_routing_actions`: trigger_type + serde payload.
    /// `None` when persistence is disabled (no rules table → no
    /// routing) so the scanners are a no-op without an extra Option
    /// check at every emit site.
    pub routing_emit:
        Option<Arc<dyn Fn(&str, serde_json::Value) + Send + Sync>>,
}

/// One unit of background work. Implementations should be cheap on
/// "no-op" ticks: the loop runs forever, so a scanner that hits the
/// DB even when nothing's due is a constant overhead. Prefer indexed
/// `WHERE` filters that return zero rows fast.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    /// Short name for tracing spans + metrics counters. Used as the
    /// `scanner = ?` field in log lines.
    fn name(&self) -> &'static str;

    /// Run-every-Nth-tick selector. Returning 1 = run every tick
    /// (default); 5 = run every fifth tick at the base cadence; etc.
    /// Lets a heavy scanner share the same `interval` without paying
    /// the cost every minute. Default 1.
    fn every(&self) -> u64 {
        1
    }

    /// Do the work. The driver swallows errors (logs as warn) so one
    /// failing scanner can't stop the loop. Return early on no-op.
    async fn tick(&self, ctx: &AutomationCtx);
}

/// Drive every scanner in `registry` at the given base cadence.
/// Spawns a dedicated tokio task; returns the `JoinHandle` so
/// `main()` can abort it on shutdown (today main is forever-blocking,
/// so the handle is mostly for tests).
pub fn spawn_loop(
    base: Duration,
    ctx: AutomationCtx,
    registry: Vec<Arc<dyn Scanner>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(base);
        // The first tick fires immediately; skip it so the loop's
        // first real run lines up with `base` after startup. Stops
        // a flurry of "nothing to do" log lines at boot.
        ticker.tick().await;
        let mut tick_count: u64 = 0;
        loop {
            ticker.tick().await;
            tick_count = tick_count.wrapping_add(1);
            for s in &registry {
                let every = s.every().max(1);
                if tick_count % every != 0 {
                    continue;
                }
                // Per-scanner span so log lines self-attribute even
                // when scanners share a tokio task.
                let span = tracing::info_span!("automation_tick", scanner = s.name(), tick_count);
                let _enter = span.enter();
                // We awaited inside a span — fine because the body
                // doesn't yield (it's an `async fn`; the span guard
                // exits when the future completes here). If a
                // scanner ever awaits long-running IO, refactor to
                // `instrument`.
                s.tick(&ctx).await;
            }
        }
    })
}

// ── Concrete scanners ────────────────────────────────────────────

/// No-op scanner used for boot smoke + as a placeholder until the
/// real dispatch / peer-drop / SLA scanners are wired. Logs once
/// per tick at `debug` level so a developer can confirm the loop is
/// alive without flooding production logs.
pub struct HeartbeatScanner;

#[async_trait::async_trait]
impl Scanner for HeartbeatScanner {
    fn name(&self) -> &'static str {
        "heartbeat"
    }
    fn every(&self) -> u64 {
        5 // every 5 minutes at the default 60s base cadence
    }
    async fn tick(&self, _ctx: &AutomationCtx) {
        tracing::debug!("automation loop alive");
    }
}

/// Find open dispatches older than `ctx.dispatch_sla_secs` and emit
/// one `tracing::warn!` per newly-stale one. Designed to be cheap on
/// no-op ticks (partial index `dispatches_pending WHERE ack_at = 0`).
///
/// Auto-pinging via a synthetic chat message is the desired behaviour
/// per roadmap-v1 F5 ("ops auto-ping without ops in the loop"), but
/// requires a handle to the broadcast `sender` map. That hookup
/// crosses module boundaries; for this initial drop the scanner logs
/// only — wiring the synthetic-message path is the next sub-task
/// (B3). The dedup `escalated` set is in place so adding the
/// publish later does not double-ping rows already warned about.
pub struct DispatchEscalationScanner;

#[async_trait::async_trait]
impl Scanner for DispatchEscalationScanner {
    fn name(&self) -> &'static str {
        "dispatch_escalation"
    }
    fn every(&self) -> u64 {
        1 // every base tick (60s) — escalation latency caps at 60s
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(store) = &ctx.store else { return };
        let cutoff = crate::now_secs().saturating_sub(ctx.dispatch_sla_secs);
        // Bound the scan so a backlog of thousands doesn't stall the
        // loop — escalation is best-effort, the head of the queue is
        // what matters; later rows show up next tick.
        let rows = match store.open_dispatches_older_than(cutoff, 100) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "dispatch escalation read failed");
                return;
            }
        };
        for d in rows {
            if !ctx.escalated.insert(d.message_id.clone()) {
                continue; // already pinged this dispatch
            }
            let age = crate::now_secs().saturating_sub(d.sent_at);
            tracing::warn!(
                message_id = %d.message_id,
                from = %d.from,
                to = %d.to,
                channel = %d.channel,
                age_secs = age,
                sla = ctx.dispatch_sla_secs,
                "dispatch unacked past sla"
            );
            publish_system(
                ctx,
                &d.channel,
                &d.to.split(',').map(str::to_string).collect::<Vec<_>>(),
                format!(
                    "[bridge-auto] dispatch {} from {} aging {}m without ack (SLA {}m). Status?",
                    d.message_id,
                    d.from,
                    age / 60,
                    ctx.dispatch_sla_secs / 60
                ),
            );
            // F17 Phase 3 — also emit `dispatch_stale` through the
            // routing engine so operator-authored rules (e.g.
            // auto_escalate to a specific role, auto_message with a
            // templated body) can fire on the same event the SLA
            // auto-ping above covers. Payload mirrors the
            // `placeholders_for("dispatch_stale")` whitelist.
            if let Some(emit) = &ctx.routing_emit {
                let payload = serde_json::json!({
                    "message_id": d.message_id,
                    "from":       d.from,
                    "to":         d.to,
                    "channel":    d.channel,
                    "age_secs":   age,
                });
                emit("dispatch_stale", payload);
            }
        }
    }
}

/// PeerRecoveryScanner (F23) — when a peer drops off (last_seen
/// lag > threshold, default 5min) AND has pending dispatches AND
/// has a configured recovery routine URL, POST to that URL with
/// the dispatch context. De-dup via `last_fired_at` so a single
/// drop episode triggers one POST per cooldown window (15 min).
pub struct PeerRecoveryScanner {
    /// Fires the POST. Wired from main() with a state-clone capture
    /// so the scanner stays decoupled from server.rs internals.
    /// The closure is responsible for SSRF guards on the URL.
    pub fire: Arc<dyn Fn(&str, &str, &serde_json::Value) + Send + Sync>,
}

#[async_trait::async_trait]
impl Scanner for PeerRecoveryScanner {
    fn name(&self) -> &'static str {
        "peer_recovery"
    }
    fn every(&self) -> u64 {
        1
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(store) = &ctx.store else { return };
        let configs = match store.list_peer_recovery_configs() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "peer recovery config read failed");
                return;
            }
        };
        if configs.is_empty() {
            return;
        }
        let now = crate::now_secs();
        const DROP_THRESHOLD_SECS: u64 = 5 * 60;
        const FIRE_COOLDOWN_SECS: u64 = 15 * 60;
        let peers = (ctx.peers_snapshot)();
        // Map peer name → idle_secs for quick lookup.
        let peer_idles: std::collections::HashMap<String, u64> = peers
            .iter()
            .map(|(n, last_seen, _ch)| (n.clone(), now.saturating_sub(*last_seen)))
            .collect();
        for cfg in configs {
            let idle = peer_idles.get(&cfg.peer).copied().unwrap_or(u64::MAX);
            if idle < DROP_THRESHOLD_SECS {
                continue;
            }
            if now.saturating_sub(cfg.last_fired_at) < FIRE_COOLDOWN_SECS {
                continue;
            }
            let pending = store
                .open_dispatches_for_peer(&cfg.peer, 50)
                .unwrap_or_default();
            if pending.is_empty() {
                continue;
            }
            let payload = serde_json::json!({
                "peer": cfg.peer,
                "idle_secs": idle,
                "dispatches": pending.iter().map(|d| serde_json::json!({
                    "message_id": d.message_id,
                    "from": d.from,
                    "to": d.to,
                    "channel": d.channel,
                    "sent_at": d.sent_at,
                })).collect::<Vec<_>>(),
            });
            tracing::info!(peer = %cfg.peer, url = %cfg.routine_url,
                "peer_recovery: firing routine webhook");
            (self.fire)(&cfg.peer, &cfg.routine_url, &payload);
            let _ = store.mark_recovery_fired(&cfg.peer, now);
        }
    }
}

/// GoalScanner (F20) — every base tick, walks pending goals,
/// recomputes current_value from the requested metric, fires
/// `goal_achieved` routing trigger on the pending→met transition
/// edge (not every tick at met). Metrics queried via the
/// `metrics_provider` closure threaded into the ctx so the
/// scanner stays decoupled from AppState.
pub struct GoalScanner {
    /// Closure returning the live metric value for a given metric
    /// name. Wired from server.rs::main with a state-clone capture.
    pub metrics_provider: Arc<dyn Fn(&str) -> Option<i64> + Send + Sync>,
}

#[async_trait::async_trait]
impl Scanner for GoalScanner {
    fn name(&self) -> &'static str {
        "goal_scanner"
    }
    fn every(&self) -> u64 {
        1
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(store) = &ctx.store else { return };
        let Some(emit) = &ctx.routing_emit else { return };
        let goals = match store.list_goals() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "goal scan read failed");
                return;
            }
        };
        let now = crate::now_secs();
        for g in goals {
            if g.status != "pending" {
                continue;
            }
            let Some(new_current) = (self.metrics_provider)(&g.target_metric) else {
                tracing::debug!(metric = %g.target_metric, "no provider for goal metric");
                continue;
            };
            let (prior, new_status) = match store.update_goal_progress(
                &g.id, new_current, &g.comparator, g.target_value,
                g.deadline, now,
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, goal_id = %g.id, "goal progress update failed");
                    continue;
                }
            };
            if prior == "pending" && new_status == "met" {
                let payload = serde_json::json!({
                    "goal_id":       g.id,
                    "name":          g.name,
                    "target_metric": g.target_metric,
                    "target_value":  g.target_value,
                    "current_value": new_current,
                    "channel":       g.channel,
                });
                emit("goal_achieved", payload);
            }
        }
    }
}

/// TaskReadyScanner (F29) — emits `task_ready` triggers when a
/// task's `depends_on` chain transitions from "any unmet" to "all
/// satisfied". Dedup via per-scanner DashSet so a single ready
/// event fires once per task; cleared when the task moves past
/// `todo` (it's been picked up by routing or by a peer).
pub struct TaskReadyScanner {
    pub seen: Arc<DashSet<String>>,
}

impl Default for TaskReadyScanner {
    fn default() -> Self {
        Self {
            seen: Arc::new(DashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl Scanner for TaskReadyScanner {
    fn name(&self) -> &'static str {
        "task_ready"
    }
    fn every(&self) -> u64 {
        1
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(store) = &ctx.store else { return };
        let Some(emit) = &ctx.routing_emit else { return };
        let ready = match store.tasks_ready_to_unblock() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "task_ready scan failed");
                return;
            }
        };
        for (task, _unmet) in ready {
            if !self.seen.insert(task.id.clone()) {
                continue;
            }
            let payload = serde_json::json!({
                "task_id": task.id,
                "title":   task.title,
                "channel": task.channel,
                "owner":   task.owner,
                "from":    task.from,
            });
            emit("task_ready", payload);
        }
    }
}

/// PeerIdleScanner (F17 Phase 3) — emits `peer_idle` triggers
/// through the routing engine when a peer's last_seen lag crosses
/// the configured threshold. Distinct from `PeerDropScanner` which
/// fires a synthetic chat message at >120s; this scanner fires the
/// routing engine path so operator rules can decide what to do
/// (auto_escalate vs auto_message vs auto_assign a wake-task to
/// somebody else).
///
/// Default threshold is 5 min (300s). Dedup via per-scanner
/// `seen` set so a single idle episode only fires once; cleared
/// when the peer reconnects (last_seen refreshes).
pub struct PeerIdleScanner {
    pub seen: Arc<DashSet<String>>,
    pub threshold_secs: u64,
}

impl Default for PeerIdleScanner {
    fn default() -> Self {
        Self {
            seen: Arc::new(DashSet::new()),
            threshold_secs: 5 * 60,
        }
    }
}

#[async_trait::async_trait]
impl Scanner for PeerIdleScanner {
    fn name(&self) -> &'static str {
        "peer_idle"
    }
    fn every(&self) -> u64 {
        1
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(emit) = &ctx.routing_emit else { return };
        let now = crate::now_secs();
        let peers = (ctx.peers_snapshot)();
        for (name, last_seen, channel) in &peers {
            let lag = now.saturating_sub(*last_seen);
            if lag < self.threshold_secs {
                // Recovered: clear the dedup so a re-idle re-fires.
                self.seen.remove(name);
                continue;
            }
            if !self.seen.insert(name.clone()) {
                continue;
            }
            let payload = serde_json::json!({
                "peer":      name,
                "idle_secs": lag,
                "channel":   channel,
            });
            emit("peer_idle", payload);
        }
    }
}

/// AutoBatchScanner (F17 Phase 3) — flushes the deferred-window
/// accumulator owned by the dispatcher. The accumulator collects
/// triggered payloads keyed by (rule_id, batch_key) where
/// `batch_key` is derived from `action_params.batch_by` (a field
/// name in the payload). At each flush tick, accumulator entries
/// older than `window_secs` get rendered into a single batched
/// message and emitted via `publish_system` to the rule's channel.
///
/// Implementation: the scanner doesn't own the accumulator — it
/// reads + drains via a callback that the dispatcher provides. This
/// keeps the accumulator's identity-per-server-state (DashMap in
/// `AppState`) and avoids splitting the state across modules.
pub struct AutoBatchScanner {
    pub flush: Arc<dyn Fn(&AutomationCtx) + Send + Sync>,
}

#[async_trait::async_trait]
impl Scanner for AutoBatchScanner {
    fn name(&self) -> &'static str {
        "auto_batch_flush"
    }
    fn every(&self) -> u64 {
        1 // every base tick (60s) — batch window resolution = 60s
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        (self.flush)(ctx);
    }
}

/// Push a synthetic system message into the broadcast stream for a
/// channel. Best-effort: if the channel has no live SSE subscriber,
/// the `send` returns `Err(SendError(_))` because the broadcast
/// channel only retains values while a receiver exists — fine for
/// scanners, the message would have been instantly dropped anyway.
/// Author is the literal string `bridge-auto` so peers can filter
/// on `from` to suppress system messages from their UI if desired.
fn publish_system(ctx: &AutomationCtx, channel: &str, to: &[String], content: String) {
    let sender = match ctx.senders.get(channel) {
        Some(s) => s.value().clone(),
        None => return,
    };
    let msg = Message {
        id: uuid::Uuid::new_v4().to_string(),
        channel: channel.to_string(),
        from: "bridge-auto".into(),
        content,
        timestamp: crate::now_secs(),
        to: to.to_vec(),
        thread_id: String::new(),
        pinned: false,
    };
    let _ = sender.send(msg);
}

/// Detect peers whose `last_seen` has crossed the configured TTL
/// and emit a one-time `__peer_dropped__`-tagged synthetic message
/// to their last-known channel. Dedups via the same `escalated`
/// set as the dispatch scanner (separate key space prefix to avoid
/// collisions). When a peer reconnects (last_seen refreshed past
/// the threshold) the dedup key is dropped so a subsequent disconnect
/// re-pings.
pub struct PeerDropScanner {
    /// Per-peer "we already pinged for this drop episode" set. Lives
    /// in the scanner (not ctx) because the dedup key set is owned
    /// by the scanner — not shared with dispatch.
    pub seen: Arc<DashSet<String>>,
}

#[async_trait::async_trait]
impl Scanner for PeerDropScanner {
    fn name(&self) -> &'static str {
        "peer_drop"
    }
    fn every(&self) -> u64 {
        1
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let now = crate::now_secs();
        let peers = (ctx.peers_snapshot)();
        // First pass: re-arm — any peer whose last_seen is RECENT
        // gets removed from the seen set so a re-drop will fire.
        for (name, last_seen, _channel) in &peers {
            if now.saturating_sub(*last_seen) < ctx.peer_history_ttl_secs.min(120) {
                self.seen.remove(name);
            }
        }
        // Second pass: any peer past TTL that we haven't pinged
        // for in this episode → fire.
        for (name, last_seen, channel) in &peers {
            let lag = now.saturating_sub(*last_seen);
            if lag <= 120 {
                continue;
            }
            if !self.seen.insert(name.clone()) {
                continue;
            }
            tracing::warn!(peer = %name, lag_secs = lag, "peer dropped past ttl");
            if !channel.is_empty() {
                publish_system(
                    ctx,
                    channel,
                    &[],
                    format!(
                        "[bridge-auto] peer `{}` dropped (no heartbeat for {}m). __peer_dropped__",
                        name,
                        lag / 60
                    ),
                );
            }
        }
    }
}

/// Prune `peer_status_history` rows older than the configured TTL.
/// Runs hourly at the default base cadence (60s * 60 = 60 min).
/// Cheap when there's nothing to delete — the indexed `recorded_at`
/// range makes the WHERE short-circuit fast.
pub struct PeerHistoryPruneScanner;

#[async_trait::async_trait]
impl Scanner for PeerHistoryPruneScanner {
    fn name(&self) -> &'static str {
        "peer_history_prune"
    }
    fn every(&self) -> u64 {
        60 // hourly at 60s base
    }
    async fn tick(&self, ctx: &AutomationCtx) {
        let Some(store) = &ctx.store else { return };
        let cutoff = crate::now_secs().saturating_sub(ctx.peer_history_ttl_secs);
        match store.prune_peer_history(cutoff) {
            Ok(n) if n > 0 => tracing::info!(deleted = n, cutoff, "peer history pruned"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "peer history prune failed"),
        }
    }
}
