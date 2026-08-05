use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::types::{CredentialMap, RelayTunnelState};

struct AdmissionControl {
    credentials: CredentialMap,
    state: Weak<RelayTunnelState>,
    runtime: tokio::runtime::Handle,
}

static CONTROL: OnceLock<Mutex<Vec<AdmissionControl>>> = OnceLock::new();

fn control() -> &'static Mutex<Vec<AdmissionControl>> {
    CONTROL.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Debug, Clone)]
pub struct PendingAdmissionInfo {
    pub client_id: u32,
    pub sas: String,
    pub label: String,
    pub read_only: bool,
    pub claimed_name: Option<String>,
    pub contested: bool,
    pub seconds_remaining: u64,
}

pub fn register_tunnel(state: &Arc<RelayTunnelState>) {
    let runtime = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(_) => return,
    };
    let credentials = state.credentials.clone();
    let mut guard = control().lock().unwrap();
    if let Some(existing) = guard
        .iter_mut()
        .find(|c| Arc::ptr_eq(&c.credentials, &credentials))
    {
        existing.state = Arc::downgrade(state);
        existing.runtime = runtime;
        return;
    }
    guard.push(AdmissionControl {
        credentials,
        state: Arc::downgrade(state),
        runtime,
    });
}

pub fn clear() {
    control().lock().unwrap().clear();
}

pub fn list() -> Vec<PendingAdmissionInfo> {
    let guard = control().lock().unwrap();
    let mut out = Vec::new();
    for ctl in guard.iter() {
        let Some(state) = ctl.state.upgrade() else {
            continue;
        };
        let map = state.pending_admissions.lock().unwrap();
        for p in map.values() {
            let contested = map.values().filter(|o| o.link_id == p.link_id).count() > 1;
            out.push(PendingAdmissionInfo {
                client_id: p.client_id,
                sas: p.sas.clone(),
                label: p.label.clone(),
                read_only: p.access.is_read_only(),
                claimed_name: p.claimed_name.clone(),
                contested,
                seconds_remaining: p.seconds_remaining(),
            });
        }
    }
    out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    out
}

pub fn resolve(client_id: u32, admit: bool, code_confirmed: bool) -> Result<(), String> {
    let guard = control().lock().unwrap();
    for ctl in guard.iter() {
        let Some(state) = ctl.state.upgrade() else {
            continue;
        };
        if !state
            .pending_admissions
            .lock()
            .unwrap()
            .contains_key(&client_id)
        {
            continue;
        }
        let state = state.clone();
        ctl.runtime.spawn(async move {
            if admit {
                let outcome = crate::multiplexer::admit_pending(&state, client_id, code_confirmed);
                log::info!(
                    "admission resolve: admit client_id={} -> {:?}",
                    client_id, outcome
                );
            } else {
                crate::multiplexer::reject_pending(&state, client_id, "rejected by owner");
            }
        });
        return Ok(());
    }
    Err(format!("no pending admission for client_id={}", client_id))
}
