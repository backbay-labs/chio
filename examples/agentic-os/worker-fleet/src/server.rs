use crate::report::{ReportTool, PRICE};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_agent_os_shared::{
    host::{grant, private_directory, request, write_json, Host},
    json, Run, Value,
};
use chio_core::{
    capability::{
        scope::{ChioScope, MonetaryAmount},
        token::CapabilityToken,
    },
    crypto::Keypair,
};
use chio_kernel::BudgetStore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub directory: PathBuf,
    pub input: Value,
    pub workers: BTreeMap<String, String>,
    pub admin: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub operation_id: String,
    pub input: Value,
    pub state: String,
    pub owner: Option<String>,
    pub claim: Option<String>,
    pub outcome: Value,
}
struct Service {
    host: Host,
    cap: CapabilityToken,
    config: Config,
    run: Run,
    jobs: Mutex<Vec<Job>>,
    cancellations: Mutex<BTreeMap<String, Arc<AtomicBool>>>,
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(e: impl ToString) -> (StatusCode, Json<Value>) {
    (StatusCode::CONFLICT, Json(json!({"error":e.to_string()})))
}
fn authenticate(headers: &HeaderMap, key: &str) -> bool {
    let supplied = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    let a = chio_core::sha256_hex(supplied.as_bytes());
    let b = chio_core::sha256_hex(key.as_bytes());
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}
fn worker(headers: &HeaderMap, service: &Service) -> Result<String, (StatusCode, Json<Value>)> {
    service
        .config
        .workers
        .iter()
        .find(|(_, key)| authenticate(headers, key))
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"Worker credential is not valid"})),
            )
        })
}
fn admin(headers: &HeaderMap, service: &Service) -> Result<(), (StatusCode, Json<Value>)> {
    if authenticate(headers, &service.config.admin) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Operator credential is not valid"})),
        ))
    }
}
impl Service {
    fn persist(&self, jobs: &[Job]) -> anyhow::Result<()> {
        write_json(&self.config.directory.join("jobs.json"), &json!(jobs))
    }
    fn accounting(&self) -> anyhow::Result<Value> {
        let usage = self.host.budget.get_usage(&self.cap.id, 0)?;
        let (spent, exposed, calls) = usage
            .map(|u| {
                (
                    u.total_cost_realized_spend,
                    u.total_cost_exposed,
                    u.invocation_count,
                )
            })
            .unwrap_or_default();
        let allowance = self.config.input["allowance"].as_u64().unwrap_or(50);
        Ok(json!({
            "allowance":allowance,
            "spent":spent,
            "reserved":exposed,
            "available":allowance.saturating_sub(spent+exposed),
            "calls":calls,
            "unit":"local demo credits",
            "capability_id":self.cap.id
        }))
    }
}
async fn claim(State(service): State<Arc<Service>>, headers: HeaderMap) -> ApiResult {
    let owner = worker(&headers, &service)?;
    let mut jobs = service.jobs.lock().await;
    let Some(job) = jobs.iter_mut().find(|job| job.state == "queued") else {
        return Ok(Json(json!({"job":null})));
    };
    job.state = "claimed".into();
    job.owner = Some(owner.clone());
    job.claim = Some(uuid::Uuid::new_v4().to_string());
    let result = job.clone();
    service.persist(&jobs).map_err(error)?;
    service
        .run
        .emit(
            "fleet.claimed",
            &owner,
            "Worker claimed a report section",
            json!({"operation_id":result.operation_id,"section":result.input["section"]}),
        )
        .map_err(error)?;
    Ok(Json(json!({"job":result})))
}
async fn execute(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let owner = worker(&headers, &service)?;
    let id = body["operation_id"]
        .as_str()
        .ok_or_else(|| error("Provide operation_id"))?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let job = {
        let mut jobs = service.jobs.lock().await;
        let job = jobs
            .iter_mut()
            .find(|job| job.operation_id == id)
            .ok_or_else(|| error("Unknown operation"))?;
        if job.owner.as_deref() != Some(owner.as_str())
            || job.claim.as_deref() != body["claim"].as_str()
        {
            return Err(error("Claim belongs to another worker"));
        }
        if job.state != "claimed" {
            return Err(error(
                "Claim is no longer executable; inspect the retained operation",
            ));
        }
        job.state = "running".into();
        let result = job.clone();
        service.persist(&jobs).map_err(error)?;
        result
    };
    service
        .cancellations
        .lock()
        .await
        .insert(id.into(), cancellation.clone());
    let mut call = request(&service.cap, "reports", "generate", job.input.clone());
    call.request_id = id.into();
    let result = service
        .host
        .call_controlled(
            &service.run,
            &owner,
            call,
            Some(json!({"operation_id":id,"worker":owner})),
            cancellation,
        )
        .await;
    service.cancellations.lock().await.remove(id);
    let outcome = match result {
        Ok(call) => {
            json!({"allowed":call.allowed,"output":call.output,"receipt_id":call.receipt_id})
        }
        Err(e) => json!({"error":e.to_string(),"receipt_id":null}),
    };
    let published = service
        .config
        .directory
        .join("reports")
        .join(format!("{id}.json"))
        .exists();
    {
        let mut jobs = service.jobs.lock().await;
        let job = jobs
            .iter_mut()
            .find(|job| job.operation_id == id)
            .ok_or_else(|| error("Operation disappeared"))?;
        job.state = if published {
            "completed"
        } else if outcome["allowed"] == false {
            "refused"
        } else {
            "unresolved"
        }
        .into();
        job.outcome = outcome.clone();
        service.persist(&jobs).map_err(error)?;
    }
    service
        .run
        .emit(
            "fleet.accounting",
            &owner,
            "Retained accounting after execution",
            service.accounting().map_err(error)?,
        )
        .map_err(error)?;
    if job.input["lose_ack"] == true {
        // The transport loses its response after the kernel and adapter finish.
        // Reconciliation reads the artifact instead of invoking the tool again.
        return Err((
            StatusCode::GATEWAY_TIMEOUT,
            Json(
                json!({"error":"Delivery acknowledgement was lost; reconcile this operation ID","operation_id":id}),
            ),
        ));
    }
    Ok(Json(outcome))
}
async fn cancel(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    admin(&headers, &service)?;
    if let Some(flag) = service.cancellations.lock().await.get(&id) {
        flag.store(true, Ordering::SeqCst);
        return Ok(Json(json!({"cancellation_requested":true})));
    }
    let mut jobs = service.jobs.lock().await;
    let job = jobs
        .iter_mut()
        .find(|job| job.operation_id == id)
        .ok_or_else(|| error("Unknown operation"))?;
    if ["queued", "claimed"].contains(&job.state.as_str()) {
        job.state = "cancelled_before_dispatch".into();
        service.persist(&jobs).map_err(error)?;
        return Ok(Json(
            json!({"state":"cancelled_before_dispatch","receipt_id":null}),
        ));
    }
    Err(error(
        "No active worker; inspect the operation before attempting recovery",
    ))
}
async fn snapshot(State(service): State<Arc<Service>>, headers: HeaderMap) -> ApiResult {
    admin(&headers, &service)?;
    let jobs = service.jobs.lock().await;
    Ok(Json(json!({
        "jobs":*jobs,
        "accounting":service.accounting().map_err(error)?,
        "capture":service.run.snapshot().map_err(error)?,
        "kernel_key":service.host.signer.to_hex()
    })))
}
async fn reconcile(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    admin(&headers, &service)?;
    let mut jobs = service.jobs.lock().await;
    let job = jobs
        .iter_mut()
        .find(|job| job.operation_id == id)
        .ok_or_else(|| error("Unknown operation"))?;
    if service.cancellations.lock().await.contains_key(&id) {
        return Err(error(
            "Worker is still executing; wait for its terminal state",
        ));
    }
    let file = service
        .config
        .directory
        .join("reports")
        .join(format!("{id}.json"));
    let resolution = if file.exists() {
        let artifact: Value =
            serde_json::from_slice(&std::fs::read(file).map_err(error)?).map_err(error)?;
        let expected =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&job.input).map_err(error)?);
        if artifact["input_sha256"] != expected || artifact["operation_id"] != id {
            return Err(error(
                "Artifact does not match this operation; leave it unresolved",
            ));
        }
        job.state = "completed".into();
        json!({"state":"completed","reused_existing_effect":true,"artifact":artifact,"receipt_id":job.outcome["receipt_id"]})
    } else {
        json!({
            "state":job.state,
            "reused_existing_effect":false,
            "recovery":"No published artifact proves completion. Inspect retained admission and partial output; this adapter does not blindly retry uncertain work."
        })
    };
    service.persist(&jobs).map_err(error)?;
    service
        .run
        .emit(
            "fleet.reconciled",
            "operator",
            "Reconciled the report's actual state",
            json!({"operation_id":id,"resolution":resolution}),
        )
        .map_err(error)?;
    Ok(Json(resolution))
}
pub async fn serve(config: Config) -> anyhow::Result<()> {
    private_directory(&config.directory)?;
    private_directory(&config.directory.join("reports"))?;
    let host = Host::open_priced(
        &config.directory.join("host"),
        "fleet-fixed-report-cost-v1",
        vec![Box::new(ReportTool {
            directory: config.directory.join("reports"),
        })],
        true,
    )?;
    let capfile = config.directory.join("worker-capability.json");
    let cap: CapabilityToken = if capfile.exists() {
        serde_json::from_slice(&std::fs::read(capfile)?)?
    } else {
        let mut grant = grant("reports", "generate", 32);
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: PRICE,
            currency: "USD".into(),
        });
        grant.max_total_cost = Some(MonetaryAmount {
            units: config.input["allowance"].as_u64().unwrap_or(50),
            currency: "USD".into(),
        });
        let cap = host.kernel.issue_capability(
            &Keypair::generate().public_key(),
            ChioScope {
                grants: vec![grant],
                ..Default::default()
            },
            config.input["capability_ttl_seconds"]
                .as_u64()
                .unwrap_or(900)
                .clamp(1, 900),
        )?;
        write_json(&capfile, &json!(cap))?;
        cap
    };
    let jobsfile = config.directory.join("jobs.json");
    let mut jobs: Vec<Job> = if jobsfile.exists() {
        serde_json::from_slice(&std::fs::read(jobsfile)?)?
    } else {
        config.input["sections"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Choose report sections"))?
            .iter()
            .enumerate()
            .map(|(index, section)| {
                let id = uuid::Uuid::new_v4().to_string();
                Job {
                    operation_id: id.clone(),
                    input: json!({
                        "operation_id":id,
                        "section":section,
                        "text":config.input["document"],
                        "lose_ack":config.input["lose_ack_index"].as_u64()==Some(index as u64)
                    }),
                    state: "queued".into(),
                    owner: None,
                    claim: None,
                    outcome: Value::Null,
                }
            })
            .collect()
    };
    // A restarted process cannot claim that its old workers are still alive.
    for job in &mut jobs {
        if ["claimed", "running"].contains(&job.state.as_str()) {
            job.state = "unresolved".into();
        }
    }
    let run = Run::create(
        &config.directory.join("service-runs"),
        "worker-fleet-host",
        &config.input,
    )?;
    let service = Arc::new(Service {
        host,
        cap,
        config,
        run,
        jobs: Mutex::new(jobs),
        cancellations: Mutex::new(BTreeMap::new()),
    });
    service.persist(&*service.jobs.lock().await)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = Router::new()
        .route("/claim", post(claim))
        .route("/execute", post(execute))
        .route("/snapshot", get(snapshot))
        .route("/cancel/{id}", post(cancel))
        .route("/reconcile/{id}", post(reconcile))
        .layer(DefaultBodyLimit::max(128_000))
        .with_state(service.clone());
    println!(
        "{}",
        json!({"url":format!("http://{address}"),"pid":std::process::id(),"kernel_key":service.host.signer.to_hex()})
    );
    axum::serve(listener, router).await?;
    Ok(())
}
