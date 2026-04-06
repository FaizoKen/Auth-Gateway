use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

async fn check_service(http: &reqwest::Client, name: &str, url: &str) -> Value {
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), http.get(url).send()).await;
    let latency = start.elapsed().as_millis() as u64;

    let is_up = matches!(result, Ok(Ok(_)));

    json!({
        "name": name,
        "status": if is_up { "up" } else { "down" },
        "latency_ms": latency
    })
}

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let db_fut = async {
        let start = std::time::Instant::now();
        let ok = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&state.pool)
            .await
            .is_ok();
        (ok, start.elapsed().as_millis() as u64)
    };
    let svc_fut = check_service(
        &state.http,
        "Discord API",
        "https://discord.com/api/v10/gateway",
    );

    let ((db_ok, db_latency), svc_check) = tokio::join!(db_fut, svc_fut);

    let svc_down = svc_check["status"] == "down";
    let status = match (db_ok, svc_down) {
        (true, false) => "healthy",
        (false, true) => "unhealthy",
        _ => "degraded",
    };

    Json(json!({
        "status": status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        },
        "services": [svc_check]
    }))
}
