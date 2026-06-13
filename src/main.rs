use std::sync::Arc;

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Embed the favicon at compile-time so it ships in the binary — no
/// runtime file IO, no static-file server, no missing-asset risk in
/// production. Cached aggressively (1 day) since the bytes are pinned
/// to whatever build is currently running.
const FAVICON_BYTES: &[u8] = include_bytes!("../favicon.ico");

async fn favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_BYTES,
    )
}

mod config;
mod db;
mod error;
mod plugins;
mod routes;
mod services;
mod tasks;

pub struct AppState {
    pub pool: PgPool,
    pub config: config::AppConfig,
    pub http: reqwest::Client,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_gateway=info,tower_http=info".into()),
        )
        .init();

    let app_config = config::AppConfig::from_env();
    let listen_addr = app_config.listen_addr.clone();

    let pool = db::create_pool(&app_config.database_url).await;
    db::run_migrations(&pool).await;
    tracing::info!("Database connected and migrations applied");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(AppState {
        pool,
        config: app_config,
        http,
    });

    // Spawn background workers
    tokio::spawn(tasks::guild_refresh_worker::run(Arc::clone(&state)));
    tokio::spawn(tasks::cleanup_expired(Arc::clone(&state)));

    let app = Router::new()
        .nest("/auth", Router::new()
            .route("/favicon.ico", get(favicon))
            .route("/login", get(routes::oauth::login))
            .route("/callback", get(routes::oauth::callback))
            .route("/logout", post(routes::oauth::logout))
            .route("/guild_permission", get(routes::oauth::guild_permission))
            .route("/guild_members", get(routes::oauth::guild_members))
            .route("/my_guilds", get(routes::oauth::my_guilds))
            .route("/my_servers", get(routes::preferences::my_servers_page))
            .route("/preferences", get(routes::preferences::get_preferences)
                                     .post(routes::preferences::update_preference))
            .route("/preferences/bulk", post(routes::preferences::bulk_update_preference))
            .route("/preferences/auto_enable", post(routes::preferences::update_auto_enable))
            .route("/internal/user_guild_ids", get(routes::internal::user_guild_ids))
            .route("/internal/guild_member_ids", get(routes::internal::guild_member_ids))
            .route("/internal/guild_optout_ids", get(routes::internal::guild_optout_ids))
            .route("/health", get(routes::health::health))
        )
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("Auth Gateway starting on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("Failed to bind listener");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutdown signal received, draining connections...");
        })
        .await
        .expect("Server error");

    tracing::info!("Auth Gateway stopped");
}
