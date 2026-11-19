mod raw;
mod snapshot;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use kube::{Client, Config, config::KubeConfigOptions};
use rust_embed::RustEmbed;
use serde::Serialize;
use tokio::sync::{Notify, RwLock};
use tower_http::compression::CompressionLayer;

use snapshot::Snapshot;

/// Read-only dashboard over Trivy Operator reports.
#[derive(Parser, Debug)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "GJALLARHORN_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// Seconds between report refreshes.
    #[arg(long, env = "GJALLARHORN_REFRESH", default_value_t = 120)]
    refresh: u64,
    /// Kubeconfig context to use (defaults to current context / in-cluster).
    #[arg(long, env = "GJALLARHORN_CONTEXT")]
    context: Option<String>,
    /// Serve reports from a JSON file instead of a cluster (see fixtures/).
    #[arg(long, env = "GJALLARHORN_FIXTURES", conflicts_with = "context")]
    fixtures: Option<PathBuf>,
}

/// Where reports come from.
enum Source {
    Cluster(Client),
    Fixtures(PathBuf),
}

impl Source {
    async fn collect(&self) -> Result<Snapshot> {
        match self {
            Source::Cluster(client) => snapshot::collect(client).await,
            Source::Fixtures(path) => {
                let text = tokio::fs::read_to_string(path).await?;
                let fixture: snapshot::Fixture = serde_json::from_str(&text)?;
                Ok(snapshot::build(fixture.into()))
            }
        }
    }
}

async fn connect(context: Option<&str>) -> Result<Client> {
    Ok(match context {
        Some(ctx) => {
            let cfg = Config::from_kubeconfig(&KubeConfigOptions {
                context: Some(ctx.to_string()),
                ..Default::default()
            })
            .await?;
            Client::try_from(cfg)?
        }
        None => Client::try_default().await?,
    })
}

#[derive(Default)]
struct AppState {
    snap: RwLock<Option<Arc<Snapshot>>>,
    last_error: RwLock<Option<String>>,
    refreshing: RwLock<bool>,
    wake: Notify,
}

type St = Arc<AppState>;

#[derive(RustEmbed)]
#[folder = "web/dist"]
struct Assets;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let source = match &args.fixtures {
        Some(path) => {
            tracing::info!("serving reports from {}", path.display());
            Source::Fixtures(path.clone())
        }
        None => Source::Cluster(connect(args.context.as_deref()).await?),
    };

    let state: St = Arc::new(AppState::default());
    tokio::spawn(refresh_loop(
        source,
        state.clone(),
        Duration::from_secs(args.refresh),
    ));

    let api = Router::new()
        .route(
            "/overview",
            get(|s: State<St>| with_snap(s, |x| json(&x.overview))),
        )
        .route(
            "/images",
            get(|s: State<St>| with_snap(s, |x| json(&x.images))),
        )
        .route(
            "/images/{id}",
            get(|s: State<St>, Path(id): Path<String>| {
                with_snap(s, move |x| opt(x.image_details.get(&id)))
            }),
        )
        .route("/cves", get(|s: State<St>| with_snap(s, |x| json(&x.cves))))
        .route(
            "/cves/{id}",
            get(|s: State<St>, Path(id): Path<String>| {
                with_snap(s, move |x| opt(x.cve_details.get(&id)))
            }),
        )
        .route(
            "/workloads",
            get(|s: State<St>| with_snap(s, |x| json(&x.workloads))),
        )
        .route(
            "/misconfigs",
            get(|s: State<St>| with_snap(s, |x| json(&x.misconfigs))),
        )
        .route(
            "/secrets",
            get(|s: State<St>| with_snap(s, |x| json(&x.secrets))),
        )
        .route(
            "/compliance",
            get(|s: State<St>| with_snap(s, |x| json(&x.compliance))),
        )
        .route("/status", get(status))
        .route(
            "/refresh",
            post(|State(s): State<St>| async move {
                s.wake.notify_one();
                StatusCode::ACCEPTED
            }),
        );

    let app = Router::new()
        .nest("/api", api)
        .route("/healthz", get(|| async { "ok" }))
        .fallback(static_file)
        .layer(CompressionLayer::new())
        .with_state(state);

    tracing::info!("listening on http://{}", args.bind);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn refresh_loop(source: Source, state: St, every: Duration) {
    loop {
        *state.refreshing.write().await = true;
        match source.collect().await {
            Ok(s) => {
                tracing::info!(
                    images = s.images.len(),
                    cves = s.cves.len(),
                    misconfigs = s.misconfigs.len(),
                    ms = s.overview.duration_ms,
                    "snapshot refreshed"
                );
                *state.snap.write().await = Some(Arc::new(s));
                *state.last_error.write().await = None;
            }
            Err(e) => {
                tracing::error!("refresh failed: {e:#}");
                *state.last_error.write().await = Some(format!("{e:#}"));
            }
        }
        *state.refreshing.write().await = false;
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = state.wake.notified() => {}
        }
    }
}

async fn status(State(s): State<St>) -> Response {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Status {
        ready: bool,
        refreshing: bool,
        refreshed_at: Option<String>,
        error: Option<String>,
    }
    let snap = s.snap.read().await.clone();
    json(&Status {
        ready: snap.is_some(),
        refreshing: *s.refreshing.read().await,
        refreshed_at: snap.map(|x| x.overview.refreshed_at.clone()),
        error: s.last_error.read().await.clone(),
    })
}

async fn with_snap(State(s): State<St>, f: impl FnOnce(&Snapshot) -> Response) -> Response {
    let snap = s.snap.read().await.clone();
    match snap {
        Some(x) => f(&x),
        None => {
            let err = s.last_error.read().await.clone();
            (StatusCode::SERVICE_UNAVAILABLE, json_body(&serde_json::json!({ "error": err.unwrap_or_else(|| "loading reports…".into()) })))
                .into_response()
        }
    }
}

fn json_body<T: Serialize>(v: &T) -> Response {
    match serde_json::to_vec(v) {
        Ok(b) => ([(header::CONTENT_TYPE, "application/json")], b).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn json<T: Serialize>(v: &T) -> Response {
    json_body(v)
}

fn opt<T: Serialize>(v: Option<&T>) -> Response {
    match v {
        Some(v) => json(v),
        None => (
            StatusCode::NOT_FOUND,
            json_body(&serde_json::json!({ "error": "not found" })),
        )
            .into_response(),
    }
}

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    let (path, file) = match Assets::get(path) {
        Some(f) => (path, f),
        // SPA fallback
        None => match Assets::get("index.html") {
            Some(f) => ("index.html", f),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        file.data,
    )
        .into_response()
}
