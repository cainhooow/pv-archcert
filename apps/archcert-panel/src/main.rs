//! Glassmere composition: read-only PostgreSQL, immutable reads, public verification.

mod query;

use archcert_glassmere::auth::PanelConfiguration;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    query_config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8090")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "Glassmere must bind loopback behind its trusted TLS boundary"
    );
    let configuration = PanelConfiguration::load(&args.config)
        .map_err(|_| anyhow::anyhow!("private panel configuration unavailable"))?;
    if configuration.development_http {
        anyhow::ensure!(
            configuration.origin == format!("http://{}", args.listen),
            "development origin must match loopback listener"
        );
    }

    let database_url = std::env::var("ARCHCERT_OBSERVATION_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("observation database configuration unavailable"))?;
    let query = query::QueryService::connect(&database_url, &args.query_config)
        .await
        .map_err(|_| anyhow::anyhow!("read-only observation initialization failed"))?;
    let router = archcert_glassmere::router(Arc::new(query), args.config)
        .map_err(|_| anyhow::anyhow!("private authentication/audit initialization failed"))?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    println!("Glassmere private observation listening on {}", args.listen);
    axum_serve(listener, router).await
}

// HTTP serving is part of outer executable composition, not an inward port.
async fn axum_serve(
    listener: tokio::net::TcpListener,
    router: archcert_glassmere::HttpRouter,
) -> anyhow::Result<()> {
    archcert_glassmere::serve(listener, router).await?;

    Ok(())
}
