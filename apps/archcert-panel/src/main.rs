//! Glassmere composition: read-only observation and optional bounded command mediation.

mod broker;
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
    #[arg(long)]
    command_config: Option<PathBuf>,
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
    let query = Arc::new(query);
    let router = if let Some(path) = args.command_config {
        let commands = broker::CommandBroker::open(path, args.config.clone())
            .map_err(|_| anyhow::anyhow!("private command broker initialization failed"))?;
        archcert_glassmere::router_with_commands(query, args.config, Arc::new(commands))
    } else {
        archcert_glassmere::router(query, args.config)
    }
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
