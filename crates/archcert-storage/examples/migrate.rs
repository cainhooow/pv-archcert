//! Explicit migration entry point; use separately provisioned migration credentials.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("ARCHCERT_DATABASE_URL")?;
    archcert_storage::PostgresJobRepository::connect(&url)
        .await?
        .migrate()
        .await?;
    println!("ArchCert migrations applied");
    Ok(())
}
