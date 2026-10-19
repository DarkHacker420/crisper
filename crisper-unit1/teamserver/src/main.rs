mod config;
mod db;
mod listener;
mod session;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "teamserver.yaml".into());
    let cfg = config::Config::load(&path)?;
    let db = db::Db::open(&cfg.db_path)?;
    let state = listener::State::new(cfg, db)?;

    let (tx, rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn({
        let state = state.clone();
        async move { listener::run(state, rx).await }
    });

    tokio::signal::ctrl_c().await?;
    println!("\n[!] shutdown requested");
    let _ = tx.send(true);
    server.await??;
    println!("[+] clean exit");
    Ok(())
}
