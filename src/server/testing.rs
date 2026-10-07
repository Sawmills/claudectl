//! Test support: a fresh PostgreSQL database per test when CLAUDECTL_TEST_DATABASE_URL names
//! an admin connection (CI service container, or a throwaway local cluster).
use anyhow::Result;

/// A URL to a new, empty database with the schema applied, or `None` without a test server.
pub async fn fresh_database() -> Result<Option<String>> {
    let Ok(admin) = std::env::var("CLAUDECTL_TEST_DATABASE_URL") else {
        return Ok(None);
    };
    let name = format!("claudectl_test_{}", &super::vault::secret()[..16]);
    let (client, connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await?;
    let url = database_url(&admin, &name);
    super::store::PostgresStore::connect(&url)
        .await?
        .migrate()
        .await?;
    Ok(Some(url))
}

/// Replace the database name in a `postgres://` URL.
fn database_url(admin: &str, name: &str) -> String {
    let (base, query) = admin
        .split_once('?')
        .map_or((admin, None), |(b, q)| (b, Some(q)));
    let base = base.rsplit_once('/').map_or(base, |(b, _)| b);
    match query {
        Some(q) => format!("{base}/{name}?{q}"),
        None => format!("{base}/{name}"),
    }
}
