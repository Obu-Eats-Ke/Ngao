use rbatis::RBatis;
use rbdc_mssql::MssqlDriver;
use rbdc_mysql::MysqlDriver;
use rbdc_pg::PgDriver;
use rbdc_sqlite::SqliteDriver;

pub async fn create_repo(connection_string: &str) -> Result<RBatis, String> {
    fast_log::init(fast_log::Config::new().console()).expect("rbatis init fail");
    let rb = RBatis::new();
    if connection_string.contains("postgres") {
        rb.link(PgDriver {}, connection_string)
            .await
            .map_err(|error| error.to_string())?;
    } else if connection_string.contains("sqlite") {
        rb.link(SqliteDriver {}, connection_string)
            .await
            .map_err(|error| error.to_string())?;
    } else if connection_string.contains("mysql") {
        rb.link(MysqlDriver {}, connection_string)
            .await
            .map_err(|error| error.to_string())?;
    } else {
        rb.link(MssqlDriver {}, connection_string)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(rb)
}
