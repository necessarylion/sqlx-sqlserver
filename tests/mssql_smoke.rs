use sqlx_sqlserver::MssqlConnectOptions;
#[cfg(feature = "integration-tests")]
use sqlx_sqlserver::MssqlPoolOptions;
#[cfg(feature = "integration-tests")]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(feature = "integration-tests")]
use std::sync::Once;
#[cfg(feature = "integration-tests")]
use std::time::Duration;

#[cfg(feature = "integration-tests")]
use futures_util::TryStreamExt;
#[cfg(feature = "integration-tests")]
use sqlx_core::column::Column;
#[cfg(feature = "integration-tests")]
use sqlx_core::connection::{ConnectOptions, Connection};
#[cfg(feature = "integration-tests")]
use sqlx_core::executor::Executor;
#[cfg(feature = "integration-tests")]
use sqlx_core::query_builder::QueryBuilder;
#[cfg(feature = "integration-tests")]
use sqlx_core::row::Row;
#[cfg(all(feature = "integration-tests", feature = "migrate"))]
use sqlx_core::sql_str::SqlSafeStr;
#[cfg(feature = "integration-tests")]
use sqlx_core::statement::Statement;
#[cfg(feature = "integration-tests")]
use sqlx_core::value::ValueRef;
#[cfg(all(feature = "integration-tests", feature = "migrate"))]
use std::borrow::Cow;

// SQL Server query macros are intentionally not ported here; this crate does not
// currently expose the macro integration needed for compile-time checked tests.

fn database_url() -> Option<String> {
    std::env::var("MSSQL_DATABASE_URL")
        .ok()
        .and_then(|url| match url.trim() {
            "" => None,
            url => Some(url.to_owned()),
        })
}

#[cfg(feature = "integration-tests")]
async fn any_test_conn(
    test_name: &str,
) -> Result<Option<sqlx_core::any::AnyConnection>, Box<dyn std::error::Error>> {
    static INSTALL: Once = Once::new();

    let Some(url) = database_url() else {
        eprintln!("skipping {test_name}: MSSQL_DATABASE_URL is not set");
        return Ok(None);
    };

    INSTALL.call_once(|| {
        sqlx_core::any::driver::install_drivers(&[sqlx_sqlserver::any::DRIVER])
            .expect("SQL Server Any driver should install once");
    });

    Ok(Some(sqlx_core::any::AnyConnection::connect(&url).await?))
}

#[cfg(all(feature = "integration-tests", feature = "migrate"))]
async fn any_migrate_test_conn(
    test_name: &str,
) -> Result<Option<sqlx_core::any::AnyConnection>, Box<dyn std::error::Error>> {
    any_test_conn(test_name).await
}

#[cfg(feature = "integration-tests")]
async fn native_test_conn(
    test_name: &str,
) -> Result<Option<sqlx_sqlserver::MssqlConnection>, Box<dyn std::error::Error>> {
    let Some(url) = database_url() else {
        eprintln!("skipping {test_name}: MSSQL_DATABASE_URL is not set");
        return Ok(None);
    };

    let options = url.parse::<MssqlConnectOptions>()?;
    Ok(Some(options.connect().await?))
}

#[test]
fn mssql_database_url_is_parseable_when_set() {
    let Some(url) = database_url() else {
        eprintln!("skipping SQL Server smoke test: MSSQL_DATABASE_URL is not set");
        return;
    };

    url.parse::<MssqlConnectOptions>()
        .expect("MSSQL_DATABASE_URL should parse as SQL Server options");
}

#[cfg(feature = "migrate")]
#[test]
fn any_driver_exposes_migrate_database_when_feature_enabled() {
    sqlx_sqlserver::any::DRIVER
        .get_migrate_database()
        .expect("SQL Server Any driver should expose migration database hooks");
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn connects_and_pings_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server integration test").await? else {
        return Ok(());
    };

    conn.ping().await?;
    conn.close().await?;

    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn encrypts_connection_when_requested() -> Result<(), Box<dyn std::error::Error>> {
    let Some(url) = database_url() else {
        eprintln!("skipping SQL Server TLS test: MSSQL_DATABASE_URL is not set");
        return Ok(());
    };
    let options = url.parse::<MssqlConnectOptions>()?;
    let mut conn = options.connect().await?;

    let row = sqlx_core::query::query(
        "SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID",
    )
    .fetch_one(&mut conn)
    .await?;
    let encrypted = row.try_get::<String, _>(0)? == "TRUE";
    let requested = matches!(
        options.encrypt(),
        sqlx_sqlserver::Encrypt::On | sqlx_sqlserver::Encrypt::Required
    );

    // With encrypt=optional the server can still pick TLS, so only check one way.
    if requested {
        assert!(
            encrypted,
            "the URL asks for TLS, but the connection is not encrypted"
        );
    }

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_select_one_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server query test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT 1")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(1_i32, row.try_get::<i32, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runs_independent_connections_in_parallel_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(url) = database_url() else {
        eprintln!("skipping SQL Server async parallelism test: MSSQL_DATABASE_URL is not set");
        return Ok(());
    };

    let mut tasks = Vec::new();

    for expected in 0_i32..8 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let options = url.parse::<MssqlConnectOptions>().map_err(|error| {
                format!("failed to parse MSSQL_DATABASE_URL for parallel task {expected}: {error}")
            })?;
            let mut conn = options.connect().await.map_err(|error| {
                format!("failed to connect SQL Server parallel task {expected}: {error}")
            })?;
            let row = sqlx_core::query::query("SELECT @p1")
                .bind(expected)
                .fetch_one(&mut conn)
                .await
                .map_err(|error| format!("parallel SQL Server query {expected} failed: {error}"))?;
            let actual = row.try_get::<i32, _>(0).map_err(|error| {
                format!("parallel SQL Server decode {expected} failed: {error}")
            })?;
            conn.close().await.map_err(|error| {
                format!("failed to close SQL Server parallel task {expected}: {error}")
            })?;

            if actual != expected {
                return Err(format!(
                    "parallel SQL Server task returned {actual}, expected {expected}"
                ));
            }

            Ok::<(), String>(())
        }));
    }

    for task in tasks {
        if let Err(message) = task.await? {
            return Err(std::io::Error::other(message).into());
        }
    }

    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_bound_scalars_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server bound scalar test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT @p1, @p2")
        .bind(7_i32)
        .bind("hello")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(7_i32, row.try_get::<i32, _>(0)?);
    assert_eq!("hello", row.try_get::<String, _>(1)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_1000_rows_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server 1000 row fetch test").await? else {
        return Ok(());
    };

    let mut rows = sqlx_core::query::query(
        "WITH n(v) AS (SELECT 1 UNION ALL SELECT v + 1 FROM n WHERE v < 1000) \
         SELECT v * 2 AS id FROM n OPTION (MAXRECURSION 1000)",
    )
    .fetch(&mut conn);

    let mut count = 0;
    let mut sum = 0_i32;
    while let Some(row) = rows.try_next().await? {
        count += 1;
        sum += row.try_get::<i32, _>("id")?;
    }
    drop(rows);

    assert_eq!(count, 1000);
    assert_eq!(sum, 1_001_000);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn execute_reports_rows_affected_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server rows affected test").await? else {
        return Ok(());
    };

    conn.execute("CREATE TABLE #rows_affected (id INT NOT NULL)")
        .await?;

    let result = sqlx_core::query::query("INSERT INTO #rows_affected (id) VALUES (@p1)")
        .bind(1_i32)
        .execute(&mut conn)
        .await?;
    assert_eq!(result.rows_affected(), 1);

    let result = sqlx_core::query::query("UPDATE #rows_affected SET id = @p1 WHERE id = @p2")
        .bind(2_i32)
        .bind(1_i32)
        .execute(&mut conn)
        .await?;
    assert_eq!(result.rows_affected(), 1);

    let result = sqlx_core::query::query("DELETE FROM #rows_affected WHERE id = @p1")
        .bind(2_i32)
        .execute(&mut conn)
        .await?;
    assert_eq!(result.rows_affected(), 1);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_bound_large_text_and_binary_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server large parameter test").await? else {
        return Ok(());
    };

    let text = "x".repeat(4001);
    let row = sqlx_core::query::query("SELECT LEN(@p1), DATALENGTH(@p1)")
        .bind(text.as_str())
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(4001_i64, row.try_get::<i64, _>(0)?);
    assert_eq!(8002_i64, row.try_get::<i64, _>(1)?);

    let bytes = vec![0x5a; 8001];
    let row = sqlx_core::query::query("SELECT DATALENGTH(@p1)")
        .bind(bytes.as_slice())
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(8001_i64, row.try_get::<i64, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_string_with_special_chars_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server special string test").await? else {
        return Ok(());
    };

    let expected = "/\r\n\t\0\x1b!@#$/.%^\x1b&*()_+";
    let row = sqlx_core::query::query("SELECT @p1")
        .bind(expected)
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(expected, row.try_get::<String, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn accepts_long_query_strings_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server long query string test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "SELECT {} 42",
        " ".repeat(3000)
    )))
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(42_i32, row.try_get::<i32, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_native_scalar_arguments_when_configured() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(mut conn) = native_test_conn("SQL Server native scalar argument test").await? else {
        return Ok(());
    };

    let bytes = vec![0x01, 0x23, 0x45, 0x67];
    let row = sqlx_core::query::query(
        "SELECT @p1, @p2, @p3, @p4, @p5, @p6, CAST(@p7 AS VARCHAR(12)), CAST(@p8 AS NVARCHAR(12))",
    )
    .bind(true)
    .bind(-1234_i16)
    .bind(9_876_543_210_i64)
    .bind(3.25_f32)
    .bind(6.5_f64)
    .bind(bytes.as_slice())
    .bind("varchar")
    .bind("nvarchar")
    .fetch_one(&mut conn)
    .await?;

    assert!(row.try_get::<bool, _>(0)?);
    assert_eq!(-1234_i16, row.try_get::<i16, _>(1)?);
    assert_eq!(9_876_543_210_i64, row.try_get::<i64, _>(2)?);
    assert_eq!(3.25_f32, row.try_get::<f32, _>(3)?);
    assert_eq!(6.5_f64, row.try_get::<f64, _>(4)?);
    assert_eq!(bytes, row.try_get::<Vec<u8>, _>(5)?);
    assert_eq!("varchar", row.try_get::<String, _>(6)?);
    assert_eq!("nvarchar", row.try_get::<String, _>(7)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_varchar_text_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server varchar decode test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT CAST('hello' AS VARCHAR(5))")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!("hello", row.try_get::<String, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_old_numeric_float_and_integer_behaviors_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server numeric behavior test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST(0.5678 AS NUMERIC(10,4)), CAST(939399419.1225182 AS DECIMAL(15,2)), CAST(123456789 AS DECIMAL(15,0)), CAST(-123456789 AS DECIMAL(15,0)), CAST('0.0001' AS MONEY)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(0.5678_f64, row.try_get::<f64, _>(0)?);
    assert_eq!(939_399_419.12_f64, row.try_get::<f64, _>(1)?);
    assert_eq!(123_456_789_i64, row.try_get::<i64, _>(2)?);
    assert_eq!(-123_456_789_i64, row.try_get::<i64, _>(3)?);
    assert_eq!(0.0001_f64, row.try_get::<f64, _>(4)?);

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "decimal"))]
#[tokio::test]
async fn fetches_rust_decimal_numeric_and_money_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    use rust_decimal::Decimal;

    let Some(mut conn) = native_test_conn("SQL Server rust_decimal type test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST('123456789.987654321' AS DECIMAL(18,9)), CAST('-1' AS DECIMAL(1,0)), CAST('922337203685477.5807' AS MONEY), CAST('-214748.3648' AS SMALLMONEY)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(
        Decimal::from_str_exact("123456789.987654321")?,
        row.try_get::<Decimal, _>(0)?
    );
    assert_eq!(
        Decimal::from_str_exact("-1")?,
        row.try_get::<Decimal, _>(1)?
    );
    assert_eq!(
        Decimal::from_str_exact("922337203685477.5807")?,
        row.try_get::<Decimal, _>(2)?
    );
    assert_eq!(
        Decimal::from_str_exact("-214748.3648")?,
        row.try_get::<Decimal, _>(3)?
    );

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "bigdecimal"))]
#[tokio::test]
async fn fetches_bigdecimal_numeric_and_money_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    let Some(mut conn) = native_test_conn("SQL Server bigdecimal type test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST('-12345678901234567890.012345678901234' AS DECIMAL(38,15)), CAST('-1234567890.1234' AS MONEY), CAST('-123456.1234' AS SMALLMONEY)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(
        BigDecimal::from_str("-12345678901234567890.012345678901234")?,
        row.try_get::<BigDecimal, _>(0)?
    );
    assert_eq!(
        BigDecimal::from_str("-1234567890.1234")?,
        row.try_get::<BigDecimal, _>(1)?
    );
    assert_eq!(
        BigDecimal::from_str("-123456.1234")?,
        row.try_get::<BigDecimal, _>(2)?
    );

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "chrono"))]
#[tokio::test]
async fn fetches_chrono_date_time_types_when_configured() -> Result<(), Box<dyn std::error::Error>>
{
    use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};

    let Some(mut conn) = native_test_conn("SQL Server chrono type test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST('1901-05-08 23:58:59' AS DATETIME), CAST('2016-10-23 12:45:37.1234567' AS DATETIME2), CAST('1789-07-14' AS DATE), CAST('23:59:59.9999' AS TIME), CAST('2016-10-23 12:45:37.1234567 +02:00' AS DATETIMEOFFSET(7))",
    )
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(
        NaiveDate::from_ymd_opt(1901, 5, 8)
            .unwrap()
            .and_hms_opt(23, 58, 59)
            .unwrap(),
        row.try_get::<NaiveDateTime, _>(0)?
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(2016, 10, 23)
            .unwrap()
            .and_hms_nano_opt(12, 45, 37, 123_456_700)
            .unwrap(),
        row.try_get::<NaiveDateTime, _>(1)?
    );
    assert_eq!(
        NaiveDate::from_ymd_opt(1789, 7, 14).unwrap(),
        row.try_get::<NaiveDate, _>(2)?
    );
    assert_eq!(
        NaiveTime::from_hms_nano_opt(23, 59, 59, 999_900_000).unwrap(),
        row.try_get::<NaiveTime, _>(3)?
    );
    assert_eq!(
        FixedOffset::east_opt(2 * 60 * 60)
            .unwrap()
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2016, 10, 23)
                    .unwrap()
                    .and_hms_nano_opt(12, 45, 37, 123_456_700)
                    .unwrap(),
            )
            .unwrap(),
        row.try_get::<DateTime<FixedOffset>, _>(4)?
    );

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "time"))]
#[tokio::test]
async fn fetches_time_crate_date_time_types_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

    let Some(mut conn) = native_test_conn("SQL Server time crate type test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST('2016-10-23 12:45:37.1234567' AS DATETIME2), CAST('1789-07-14' AS DATE), CAST('23:59:59.9999' AS TIME), CAST('2016-10-23 12:45:37.1234567 +02:00' AS DATETIMEOFFSET(7))",
    )
    .fetch_one(&mut conn)
    .await?;

    let date = Date::from_calendar_date(2016, Month::October, 23)?;
    let time = Time::from_hms_nano(12, 45, 37, 123_456_700)?;
    assert_eq!(
        PrimitiveDateTime::new(date, time),
        row.try_get::<PrimitiveDateTime, _>(0)?
    );
    assert_eq!(
        Date::from_calendar_date(1789, Month::July, 14)?,
        row.try_get::<Date, _>(1)?
    );
    assert_eq!(
        Time::from_hms_nano(23, 59, 59, 999_900_000)?,
        row.try_get::<Time, _>(2)?
    );
    assert_eq!(
        PrimitiveDateTime::new(date, time).assume_offset(UtcOffset::from_hms(2, 0, 0)?),
        row.try_get::<OffsetDateTime, _>(3)?
    );

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "json"))]
#[tokio::test]
async fn fetches_json_value_from_varchar_when_configured() -> Result<(), Box<dyn std::error::Error>>
{
    use sqlx_core::types::Json;

    let Some(mut conn) = native_test_conn("SQL Server JSON type test").await? else {
        return Ok(());
    };

    let value = sqlx_core::query_scalar::query_scalar::<_, Json<serde_json::Value>>("SELECT '123'")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(Json(serde_json::Value::Number(123.into())), value);

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "uuid"))]
#[tokio::test]
async fn fetches_uniqueidentifier_uuid_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    use uuid::Uuid;

    let Some(mut conn) = native_test_conn("SQL Server UUID type test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query(
        "SELECT CAST('00000000-0000-0000-0000-000000000000' AS UNIQUEIDENTIFIER), CAST('6F9619FF-8B86-D011-B42D-00C04FC964FF' AS UNIQUEIDENTIFIER)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(Uuid::nil(), row.try_get::<Uuid, _>(0)?);
    assert_eq!(
        Uuid::parse_str("6F9619FF-8B86-D011-B42D-00C04FC964FF")?,
        row.try_get::<Uuid, _>(1)?
    );

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn fetches_bound_null_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server bound null test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT @p1")
        .bind(Option::<i32>::None)
        .fetch_one(&mut conn)
        .await?;

    assert!(row.try_get_raw(0)?.is_null());

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn prepares_statement_metadata_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server prepare test").await? else {
        return Ok(());
    };

    let statement = conn
        .prepare(sqlx_core::sql_str::SqlStr::from_static(
            "SELECT CAST(1 AS BIGINT) AS id, CAST(N'text' AS NVARCHAR(20)) AS text, CAST(0 AS TINYINT) AS is_sent, CAST(NULL AS BIGINT) AS owner_id",
        ))
        .await?;

    assert_eq!(4, statement.columns().len());
    assert_eq!("id", statement.columns()[0].name());
    assert_eq!("text", statement.columns()[1].name());
    assert_eq!("is_sent", statement.columns()[2].name());
    assert_eq!("owner_id", statement.columns()[3].name());
    assert_eq!("BIGINT", statement.columns()[0].type_info().name());
    assert_eq!("NVARCHAR", statement.columns()[1].type_info().name());
    assert_eq!("TINYINT", statement.columns()[2].type_info().name());
    assert_eq!("BIGINT", statement.columns()[3].type_info().name());

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn prepares_then_statement_query_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server statement query test").await? else {
        return Ok(());
    };

    let statement = (&mut conn)
        .prepare(sqlx_core::sql_str::SqlStr::from_static(
            "SELECT CAST(50 AS BIGINT) AS id, CAST(N'Hello, World' AS NVARCHAR(20)) AS text",
        ))
        .await?;

    assert_eq!(2, statement.columns().len());
    assert_eq!("id", statement.columns()[0].name());
    assert_eq!("text", statement.columns()[1].name());

    let row = statement.query().fetch_one(&mut conn).await?;

    assert_eq!(50_i64, row.try_get::<i64, _>("id")?);
    assert_eq!("Hello, World", row.try_get::<String, _>("text")?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn rolls_back_transaction_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server transaction test").await? else {
        return Ok(());
    };

    let tx = conn.begin().await?;
    tx.rollback().await?;

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn supports_nested_transactions_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server nested transaction test").await? else {
        return Ok(());
    };

    let table_name = "_sqlx_nested_tx_smoke";
    conn.execute(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {table_name}"
    )))
    .await?;
    conn.execute(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE TABLE {table_name} (id INT NOT NULL PRIMARY KEY)"
    )))
    .await?;

    let mut tx = conn.begin().await?;
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "INSERT INTO {table_name} (id) VALUES (@p1)"
    )))
    .bind(50_i32)
    .execute(&mut *tx)
    .await?;

    let mut tx2 = sqlx_core::acquire::Acquire::begin(&mut tx).await?;
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "INSERT INTO {table_name} (id) VALUES (@p1)"
    )))
    .bind(10_i32)
    .execute(&mut *tx2)
    .await?;
    tx2.rollback().await?;

    let count: i32 = sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(
        format!("SELECT COUNT(*) FROM {table_name}"),
    ))
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(1, count);

    tx.commit().await?;

    let count: i32 = sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(
        format!("SELECT COUNT(*) FROM {table_name}"),
    ))
    .fetch_one(&mut conn)
    .await?;
    assert_eq!(1, count);

    conn.execute(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {table_name}"
    )))
    .await?;
    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn dropped_transaction_rolls_back_on_next_use() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server dropped transaction rollback test").await?
    else {
        return Ok(());
    };

    let table_name = "_sqlx_drop_rollback_smoke";
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;
    conn.execute(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE TABLE {table_name} (id INT NOT NULL)"
    )))
    .await?;

    {
        let mut tx = conn.begin().await?;
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "INSERT INTO {table_name} (id) VALUES (1)"
        )))
        .execute(&mut *tx)
        .await?;
    }

    let count: i32 = sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(
        format!("SELECT COUNT(*) FROM {table_name}"),
    ))
    .fetch_one(&mut conn)
    .await?;

    assert_eq!(0, count);

    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;
    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn pool_callbacks_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug, PartialEq, Eq)]
    struct ConnStats {
        id: i32,
        before_acquire_calls: i32,
        after_release_calls: i32,
    }

    async fn conn_stats(
        conn: &mut sqlx_sqlserver::MssqlConnection,
    ) -> Result<ConnStats, sqlx_core::error::Error> {
        let row = sqlx_core::query::query(
            "SELECT id, before_acquire_calls, after_release_calls FROM #conn_stats",
        )
        .fetch_one(conn)
        .await?;

        Ok(ConnStats {
            id: row.try_get("id")?,
            before_acquire_calls: row.try_get("before_acquire_calls")?,
            after_release_calls: row.try_get("after_release_calls")?,
        })
    }

    let Some(url) = database_url() else {
        eprintln!("skipping SQL Server pool callbacks test: MSSQL_DATABASE_URL is not set");
        return Ok(());
    };

    let current_id = AtomicI32::new(0);

    let pool = MssqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(move |conn, meta| {
            assert_eq!(meta.age, Duration::ZERO);
            assert_eq!(meta.idle_for, Duration::ZERO);

            let id = current_id.fetch_add(1, Ordering::AcqRel);

            Box::pin(async move {
                conn.execute(sqlx_core::sql_str::AssertSqlSafe(format!(
                    "CREATE TABLE #conn_stats(
                        id int primary key,
                        before_acquire_calls int default 0,
                        after_release_calls int default 0
                    );
                    INSERT INTO #conn_stats(id) VALUES ({id});"
                )))
                .await?;
                Ok(())
            })
        })
        .before_acquire(|conn, meta| {
            assert_ne!(meta.age, Duration::ZERO);
            assert_ne!(meta.idle_for, Duration::ZERO);

            Box::pin(async move {
                sqlx_core::query::query(
                    "UPDATE #conn_stats SET before_acquire_calls = before_acquire_calls + 1",
                )
                .execute(&mut *conn)
                .await?;

                let stats = conn_stats(conn).await?;
                Ok((stats.id & 1) == 1 || stats.before_acquire_calls < 3)
            })
        })
        .after_release(|conn, meta| {
            assert_ne!(meta.age, Duration::ZERO);
            assert_eq!(meta.idle_for, Duration::ZERO);

            Box::pin(async move {
                sqlx_core::query::query(
                    "UPDATE #conn_stats SET after_release_calls = after_release_calls + 1",
                )
                .execute(&mut *conn)
                .await?;

                let stats = conn_stats(conn).await?;
                Ok((stats.id & 1) == 0 || stats.after_release_calls < 4)
            })
        })
        .connect_lazy(&url)?;

    let pattern = [
        (0, 0, 0),
        (0, 1, 1),
        (0, 2, 2),
        (1, 0, 0),
        (1, 1, 1),
        (1, 2, 2),
        (1, 3, 3),
        (2, 0, 0),
        (2, 1, 1),
        (2, 2, 2),
        (3, 0, 0),
    ];

    for (id, before_acquire_calls, after_release_calls) in pattern {
        let row = sqlx_core::query::query(
            "SELECT id, before_acquire_calls, after_release_calls FROM #conn_stats",
        )
        .fetch_one(&pool)
        .await?;

        assert_eq!(
            ConnStats {
                id,
                before_acquire_calls,
                after_release_calls,
            },
            ConnStats {
                id: row.try_get("id")?,
                before_acquire_calls: row.try_get("before_acquire_calls")?,
                after_release_calls: row.try_get("after_release_calls")?,
            }
        );
    }

    pool.close().await;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn query_builder_binds_mssql_placeholders_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server QueryBuilder test").await? else {
        return Ok(());
    };

    conn.execute("CREATE TABLE #qb_test (id INT PRIMARY KEY, name NVARCHAR(50))")
        .await?;

    let items = [(1_i32, "Alice"), (2_i32, "Bob"), (3_i32, "Charlie")];
    let mut insert_builder =
        QueryBuilder::<sqlx_sqlserver::Mssql>::new("INSERT INTO #qb_test (id, name) ");
    insert_builder.push_values(items.iter(), |mut row, (id, name)| {
        row.push_bind(*id).push_bind(*name);
    });

    assert_eq!(
        "INSERT INTO #qb_test (id, name) VALUES (@p1, @p2), (@p3, @p4), (@p5, @p6)",
        insert_builder.sql().as_str()
    );
    let insert_query = insert_builder.build();
    insert_query.execute(&mut conn).await?;

    let mut select_builder =
        QueryBuilder::<sqlx_sqlserver::Mssql>::new("SELECT id, name FROM #qb_test WHERE id=");
    select_builder.push_bind(2_i32);
    let row = select_builder.build().fetch_one(&mut conn).await?;
    assert_eq!(2_i32, row.try_get::<i32, _>("id")?);
    assert_eq!("Bob", row.try_get::<String, _>("name")?);

    let mut issue_builder =
        QueryBuilder::<sqlx_sqlserver::Mssql>::new("SELECT id, name FROM #qb_test ");
    issue_builder
        .push("WHERE id=")
        .push_bind(1_i32)
        .push(" AND name=")
        .push_bind("Alice");
    assert_eq!(
        "SELECT id, name FROM #qb_test WHERE id=@p1 AND name=@p2",
        issue_builder.sql().as_str()
    );
    let issue_query = issue_builder.build();
    let row = issue_query.fetch_one(&mut conn).await?;
    assert_eq!(1_i32, row.try_get::<i32, _>("id")?);
    assert_eq!("Alice", row.try_get::<String, _>("name")?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn inspects_database_errors_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server database error inspection test").await?
    else {
        return Ok(());
    };

    let error = sqlx_core::query::query("select\nf")
        .execute(&mut conn)
        .await
        .expect_err("invalid query should fail");
    let database_error = error
        .into_database_error()
        .expect("invalid SQL should return a database error");

    assert_eq!("Invalid column name 'f'.", database_error.message());

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn any_fetches_bound_integer_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = any_test_conn("SQL Server Any bound argument test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT @p1")
        .bind(7_i32)
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(7_i32, row.try_get::<i32, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn any_fetches_text_blob_bool_and_typed_null_arguments_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = any_test_conn("SQL Server Any text/blob/bool/null argument test").await?
    else {
        return Ok(());
    };

    let bytes = vec![0xde, 0xad, 0xbe, 0xef];
    let row = sqlx_core::query::query("SELECT @p1, @p2, @p3, @p4")
        .bind("hello any")
        .bind(bytes.as_slice())
        .bind(true)
        .bind(Option::<String>::None)
        .fetch_one(&mut conn)
        .await?;

    assert_eq!("hello any", row.try_get::<String, _>(0)?);
    assert_eq!(bytes, row.try_get::<Vec<u8>, _>(1)?);
    assert!(row.try_get::<bool, _>(2)?);
    assert!(row.try_get_raw(3)?.is_null());

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn any_prepares_statement_metadata_when_configured() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(mut conn) = any_test_conn("SQL Server Any prepare test").await? else {
        return Ok(());
    };

    let statement = conn
        .prepare(sqlx_core::sql_str::SqlStr::from_static("SELECT 1 AS value"))
        .await?;

    assert_eq!(1, statement.columns().len());
    assert_eq!("value", statement.columns()[0].name());

    conn.close().await?;
    Ok(())
}

#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn any_fetches_select_one_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = any_test_conn("SQL Server Any query test").await? else {
        return Ok(());
    };

    let row = sqlx_core::query::query("SELECT 1")
        .fetch_one(&mut conn)
        .await?;

    assert_eq!(1_i32, row.try_get::<i32, _>(0)?);

    conn.close().await?;
    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "migrate"))]
#[tokio::test]
async fn runs_migration_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = native_test_conn("SQL Server migration test").await? else {
        return Ok(());
    };

    let table_name = "_sqlx_migrations_smoke";
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}_table"
        )))
        .await?;
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;

    let migration = sqlx_core::migrate::Migration::new(
        1,
        Cow::Borrowed("create smoke table"),
        sqlx_core::migrate::MigrationType::Simple,
        sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE TABLE {table_name}_table (id INT NOT NULL)"
        ))
        .into_sql_str(),
        false,
    );
    let mut migrator = sqlx_core::migrate::Migrator::with_migrations(vec![migration]);
    migrator.dangerous_set_table_name(table_name.to_owned());

    migrator.run_direct(None, &mut conn, false).await?;

    let exists: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT CONVERT(bit, CASE WHEN OBJECT_ID(N'_sqlx_migrations_smoke_table', N'U') IS NULL THEN 0 ELSE 1 END)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert!(exists);

    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}_table"
        )))
        .await?;
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;
    conn.close().await?;

    Ok(())
}

#[cfg(all(feature = "integration-tests", feature = "migrate"))]
#[tokio::test]
async fn any_runs_migration_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut conn) = any_migrate_test_conn("SQL Server Any migration test").await? else {
        return Ok(());
    };

    let table_name = "_sqlx_any_migrations_smoke";
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}_table"
        )))
        .await?;
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;

    let migration = sqlx_core::migrate::Migration::new(
        1,
        Cow::Borrowed("create any smoke table"),
        sqlx_core::migrate::MigrationType::Simple,
        sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE TABLE {table_name}_table (id INT NOT NULL)"
        ))
        .into_sql_str(),
        false,
    );
    let mut migrator = sqlx_core::migrate::Migrator::with_migrations(vec![migration]);
    migrator.dangerous_set_table_name(table_name.to_owned());

    migrator.run_direct(None, &mut conn, false).await?;

    let exists: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT CONVERT(bit, CASE WHEN OBJECT_ID(N'_sqlx_any_migrations_smoke_table', N'U') IS NULL THEN 0 ELSE 1 END)",
    )
    .fetch_one(&mut conn)
    .await?;

    assert!(exists);

    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}_table"
        )))
        .await?;
    let _ = conn
        .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table_name}"
        )))
        .await?;
    conn.close().await?;

    Ok(())
}
