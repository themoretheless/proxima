//! The traffic archive: every flow that finished, on disk, queryable with SQL.
//!
//! The ring buffer in [`super::FlowStore`] answers "what just happened". It
//! cannot answer "which hosts served the most 5xx this afternoon", because it
//! holds a few thousand flows, in memory, and forgets all of them on exit. This
//! module is the other half: a flow that reaches a terminal state is copied into
//! a DuckDB file under the data directory and stays there.
//!
//! DuckDB rather than SQLite because every question worth asking here is an
//! aggregate over a column, which is what a columnar engine is for, and because
//! it is embedded, so there is nothing to install or administer.
//!
//! Three rules shape the design, in this order:
//!
//! 1. **The proxy never waits for the archive.** Writes go down a bounded
//!    channel to a thread of its own. When that channel is full the row is
//!    dropped and counted, because a debugging proxy that stalls a phone's
//!    request to finish a disk write is worse than one with a gap in its
//!    statistics.
//! 2. **Bodies are not archived**, only their sizes and content types. Bodies
//!    are the one part of a capture with no ceiling on total size, and a file
//!    that grows without bound is how this feature would end up deleted.
//! 3. **Submitted SQL is read only and cannot touch the filesystem.** The UI
//!    port has no authentication and listens on every interface, so an endpoint
//!    that runs SQL is an endpoint that runs SQL for anyone on the network. See
//!    [`is_read_only`] and the connection settings in `open`.
//!
//! Without the `archive` feature this module still compiles, and [`Archive::open`]
//! reports that the binary was built without it. Callers then have one shape to
//! handle rather than two.

use std::path::Path;

use serde::Serialize;

/// Rows returned to a caller of [`Archive::query`]. Kept well under what a
/// browser will render, since the point of a query is a summary and anything
/// larger is a mistake being made interactively.
pub const MAX_QUERY_ROWS: usize = 5_000;

/// One row of the archive, flattened out of a [`crate::types::Flow`].
///
/// Built while the flow store is locked and sent on afterwards, so it holds
/// owned values rather than borrowing anything from the store.
#[derive(Debug, Clone)]
pub struct ArchiveRow {
    pub seq: u64,
    pub id: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub intercepted: bool,
    pub method: String,
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    pub url: String,
    pub http_version: &'static str,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub started_ms: u64,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    pub likely_pinning: bool,
    pub client: String,
    pub replay_of: Option<String>,
    /// Headers as a JSON array of `[name, value]` pairs, so DuckDB's JSON
    /// functions can reach into them without a second table and a join.
    pub request_headers: String,
    pub response_headers: Option<String>,
    pub ws_messages: Option<u64>,
}

/// The answer to a query: column names, rows of JSON values, and whether the
/// result was cut off at [`MAX_QUERY_ROWS`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub truncated: bool,
}

/// Rejects anything that is not a single read only statement.
///
/// This is a whitelist of leading keywords plus a ban on statement separators,
/// not an attempt to parse SQL. DuckDB will happily `COPY ... TO '/etc/passwd'`
/// or `ATTACH` another database, and the connection settings block the
/// filesystem separately, but neither of those should be reachable at all from
/// an unauthenticated port, so the front door is shut here as well.
pub fn is_read_only(sql: &str) -> bool {
    let trimmed = sql.trim().trim_end_matches(';');
    if trimmed.is_empty() {
        return false;
    }
    // A second statement would run with the same privileges as the first, and
    // the leading-keyword check only ever looks at the first.
    if trimmed.contains(';') {
        return false;
    }
    let head = trimmed
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|word| !word.is_empty())
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        head.as_str(),
        "SELECT" | "WITH" | "DESCRIBE" | "SUMMARIZE" | "EXPLAIN" | "SHOW" | "TABLE" | "FROM"
    )
}

#[cfg(not(feature = "archive"))]
mod imp {
    use super::*;
    use anyhow::{anyhow, Result};

    /// Stand-in for a build without the `archive` feature. It exists so callers
    /// have one type to name; nothing can construct it.
    #[derive(Clone)]
    pub struct Archive {
        _never: std::convert::Infallible,
    }

    impl Archive {
        pub fn open(_path: &Path) -> Result<Self> {
            Err(anyhow!(
                "this build has no traffic archive. Rebuild with --features archive to record \
                 flows to disk and query them."
            ))
        }

        pub fn record(&self, _row: ArchiveRow) {}

        pub async fn query(&self, _sql: String) -> Result<QueryResult> {
            unreachable!("an Archive cannot be constructed without the archive feature")
        }

        pub async fn stats(&self) -> Result<serde_json::Value> {
            unreachable!("an Archive cannot be constructed without the archive feature")
        }

        pub fn dropped(&self) -> u64 {
            0
        }

        pub fn close(&self) {}
    }
}

#[cfg(feature = "archive")]
mod imp {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{anyhow, Context, Result};
    use duckdb::types::Value as DuckValue;
    use duckdb::{params, Config as DuckConfig, Connection};
    use serde_json::{json, Value};
    use tokio::sync::oneshot;
    use tracing::{debug, info, warn};

    /// Deep enough to absorb a burst from a page load, shallow enough that a
    /// stalled writer costs a bounded amount of memory rather than the machine.
    const QUEUE_CAPACITY: usize = 8_192;
    /// Rows per transaction. Larger batches are faster per row, but a batch is
    /// also the window in which a crash loses data.
    const BATCH_ROWS: usize = 256;
    /// How long a partial batch waits before being written anyway, so a quiet
    /// proxy still has its last few flows on disk.
    const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS flows_raw (
          session          VARCHAR NOT NULL,
          seq              BIGINT  NOT NULL,
          id               VARCHAR NOT NULL,
          kind             VARCHAR NOT NULL,
          state            VARCHAR NOT NULL,
          intercepted      BOOLEAN NOT NULL,
          method           VARCHAR NOT NULL,
          scheme           VARCHAR NOT NULL,
          host             VARCHAR NOT NULL,
          port             INTEGER NOT NULL,
          authority        VARCHAR NOT NULL,
          path             VARCHAR NOT NULL,
          url              VARCHAR NOT NULL,
          http_version     VARCHAR NOT NULL,
          status           INTEGER,
          content_type     VARCHAR,
          request_bytes    BIGINT  NOT NULL,
          response_bytes   BIGINT  NOT NULL,
          started_ms       BIGINT  NOT NULL,
          duration_ms      BIGINT,
          error            VARCHAR,
          likely_pinning   BOOLEAN NOT NULL,
          client           VARCHAR NOT NULL,
          replay_of        VARCHAR,
          request_headers  VARCHAR NOT NULL,
          response_headers VARCHAR,
          ws_messages      BIGINT
        );

        -- The view is what anyone should query. It adds the two derived columns
        -- every question needs and nobody wants to retype: a real timestamp
        -- instead of epoch milliseconds, and the status class to group by.
        CREATE OR REPLACE VIEW flows AS
          SELECT *,
                 epoch_ms(started_ms) AS started,
                 CAST(status / 100 AS INTEGER) * 100 AS status_class,
                 request_bytes + response_bytes AS bytes
          FROM flows_raw;
    ";

    const INSERT: &str = "INSERT INTO flows_raw VALUES (\
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    enum Job {
        Insert(Box<ArchiveRow>),
        Query {
            sql: String,
            reply: oneshot::Sender<Result<QueryResult, String>>,
        },
        Stats {
            reply: oneshot::Sender<Result<Value, String>>,
        },
    }

    /// A handle on the archive. Cloning gives another handle on the same writer
    /// thread, not another connection.
    #[derive(Clone)]
    pub struct Archive {
        inner: Arc<Inner>,
    }

    struct Inner {
        jobs: SyncSender<Job>,
        dropped: AtomicU64,
        session: String,
    }

    impl Archive {
        /// Opens or creates the archive at `path` and starts its writer thread.
        ///
        /// Fails rather than falling back to memory: a user who asked for an
        /// archive and silently got none would find out weeks later, when the
        /// question they wanted answering had already gone by.
        pub fn open(path: &Path) -> Result<Self> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("creating the archive directory {}", parent.display())
                })?;
            }

            // `enable_external_access` off is the setting that matters. It stops
            // SQL from reading or writing files and from opening http/s3 URLs,
            // which is what turns an unauthenticated query endpoint from a
            // reporting tool into a way to read the machine. `lock_configuration`
            // then stops submitted SQL from turning it back on with a SET.
            let config = DuckConfig::default()
                .enable_external_access(false)
                .with_context(|| "refusing external access")?;
            let connection = Connection::open_with_flags(path, config)
                .with_context(|| format!("opening the archive at {}", path.display()))?;
            connection
                .execute_batch(SCHEMA)
                .context("creating the archive schema")?;
            connection
                .execute_batch("SET lock_configuration = true;")
                .context("locking the archive configuration")?;

            let session = super::super::new_id();
            let (jobs, rx) = sync_channel::<Job>(QUEUE_CAPACITY);
            let thread_session = session.clone();
            std::thread::Builder::new()
                .name("proxima-archive".to_string())
                .spawn(move || writer_loop(connection, rx, thread_session))
                .context("starting the archive writer thread")?;

            info!(path = %path.display(), session = %session, "traffic archive open");
            Ok(Self {
                inner: Arc::new(Inner {
                    jobs,
                    dropped: AtomicU64::new(0),
                    session,
                }),
            })
        }

        /// Queues a finished flow. Never blocks: a full queue drops the row and
        /// counts it, which [`Archive::dropped`] reports.
        pub fn record(&self, row: ArchiveRow) {
            if self.inner.jobs.try_send(Job::Insert(Box::new(row))).is_err() {
                let dropped = self.inner.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // One line per drop would itself become the bottleneck, so this
                // reports at the powers of ten.
                if is_power_of_ten(dropped) {
                    warn!(
                        dropped,
                        "the archive writer is behind, so flows are missing from it"
                    );
                }
            }
        }

        /// Runs a read only statement. Rejects anything else without going near
        /// the database, see [`is_read_only`].
        pub async fn query(&self, sql: String) -> Result<QueryResult> {
            if !is_read_only(&sql) {
                return Err(anyhow!(
                    "the archive answers one read only statement at a time: SELECT, WITH, \
                     DESCRIBE, SUMMARIZE, EXPLAIN or SHOW."
                ));
            }
            let (reply, answer) = oneshot::channel();
            self.submit(Job::Query { sql, reply })?;
            match answer.await {
                Ok(Ok(result)) => Ok(result),
                Ok(Err(message)) => Err(anyhow!(message)),
                Err(_) => Err(anyhow!("the archive stopped before answering")),
            }
        }

        /// The canned report: totals, busiest hosts, status classes, slowest
        /// paths. What most people want the archive for, without writing SQL.
        pub async fn stats(&self) -> Result<Value> {
            let (reply, answer) = oneshot::channel();
            self.submit(Job::Stats { reply })?;
            match answer.await {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(message)) => Err(anyhow!(message)),
                Err(_) => Err(anyhow!("the archive stopped before answering")),
            }
        }

        /// Flows lost to a full queue since start.
        pub fn dropped(&self) -> u64 {
            self.inner.dropped.load(Ordering::Relaxed)
        }

        /// The id this run tags its rows with, so one session can be told from
        /// another in a file that outlives both.
        pub fn session(&self) -> &str {
            &self.inner.session
        }

        pub fn close(&self) {}

        /// Queries go down the same queue as inserts, so they see every row that
        /// was recorded before them. A full queue means the writer is saturated,
        /// and waiting behind thousands of pending inserts would look like a
        /// hang, so this refuses instead.
        fn submit(&self, job: Job) -> Result<()> {
            self.inner.jobs.try_send(job).map_err(|_| {
                anyhow!("the archive is busy writing and cannot answer a query right now")
            })
        }
    }

    /// Owns the connection. Everything that touches DuckDB happens here, on one
    /// thread, so the connection needs no lock and inserts need no coordination.
    fn writer_loop(connection: Connection, rx: std::sync::mpsc::Receiver<Job>, session: String) {
        let mut pending: Vec<ArchiveRow> = Vec::with_capacity(BATCH_ROWS);
        loop {
            match rx.recv_timeout(FLUSH_INTERVAL) {
                Ok(Job::Insert(row)) => {
                    pending.push(*row);
                    if pending.len() >= BATCH_ROWS {
                        flush(&connection, &session, &mut pending);
                    }
                }
                Ok(Job::Query { sql, reply }) => {
                    // Before answering, so a query sees the flows the caller
                    // just watched go by rather than the ones from a moment ago.
                    flush(&connection, &session, &mut pending);
                    let _ = reply.send(guard(|| run_query(&connection, &sql)));
                }
                Ok(Job::Stats { reply }) => {
                    flush(&connection, &session, &mut pending);
                    let _ = reply.send(guard(|| run_stats(&connection)));
                }
                Err(RecvTimeoutError::Timeout) => flush(&connection, &session, &mut pending),
                // Every handle is gone, so nothing more will arrive.
                Err(RecvTimeoutError::Disconnected) => {
                    flush(&connection, &session, &mut pending);
                    debug!("archive writer stopping");
                    return;
                }
            }
        }
    }

    /// Runs a query and turns both failures and panics into a message.
    ///
    /// The panic half is not defensive habit. Submitted SQL reaches a large C++
    /// engine through bindings that panic on a few shapes of misuse, and a panic
    /// here would take the writer thread with it, so one bad query in the box
    /// would silently end archiving for the rest of the run.
    fn guard<T>(work: impl FnOnce() -> Result<T>) -> Result<T, String> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(format!("{err:#}")),
            Err(_) => Err("the archive could not run that statement".to_string()),
        }
    }

    /// Writes a batch in one transaction. A failure is logged and the batch
    /// dropped: retrying a statement that DuckDB refused would refuse again, and
    /// the proxy must not stop capturing because its archive is unhappy.
    fn flush(connection: &Connection, session: &str, pending: &mut Vec<ArchiveRow>) {
        if pending.is_empty() {
            return;
        }
        let count = pending.len();
        match insert_batch(connection, session, pending) {
            Ok(()) => debug!(rows = count, "archived a batch of flows"),
            Err(err) => warn!(rows = count, error = %format!("{err:#}"), "archiving a batch failed"),
        }
        pending.clear();
    }

    fn insert_batch(
        connection: &Connection,
        session: &str,
        pending: &[ArchiveRow],
    ) -> Result<()> {
        connection.execute_batch("BEGIN TRANSACTION;")?;
        let result = (|| -> Result<()> {
            let mut statement = connection.prepare(INSERT)?;
            for row in pending {
                statement.execute(params![
                    session,
                    as_i64(row.seq),
                    row.id,
                    row.kind,
                    row.state,
                    row.intercepted,
                    row.method,
                    row.scheme,
                    row.host,
                    i32::from(row.port),
                    row.authority,
                    row.path,
                    row.url,
                    row.http_version,
                    row.status.map(i32::from),
                    row.content_type,
                    as_i64(row.request_bytes),
                    as_i64(row.response_bytes),
                    as_i64(row.started_ms),
                    row.duration_ms.map(as_i64),
                    row.error,
                    row.likely_pinning,
                    row.client,
                    row.replay_of,
                    row.request_headers,
                    row.response_headers,
                    row.ws_messages.map(as_i64),
                ])?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                connection.execute_batch("COMMIT;")?;
                Ok(())
            }
            Err(err) => {
                // Leaving the transaction open would fail every later batch too.
                if let Err(rollback) = connection.execute_batch("ROLLBACK;") {
                    warn!(error = %rollback, "the archive transaction could not be rolled back");
                }
                Err(err)
            }
        }
    }

    /// DuckDB has no unsigned 64 bit column, and a byte count that overflows an
    /// i64 is not a number this proxy can have produced.
    fn as_i64(value: u64) -> i64 {
        i64::try_from(value).unwrap_or(i64::MAX)
    }

    fn run_query(connection: &Connection, sql: &str) -> Result<QueryResult> {
        let mut statement = connection.prepare(sql)?;
        let mut rows = statement.query([])?;
        // Column names come from the executed statement, not the prepared one:
        // asking earlier panics inside duckdb rather than returning an error.
        let columns: Vec<String> = rows
            .as_ref()
            .map(|statement| {
                statement
                    .column_names()
                    .into_iter()
                    .map(|name| name.to_string())
                    .collect()
            })
            .unwrap_or_default();
        let width = columns.len();

        let mut out: Vec<Vec<Value>> = Vec::new();
        let mut truncated = false;
        while let Some(row) = rows.next()? {
            if out.len() >= MAX_QUERY_ROWS {
                truncated = true;
                break;
            }
            let mut values = Vec::with_capacity(width);
            for index in 0..width {
                values.push(to_json(row.get::<_, DuckValue>(index)?));
            }
            out.push(values);
        }

        Ok(QueryResult {
            columns,
            rows: out,
            truncated,
        })
    }

    /// Fixed queries behind `/api/stats`. Each is a shape people ask for by
    /// hand within a minute of finding the query box.
    fn run_stats(connection: &Connection) -> Result<Value> {
        let totals = run_query(
            connection,
            "SELECT count(*) AS flows,
                    count(DISTINCT host) AS hosts,
                    sum(request_bytes) AS request_bytes,
                    sum(response_bytes) AS response_bytes,
                    count(*) FILTER (WHERE status >= 400 OR error IS NOT NULL) AS failures,
                    min(started) AS first_seen,
                    max(started) AS last_seen
             FROM flows",
        )?;
        let hosts = run_query(
            connection,
            "SELECT host,
                    count(*) AS flows,
                    sum(bytes) AS bytes,
                    count(*) FILTER (WHERE status >= 400 OR error IS NOT NULL) AS failures,
                    CAST(median(duration_ms) AS BIGINT) AS median_ms,
                    CAST(quantile_cont(duration_ms, 0.95) AS BIGINT) AS p95_ms
             FROM flows
             GROUP BY host
             ORDER BY flows DESC
             LIMIT 20",
        )?;
        let statuses = run_query(
            connection,
            "SELECT coalesce(CAST(status_class AS VARCHAR), 'no response') AS class,
                    count(*) AS flows
             FROM flows
             GROUP BY class
             ORDER BY class",
        )?;
        let slowest = run_query(
            connection,
            "SELECT host,
                    path,
                    count(*) AS flows,
                    CAST(quantile_cont(duration_ms, 0.95) AS BIGINT) AS p95_ms
             FROM flows
             WHERE duration_ms IS NOT NULL
             GROUP BY host, path
             HAVING count(*) >= 3
             ORDER BY p95_ms DESC
             LIMIT 20",
        )?;
        let heaviest = run_query(
            connection,
            "SELECT host,
                    path,
                    count(*) AS flows,
                    sum(response_bytes) AS response_bytes
             FROM flows
             GROUP BY host, path
             ORDER BY response_bytes DESC
             LIMIT 20",
        )?;

        Ok(json!({
            "totals": totals,
            "hosts": hosts,
            "statuses": statuses,
            "slowest": slowest,
            "heaviest": heaviest,
        }))
    }

    /// DuckDB value to JSON, for a browser that has to render it.
    ///
    /// Integers wider than an f64 can hold, decimals and intervals become
    /// strings rather than silently losing precision on the way through
    /// JavaScript's only number type.
    fn to_json(value: DuckValue) -> Value {
        match value {
            DuckValue::Null => Value::Null,
            DuckValue::Boolean(v) => Value::Bool(v),
            DuckValue::TinyInt(v) => json!(v),
            DuckValue::SmallInt(v) => json!(v),
            DuckValue::Int(v) => json!(v),
            DuckValue::BigInt(v) => json!(v),
            DuckValue::UTinyInt(v) => json!(v),
            DuckValue::USmallInt(v) => json!(v),
            DuckValue::UInt(v) => json!(v),
            DuckValue::UBigInt(v) => json!(v),
            // `sum()` over a BIGINT column widens to HUGEINT, so this is what a
            // byte total comes back as, not an exotic case. JSON has no 128 bit
            // number and JavaScript has no integer wider than 53 bits, so
            // anything that does not fit becomes a string rather than a wrong
            // number.
            DuckValue::HugeInt(v) => match i64::try_from(v) {
                Ok(narrow) => json!(narrow),
                Err(_) => Value::String(v.to_string()),
            },
            DuckValue::Float(v) => json!(v),
            DuckValue::Double(v) => json!(v),
            DuckValue::Text(v) => Value::String(v),
            DuckValue::Blob(v) => Value::String(format!("{} bytes", v.len())),
            DuckValue::List(items) => Value::Array(items.into_iter().map(to_json).collect()),
            DuckValue::Timestamp(unit, value) => Value::String(timestamp(unit, value)),
            DuckValue::Date32(days) => Value::String(date(days)),
            other => Value::String(format!("{other:?}")),
        }
    }

    /// RFC 3339, which is what the browser's `Date` takes and what a person
    /// reading a result table expects to see. Anything the conversion cannot
    /// represent falls back to the raw count rather than inventing a date.
    fn timestamp(unit: duckdb::types::TimeUnit, value: i64) -> String {
        let nanos = match unit {
            duckdb::types::TimeUnit::Second => i128::from(value) * 1_000_000_000,
            duckdb::types::TimeUnit::Millisecond => i128::from(value) * 1_000_000,
            duckdb::types::TimeUnit::Microsecond => i128::from(value) * 1_000,
            duckdb::types::TimeUnit::Nanosecond => i128::from(value),
        };
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .and_then(|at| at.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_else(|| value.to_string())
    }

    /// Days since the epoch, as DuckDB stores a DATE.
    fn date(days: i32) -> String {
        time::Date::from_calendar_date(1970, time::Month::January, 1)
            .ok()
            .and_then(|epoch| epoch.checked_add(time::Duration::days(i64::from(days))))
            .map(|date| date.to_string())
            .unwrap_or_else(|| days.to_string())
    }

    /// `1`, `10`, `100`, and so on. Used to thin out a log line that would
    /// otherwise be written once per dropped row.
    fn is_power_of_ten(mut value: u64) -> bool {
        if value == 0 {
            return false;
        }
        while value % 10 == 0 {
            value /= 10;
        }
        value == 1
    }
}

pub use imp::Archive;

#[cfg(test)]
mod read_only_tests {
    use super::is_read_only;

    #[test]
    fn reading_is_allowed_and_writing_is_not() {
        assert!(is_read_only("SELECT 1"));
        assert!(is_read_only("  select host from flows  "));
        assert!(is_read_only("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(is_read_only("(SELECT 1)"));
        assert!(is_read_only("SUMMARIZE flows"));
        assert!(is_read_only("FROM flows SELECT host"));

        assert!(!is_read_only(""));
        assert!(!is_read_only("   "));
        assert!(!is_read_only("DELETE FROM flows_raw"));
        assert!(!is_read_only("DROP VIEW flows"));
        assert!(!is_read_only("INSERT INTO flows_raw VALUES (1)"));
        assert!(!is_read_only("ATTACH 'other.db'"));
        assert!(!is_read_only("COPY flows TO '/tmp/out.csv'"));
        assert!(!is_read_only("SET enable_external_access = true"));
    }

    #[test]
    fn a_second_statement_cannot_ride_along_with_a_select() {
        assert!(
            !is_read_only("SELECT 1; DROP VIEW flows"),
            "only the first statement is ever checked, so a second one must be refused outright"
        );
        assert!(
            is_read_only("SELECT 1;"),
            "a trailing semicolon is punctuation, not a second statement"
        );
    }
}

#[cfg(all(test, feature = "archive"))]
mod tests {
    use super::*;
    use crate::capture::{FlowInit, FlowStore};
    use crate::types::{
        FlowClient, FlowError, FlowKind, FlowRequest, FlowResponse, FlowServer, HttpVersion, Scheme,
    };

    fn store(dir: &Path, max_flows: usize) -> (FlowStore, Archive) {
        let archive = Archive::open(&dir.join("capture.duckdb")).expect("opening the archive");
        let store = FlowStore::new(max_flows, 1024, 64 * 1024).with_archive(archive.clone());
        (store, archive)
    }

    fn init(method: &str, host: &str, path: &str) -> FlowInit {
        FlowInit {
            kind: FlowKind::Http,
            intercepted: true,
            request: FlowRequest {
                method: method.to_string(),
                url: format!("https://{host}{path}"),
                scheme: Scheme::Https,
                authority: host.to_string(),
                host: host.to_string(),
                port: 443,
                path: path.to_string(),
                http_version: HttpVersion::Http11,
                headers: vec![("accept".into(), "application/json".into())],
                body: None,
            },
            client: FlowClient {
                address: "192.168.1.20".into(),
                port: 51314,
            },
            server: FlowServer::default(),
            replay_of: None,
        }
    }

    fn respond(store: &FlowStore, id: &str, status: u16) {
        store.update(id, |flow| {
            flow.response = Some(FlowResponse {
                status,
                status_text: String::new(),
                http_version: HttpVersion::Http11,
                headers: vec![("content-type".into(), "application/json".into())],
                body: None,
            });
        });
        store.finish(id);
    }

    /// The first column of the first row, as an integer. Every count in these
    /// tests is that shape.
    fn count(result: &QueryResult) -> i64 {
        result
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|value| value.as_i64())
            .expect("a query that counts should answer with one number")
    }

    #[tokio::test]
    async fn finished_flows_can_be_counted_and_grouped() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);

        for _ in 0..3 {
            let id = store.create(init("GET", "api.example.com", "/users"));
            respond(&store, &id, 200);
        }
        let failed = store.create(init("POST", "cdn.example.com", "/upload"));
        respond(&store, &failed, 503);

        let total = archive
            .query("SELECT count(*) FROM flows".into())
            .await
            .expect("counting");
        assert_eq!(count(&total), 4, "not every finished flow reached the disk");

        let by_host = archive
            .query(
                "SELECT host, count(*) AS n FROM flows GROUP BY host ORDER BY n DESC".into(),
            )
            .await
            .expect("grouping");
        assert_eq!(by_host.columns, vec!["host", "n"]);
        assert_eq!(by_host.rows.len(), 2);
        assert_eq!(by_host.rows[0][0], serde_json::json!("api.example.com"));
        assert_eq!(by_host.rows[0][1], serde_json::json!(3));

        // The derived column exists so nobody has to write the arithmetic, and
        // grouping by it is the single most common question asked here.
        let failures = archive
            .query("SELECT count(*) FROM flows WHERE status_class = 500".into())
            .await
            .expect("status class");
        assert_eq!(count(&failures), 1);
    }

    #[tokio::test]
    async fn a_failed_flow_keeps_its_error_and_its_pinning_flag() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);

        let id = store.create(init("GET", "pinned.example.com", "/"));
        store.fail(
            &id,
            FlowError {
                message: "the client rejected our certificate".into(),
                code: None,
                likely_pinning: Some(true),
            },
        );

        let result = archive
            .query("SELECT host, state, error, likely_pinning FROM flows".into())
            .await
            .expect("querying");
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][1], serde_json::json!("error"));
        assert_eq!(
            result.rows[0][2],
            serde_json::json!("the client rejected our certificate")
        );
        assert_eq!(
            result.rows[0][3],
            serde_json::json!(true),
            "a pinned host is the one failure worth finding again later"
        );
    }

    #[tokio::test]
    async fn a_flow_evicted_before_it_finished_is_still_recorded() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A ring buffer of one: creating the second flow evicts the first while
        // it is still pending.
        let (store, archive) = store(dir.path(), 1);

        store.create(init("GET", "first.example.com", "/"));
        let second = store.create(init("GET", "second.example.com", "/"));
        respond(&store, &second, 200);

        let result = archive
            .query("SELECT host, state FROM flows ORDER BY seq".into())
            .await
            .expect("querying");
        assert_eq!(
            result.rows.len(),
            2,
            "the evicted flow was lost, and the archive is the only place it could have gone"
        );
        assert_eq!(result.rows[0][0], serde_json::json!("first.example.com"));
        assert_eq!(result.rows[0][1], serde_json::json!("pending"));
    }

    #[tokio::test]
    async fn a_flow_is_never_written_twice() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 1);

        // Finished, then evicted by the next flow, which is both paths that
        // archive a flow firing on the same one.
        let id = store.create(init("GET", "api.example.com", "/once"));
        respond(&store, &id, 200);
        let next = store.create(init("GET", "api.example.com", "/twice"));
        respond(&store, &next, 200);

        let result = archive
            .query("SELECT count(*) FROM flows WHERE path = '/once'".into())
            .await
            .expect("counting");
        assert_eq!(count(&result), 1, "the flow was archived by both paths");
    }

    #[tokio::test]
    async fn clearing_the_list_leaves_the_archive_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);

        let done = store.create(init("GET", "api.example.com", "/done"));
        respond(&store, &done, 200);
        // Still in flight, so nothing has archived it yet.
        store.create(init("GET", "api.example.com", "/live"));

        store.clear();
        assert!(store.is_empty());

        let result = archive
            .query("SELECT count(*) FROM flows".into())
            .await
            .expect("counting");
        assert_eq!(
            count(&result),
            2,
            "clearing the in-memory list is not a request to destroy the history"
        );
    }

    #[tokio::test]
    async fn the_archive_survives_being_reopened() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capture.duckdb");
        {
            let archive = Archive::open(&path).expect("opening");
            let store = FlowStore::new(100, 1024, 64 * 1024).with_archive(archive.clone());
            let id = store.create(init("GET", "api.example.com", "/users"));
            respond(&store, &id, 200);
            // Forces the pending batch out before the connection goes away.
            archive
                .query("SELECT 1".into())
                .await
                .expect("flushing through a query");
        }

        let reopened = Archive::open(&path).expect("reopening");
        let result = reopened
            .query("SELECT count(*) FROM flows".into())
            .await
            .expect("counting");
        assert_eq!(
            count(&result),
            1,
            "the whole point of a file is that a restart can still see it"
        );
    }

    #[tokio::test]
    async fn sessions_tell_one_run_from_another() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("capture.duckdb");

        let first = Archive::open(&path).expect("opening");
        let store = FlowStore::new(100, 1024, 64 * 1024).with_archive(first.clone());
        let id = store.create(init("GET", "api.example.com", "/users"));
        respond(&store, &id, 200);

        let result = first
            .query(format!(
                "SELECT count(*) FROM flows WHERE session = '{}'",
                first.session()
            ))
            .await
            .expect("counting");
        assert_eq!(count(&result), 1);
    }

    #[tokio::test]
    async fn writing_and_reading_the_filesystem_are_both_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_store, archive) = store(dir.path(), 100);

        // Refused before the database sees it.
        let write = archive.query("DELETE FROM flows_raw".into()).await;
        assert!(write.is_err(), "a write was accepted");

        // Reads are allowed through, so this one has to be stopped by DuckDB's
        // own settings. This endpoint has no authentication in front of it, and
        // reading a local file through it would be the whole machine.
        let read_a_file = archive
            .query("SELECT * FROM read_csv('/etc/passwd')".into())
            .await;
        assert!(
            read_a_file.is_err(),
            "SQL reached the filesystem, which turns an unauthenticated query box into a file \
             browser"
        );

        // And the setting that stops it cannot be turned back on.
        let unlock = archive
            .query("SELECT 1 FROM (SET enable_external_access = true)".into())
            .await;
        assert!(unlock.is_err());
    }

    #[tokio::test]
    async fn the_canned_report_covers_the_questions_people_ask_first() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);

        for path in ["/a", "/b", "/c"] {
            let id = store.create(init("GET", "api.example.com", path));
            respond(&store, &id, 200);
        }
        let bad = store.create(init("GET", "api.example.com", "/d"));
        respond(&store, &bad, 500);

        let stats = archive.stats().await.expect("stats");
        for section in ["totals", "hosts", "statuses", "slowest", "heaviest"] {
            assert!(
                stats.get(section).is_some(),
                "the report is missing its {section} section"
            );
        }

        let totals = &stats["totals"]["rows"][0];
        assert_eq!(totals[0], serde_json::json!(4), "flow count");
        assert_eq!(totals[1], serde_json::json!(1), "distinct hosts");
        assert_eq!(totals[4], serde_json::json!(1), "failures");
        assert!(
            totals[3].is_number(),
            "a byte total has to arrive as a number a chart can use, not as a rendering of \
             whatever type DuckDB widened it to: {}",
            totals[3]
        );
    }

    #[tokio::test]
    async fn a_summed_byte_count_is_a_number() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);
        let id = store.create(init("GET", "api.example.com", "/users"));
        respond(&store, &id, 200);

        // sum() widens BIGINT to HUGEINT, which is the one type every totalling
        // query in this file goes through.
        let result = archive
            .query("SELECT sum(bytes) FROM flows".into())
            .await
            .expect("summing");
        assert!(
            result.rows[0][0].is_number(),
            "got {} instead of a number",
            result.rows[0][0]
        );
    }

    #[tokio::test]
    async fn timestamps_come_back_as_dates_rather_than_as_a_debug_dump() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (store, archive) = store(dir.path(), 100);
        let id = store.create(init("GET", "api.example.com", "/users"));
        respond(&store, &id, 200);

        let result = archive
            .query("SELECT started, CAST(started AS DATE) AS day FROM flows".into())
            .await
            .expect("querying");
        let started = result.rows[0][0].as_str().expect("a string");
        assert!(
            started.starts_with("20") && started.contains('T') && started.ends_with('Z'),
            "a timestamp has to be readable and parseable by a browser, got {started}"
        );
        let day = result.rows[0][1].as_str().expect("a string");
        assert_eq!(day.len(), 10, "a date should read as YYYY-MM-DD, got {day}");
    }

    #[tokio::test]
    async fn a_broken_query_answers_with_the_reason() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_store, archive) = store(dir.path(), 100);

        let err = archive
            .query("SELECT nonexistent_column FROM flows".into())
            .await
            .expect_err("that column does not exist");
        let text = format!("{err:#}");
        assert!(
            text.contains("nonexistent_column"),
            "the error has to name what was wrong or a query cannot be fixed: {text}"
        );
    }
}
