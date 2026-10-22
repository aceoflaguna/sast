import { defineQuery } from "../src/query";

export default defineQuery({
  id: "sql-injection",
  title: "SQL injection",
  severity: "critical",
  cwe: "CWE-89",
  description: "User-controlled data reaches a SQL execution call without escaping or parameterization.",
  taint: {
    sinks: {
      javascript: [
        { callee: /(^|\.)(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe|queryRaw)$/, args: [0], label: "SQL query" },
        { callee: /^(db|database|conn|connection|client|pool|sqlite|sql)\.(all|get|run|each|exec)$/, args: [0], label: "SQL query" },
      ],
      python: [{ callee: /(^|\.)(execute|executemany|executescript|raw|extra)$/, args: [0], label: "SQL execute" }],
      php: [
        { callee: /^(mysqli_query|mysql_query|pg_query|pg_send_query|sqlite_query|mssql_query|odbc_exec)$/, label: "SQL query" },
        // `$xp->query()` is DOMXPath, handled by xpath-injection
        { callee: /(^|\.)(query|exec|multi_query|real_query|prepare)$/, args: [0], when: (c) => !/(^|[.$])(xp|xpath|domxpath|dom)\w*\./i.test(c.callee), label: "SQL query" },
        { callee: /^DB\.(raw|select|statement|unprepared)$/, args: [0], label: "SQL query" },
      ],
      java: [
        { callee: /(^|\.)(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery)$/, args: [0], label: "JDBC/JPA query" },
        { callee: /(jdbcTemplate|JdbcTemplate|template)\.(query\w*|update|batchUpdate|execute)$/, args: [0], label: "JdbcTemplate query" },
      ],
      go: [
        // query is argument 0 (arguments after it are bind parameters, so they are NOT sinks)
        { callee: /(^|\.)(Query|QueryRow|Exec|Prepare|Raw|Where|Order|Having|Group|Joins|MustExec|NamedExec|NamedQuery)$/, args: [0], label: "database/sql, sqlx or GORM query" },
        { callee: /(^|\.)(QueryContext|QueryRowContext|ExecContext|PrepareContext)$/, args: [1], label: "database/sql query" },
        { callee: /^(db|tx|conn|sqlx|dbx)\.(Get|Select)$/, args: [1], label: "sqlx query" },
        { callee: /^(db|tx|conn|sqlx|dbx)\.(GetContext|SelectContext)$/, args: [2], label: "sqlx query" },
      ],
      csharp: [
        { callee: /^new (SqlCommand|SqlDataAdapter|OleDbCommand|OdbcCommand|NpgsqlCommand|MySqlCommand|SQLiteCommand|SqliteCommand|OracleCommand|FbCommand)$/, args: [0], label: "ADO.NET command text" },
        { assign: /\.CommandText$/, label: "CommandText assignment" },
        { callee: /(^|\.)(ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteSqlCommand|FromSqlRaw|SqlQuery|SqlQueryRaw|Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QuerySingle|QuerySingleOrDefault|Execute|ExecuteAsync|ExecuteScalar)$/, args: [0], label: "Dapper/EF raw SQL" },
      ],
      ruby: [{ callee: /(^|\.)(execute|exec_query|select_all|select_one|select_rows|select_value|find_by_sql|count_by_sql|where|having|order|group|joins|pluck|select|from|reorder|delete_all|update_all|exists\?|lock|exec_update|exec_delete)$/, args: [0], label: "ActiveRecord raw SQL" }],
    },
    sanitizers: {
      javascript: [/(^|\.)(escape|escapeId|escapeLiteral)$/],
      python: [/(^|\.)(escape_string|literal|quote_name)$/],
      php: [/(^|\.)(\w*escape_string|addslashes|quote|real_escape_string)$/],
      java: [/(^|\.)encodeForSQL$/],
      ruby: [/(^|\.)(sanitize_sql\w*|quote|quote_string)$/],
    },
  },
  message: (f) => `User input flows into ${f.label} (line ${f.source.line} → line ${f.sink.line}); use parameterized queries.`,
});
