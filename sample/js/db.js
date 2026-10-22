const { Pool } = require("pg");
const pool = new Pool();

// helper: parameter 0 reaches the SQL sink (found via function summary, across files)
function runQuery(sql) {
  return pool.query(sql);
}

module.exports = { runQuery };
