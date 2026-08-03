use rusqlite::{params, Connection, Result};
use std::path::Path;

pub struct ProjectDatabase {
    conn: Connection,
}

impl ProjectDatabase {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                schema_json TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                stats_json TEXT NOT NULL,
                fingerprint_json TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )",
            [],
        )?;

        // Upgrade older databases in place (SQLite has no ADD COLUMN IF NOT
        // EXISTS; ignore the error if the column already exists).
        let _ = self.conn.execute("ALTER TABLE scans ADD COLUMN fingerprint_json TEXT", []);

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS seeds (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL,
                field_name TEXT NOT NULL,
                type_name TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                UNIQUE(project_id, field_name, value),
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )",
            [],
        )?;

        Ok(())
    }

    pub fn get_or_create_project(&self, name: &str, url: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO projects (name, url) VALUES (?1, ?2)",
            params![name, url],
        )?;
        
        self.conn.query_row(
            "SELECT id FROM projects WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
    }

    pub fn save_scan(&self, project_id: i64, schema: &str, findings: &str, stats: &str, fingerprint: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scans (project_id, schema_json, findings_json, stats_json, fingerprint_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![project_id, schema, findings, stats, fingerprint],
        )?;
        Ok(())
    }

    /// Return the most recent cached scan's schema JSON and its timestamp for a
    /// project, if any. Used to serve scan/brute from cache instead of issuing
    /// another round of network requests. Findings are recomputed locally from
    /// the schema, so only `schema_json` is read back here.
    pub fn get_latest_scan(&self, project_id: i64) -> Result<Option<(String, String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT schema_json, timestamp, fingerprint_json FROM scans WHERE project_id = ?1 ORDER BY timestamp DESC, id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![project_id])?;
        match rows.next()? {
            Some(row) => Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?))),
            None => Ok(None),
        }
    }

    /// Row counts for `(projects, scans, seeds)` — used to summarize what a full purge will delete.
    pub fn counts(&self) -> Result<(usize, usize, usize)> {
        let projects: i64 = self.conn.query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0))?;
        let scans: i64 = self.conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))?;
        let seeds: i64 = self.conn.query_row("SELECT COUNT(*) FROM seeds", [], |r| r.get(0))?;
        Ok((projects as usize, scans as usize, seeds as usize))
    }

    /// Full reset: delete all projects, scans, and learned seeds (the `--purge-db` action), then
    /// reclaim the freed space. Irreversible — callers must confirm with the user first.
    pub fn reset_all(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scans", [])?;
        self.conn.execute("DELETE FROM seeds", [])?;
        self.conn.execute("DELETE FROM projects", [])?;
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// List every project that has at least one cached scan, newest scan first. Powers the
    /// visualizer's target switcher. Returns `(id, name, url, latest_scan_timestamp)`.
    pub fn list_projects_with_scans(&self) -> Result<Vec<(i64, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.name, p.url, MAX(s.timestamp) AS latest
             FROM projects p JOIN scans s ON s.project_id = p.id
             GROUP BY p.id
             ORDER BY latest DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Look up a project's `(name, url)` by id.
    pub fn get_project(&self, id: i64) -> Result<Option<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT name, url FROM projects WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => Ok(Some((row.get(0)?, row.get(1)?))),
            None => Ok(None),
        }
    }

    /// Delete all cached scans for a project (the `--purge-cache` action).
    /// Learned seeds are intentionally left intact. Returns the number of
    /// scan rows removed.
    pub fn purge_project_scans(&self, project_id: i64) -> Result<usize> {
        let removed = self.conn.execute(
            "DELETE FROM scans WHERE project_id = ?1",
            params![project_id],
        )?;
        Ok(removed)
    }

    pub fn save_seed(&self, project_id: i64, field: &str, type_name: &str, value: &str, source: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO seeds (project_id, field_name, type_name, value, source) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![project_id, field, type_name, value, source],
        )?;
        Ok(())
    }

    pub fn get_seeds(&self, project_id: i64) -> Result<Vec<crate::traffic::TrafficSeed>> {
        let mut stmt = self.conn.prepare(
            "SELECT field_name, type_name, value, source FROM seeds WHERE project_id = ?1"
        )?;
        let seed_iter = stmt.query_map(params![project_id], |row| {
            Ok(crate::traffic::TrafficSeed {
                field_name: row.get(0)?,
                type_name: row.get(1)?,
                value: row.get(2)?,
                source: row.get(3)?,
            })
        })?;

        let mut seeds = Vec::new();
        for seed in seed_iter {
            seeds.push(seed?);
        }
        Ok(seeds)
    }
}
