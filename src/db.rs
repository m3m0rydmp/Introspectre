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
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )",
            [],
        )?;

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

    pub fn save_scan(&self, project_id: i64, schema: &str, findings: &str, stats: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scans (project_id, schema_json, findings_json, stats_json) VALUES (?1, ?2, ?3, ?4)",
            params![project_id, schema, findings, stats],
        )?;
        Ok(())
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
