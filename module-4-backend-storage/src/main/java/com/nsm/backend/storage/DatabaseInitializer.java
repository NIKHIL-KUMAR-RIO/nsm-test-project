package com.nsm.backend.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DatabaseInitializer.class);
    private final JdbcTemplate jdbcTemplate;

    public DatabaseInitializer(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(String... args) {
        log.info("Initializing SQLite database schema for NSM Platform...");

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                details TEXT,
                confidence REAL,
                detection_method TEXT
            );
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                flags TEXT,
                length INTEGER
            );
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'ANALYST',
                account_status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                last_login TEXT
            );
        """);

        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp DESC);");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);");
        jdbcTemplate.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);");

        // Remove legacy default 'admin' account if present
        jdbcTemplate.update("DELETE FROM users WHERE LOWER(username) = 'admin' OR LOWER(email) = 'admin@netsentinel.local'");

        log.info("SQLite schema initialized successfully (tables: alerts, packets, users).");
    }
}
