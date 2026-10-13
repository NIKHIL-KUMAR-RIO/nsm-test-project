package com.nsm.backend.storage;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<UserEntity> rowMapper = (rs, rowNum) -> new UserEntity(
            rs.getLong("id"),
            rs.getString("email"),
            rs.getString("username"),
            rs.getString("full_name"),
            rs.getString("password_hash"),
            rs.getString("role"),
            rs.getString("account_status"),
            rs.getString("created_at"),
            rs.getString("last_login")
    );

    public UserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<UserEntity> findByUsernameOrEmail(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return Optional.empty();
        }
        String clean = identifier.trim().toLowerCase();
        String sql = "SELECT id, email, username, full_name, password_hash, role, account_status, created_at, last_login " +
                     "FROM users WHERE LOWER(username) = ? OR LOWER(email) = ? LIMIT 1";
        try {
            UserEntity user = jdbcTemplate.queryForObject(sql, rowMapper, clean, clean);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public Optional<UserEntity> findById(Long id) {
        if (id == null) {
            return Optional.empty();
        }
        String sql = "SELECT id, email, username, full_name, password_hash, role, account_status, created_at, last_login " +
                     "FROM users WHERE id = ?";
        try {
            UserEntity user = jdbcTemplate.queryForObject(sql, rowMapper, id);
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public Optional<UserEntity> findByEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        String sql = "SELECT id, email, username, full_name, password_hash, role, account_status, created_at, last_login " +
                     "FROM users WHERE LOWER(email) = ? LIMIT 1";
        try {
            UserEntity user = jdbcTemplate.queryForObject(sql, rowMapper, email.trim().toLowerCase());
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public Optional<UserEntity> findByUsername(String username) {
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }
        String sql = "SELECT id, email, username, full_name, password_hash, role, account_status, created_at, last_login " +
                     "FROM users WHERE LOWER(username) = ? LIMIT 1";
        try {
            UserEntity user = jdbcTemplate.queryForObject(sql, rowMapper, username.trim().toLowerCase());
            return Optional.ofNullable(user);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public List<UserEntity> findAll() {
        String sql = "SELECT id, email, username, full_name, password_hash, role, account_status, created_at, last_login " +
                     "FROM users ORDER BY id DESC";
        return jdbcTemplate.query(sql, rowMapper);
    }

    public long countPending() {
        Long count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users WHERE UPPER(account_status) = 'PENDING'", Long.class);
        return count != null ? count : 0L;
    }

    public long countAdmins() {
        Long count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users WHERE UPPER(role) = 'ADMIN' AND UPPER(account_status) = 'ACTIVE'", Long.class);
        return count != null ? count : 0L;
    }

    public UserEntity save(UserEntity user) {
        String sql = """
            INSERT INTO users (email, username, full_name, password_hash, role, account_status, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """;
        jdbcTemplate.update(sql,
                user.email().toLowerCase().trim(),
                user.username().toLowerCase().trim(),
                user.fullName().trim(),
                user.passwordHash(),
                user.role().toUpperCase().trim(),
                user.accountStatus().toUpperCase().trim(),
                user.createdAt(),
                user.lastLogin()
        );

        return findByUsername(user.username()).orElse(user);
    }

    public boolean updateStatus(Long id, String status) {
        String sql = "UPDATE users SET account_status = ? WHERE id = ?";
        int updated = jdbcTemplate.update(sql, status.toUpperCase().trim(), id);
        return updated > 0;
    }

    public boolean updateLastLogin(Long id, String timestamp) {
        String sql = "UPDATE users SET last_login = ? WHERE id = ?";
        int updated = jdbcTemplate.update(sql, timestamp, id);
        return updated > 0;
    }

    public boolean delete(Long id) {
        String sql = "DELETE FROM users WHERE id = ?";
        int deleted = jdbcTemplate.update(sql, id);
        return deleted > 0;
    }
}
