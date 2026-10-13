package com.nsm.backend.storage;

/**
 * Immutable User Entity record representing an authenticated operator in SQLite (Person 4).
 *
 * @param id Unique database identifier (auto-incremented)
 * @param email User's official email address (unique)
 * @param username Unique login handle
 * @param fullName Full display name of the analyst or administrator
 * @param passwordHash BCrypt-hashed password string
 * @param role Assigned role: 'ADMIN' or 'ANALYST'
 * @param accountStatus Lifecycle state: 'PENDING', 'ACTIVE', or 'DISABLED'
 * @param createdAt ISO-8601 registration timestamp
 * @param lastLogin ISO-8601 last successful authentication timestamp (or null)
 */
public record UserEntity(
        Long id,
        String email,
        String username,
        String fullName,
        String passwordHash,
        String role,
        String accountStatus,
        String createdAt,
        String lastLogin
) {
    public boolean isActive() {
        return "ACTIVE".equalsIgnoreCase(accountStatus);
    }

    public boolean isPending() {
        return "PENDING".equalsIgnoreCase(accountStatus);
    }

    public boolean isDisabled() {
        return "DISABLED".equalsIgnoreCase(accountStatus);
    }

    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(role);
    }
}
