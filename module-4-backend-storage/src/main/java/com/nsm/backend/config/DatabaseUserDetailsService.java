package com.nsm.backend.config;

import com.nsm.backend.storage.UserEntity;
import com.nsm.backend.storage.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Custom Spring Security UserDetailsService backed by SQLite (Person 4).
 * Enforces Option A Account Lifecycle:
 * - ACTIVE accounts are permitted to authenticate.
 * - PENDING accounts are marked disabled (throws DisabledException).
 * - DISABLED accounts are marked locked (throws LockedException).
 */
@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public DatabaseUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Account not found for: " + usernameOrEmail));

        boolean enabled = user.isActive();
        boolean accountNonLocked = !user.isDisabled();

        String roleWithPrefix = user.role().toUpperCase().startsWith("ROLE_")
                ? user.role().toUpperCase()
                : "ROLE_" + user.role().toUpperCase();

        return new org.springframework.security.core.userdetails.User(
                user.username(),
                user.passwordHash(),
                enabled,
                true, // accountNonExpired
                true, // credentialsNonExpired
                accountNonLocked,
                List.of(new SimpleGrantedAuthority(roleWithPrefix))
        );
    }
}
