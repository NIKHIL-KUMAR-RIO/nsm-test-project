package com.nsm.backend.config;

import com.nsm.backend.storage.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Spring Security Configuration (Person 4 Backend Hardening):
 * Enforces Option A Authentication & Role-Based Access Control (RBAC):
 * - Database-backed user authentication with BCrypt hashing.
 * - ROLE_ADMIN: Full operational control, user approval/management, clear alerts, attack simulations.
 * - ROLE_ANALYST: Read-only SOC observation (view dashboard, metrics, alerts, stream).
 * - PENDING registrations are rejected until administrator approval.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DatabaseUserDetailsService userDetailsService;
    private final UserRepository userRepository;

    public SecurityConfig(DatabaseUserDetailsService userDetailsService, UserRepository userRepository) {
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://localhost:3000",
                "http://127.0.0.1:3000"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler logoutSuccessHandler =
                new org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/login.html?logout=true");

        AuthenticationFailureHandler failureHandler = (request, response, exception) -> {
            String errorParam = "true";
            if (exception instanceof org.springframework.security.authentication.DisabledException) {
                errorParam = "pending";
            } else if (exception instanceof org.springframework.security.authentication.LockedException) {
                errorParam = "locked";
            }
            response.sendRedirect("/login.html?error=" + errorParam);
        };

        AuthenticationSuccessHandler successHandler = (request, response, authentication) -> {
            userRepository.findByUsernameOrEmail(authentication.getName())
                    .ifPresent(u -> userRepository.updateLastLogin(u.id(), java.time.Instant.now().toString()));
            response.sendRedirect("/");
        };

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .userDetailsService(userDetailsService)
                .authorizeHttpRequests(auth -> auth
                        // Public resources: Login page, registration endpoint, stylesheets, scripts, images
                        .requestMatchers("/login.html", "/login-bg.jpg", "/css/**", "/js/**", "/img/**", "/favicon.ico", "/api/auth/register").permitAll()
                        // Destructive actions, attack simulation triggers, and user management require ADMIN role
                        .requestMatchers("/api/alerts/clear", "/api/attack/**", "/api/ingest/**", "/api/admin/**").hasRole("ADMIN")
                        // Observability, metrics, alert feeds, and SOC Dashboard accessible to both ADMIN and ANALYST
                        .requestMatchers("/api/**").hasAnyRole("ADMIN", "ANALYST")
                        .requestMatchers("/", "/index.html").hasAnyRole("ADMIN", "ANALYST")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new org.springframework.security.web.authentication.HttpStatusEntryPoint(org.springframework.http.HttpStatus.UNAUTHORIZED),
                                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/api/**")
                        )
                        .defaultAuthenticationEntryPointFor(
                                new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login.html"),
                                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/**")
                        )
                )
                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/logout"))
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                );

        return http.build();
    }
}
