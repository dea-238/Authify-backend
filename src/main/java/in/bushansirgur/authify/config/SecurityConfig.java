package in.bushansirgur.authify.config;

import in.bushansirgur.authify.filter.JwtRequestFilter;
import in.bushansirgur.authify.service.AppUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtRequestFilter jwtRequestFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ① Tells Spring Security: “Use the CorsConfigurationSource bean that follows.”
            .cors(Customizer.withDefaults())
            // ② Disable CSRF (stateless JWT flow)
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                // ③ Permit exactly the same endpoints your controllers define.
                // If you chose Option #1 (controllers annotated with @RequestMapping("/api/v1.0")),
                // then these matchers should be "/api/v1.0/login", "/api/v1.0/register", etc.
                //
                // If you chose Option #2 (bare paths), then simply list "/login", "/register", etc.
                //
                // EXAMPLE here assumes you did Option #2: no "/api/v1.0" prefix in controllers:
                .requestMatchers(
                    "/login",
                    "/register",
                    "/send-reset-otp",
                    "/reset-password",
                    "/logout"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // ④ Add JWT filter before the default UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtRequestFilter, 
                             org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
            // ⑤ If authentication fails (e.g. no valid JWT), use your custom entry point
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(customAuthenticationEntryPoint)
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * ⑥ Expose a CorsConfigurationSource. Spring Security will automatically turn this
     *     into a CorsFilter at the correct position in the chain.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // ⚠️ You cannot use "*" if allowCredentials(true). Must list the exact origin:
        String frontendUrl = System.getenv("FRONTEND_URL");
        if (frontendUrl == null || frontendUrl.isBlank()) {
            throw new IllegalStateException(
                "Environment variable FRONTEND_URL must be set to your Vercel domain."
            );
        }
        config.setAllowedOrigins(List.of(frontendUrl));

        // Permit whichever HTTP methods your client will call:
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Permit the headers your client sends (e.g. "Authorization", "Content-Type"):
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        // If you send credentials (cookies + JWT) from the browser, leave this flag true:
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply these rules to all paths:
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(appUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }
}
