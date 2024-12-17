package vn.edu.iuh.fit.backend.configs;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestClient;
import vn.edu.iuh.fit.backend.filters.RedirectIFilter;
import vn.edu.iuh.fit.backend.models.Candidate;
import vn.edu.iuh.fit.backend.models.Company;
import vn.edu.iuh.fit.backend.services.CandidateService;
import vn.edu.iuh.fit.backend.services.CompanyService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final CandidateService candidateService;
    private final CompanyService companyService;

    public SecurityConfig(CandidateService candidateService, CompanyService companyService) {
        this.candidateService = candidateService;
        this.companyService = companyService;
    }

//    @Bean
//    public ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("google")
//                .clientId("575575126838-u59uank0kbgq80u6lfblsrvlikhlp00j.apps.googleusercontent.com")
//                .clientSecret("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")
//                .scope(
//                        "profile",
//                        "email",
//                        "https://www.googleapis.com/auth/gmail.send",
//                        "https://www.googleapis.com/auth/gmail.compose"
//                )
//                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
//                .tokenUri("https://oauth2.googleapis.com/token")
//                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/login/oauth2/code/google")
//                .userNameAttributeName("sub")
//                .build();
//    }


    @Bean
    public ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
                .clientId("575575126838-u59uank0kbgq80u6lfblsrvlikhlp00j.apps.googleusercontent.com")
                .clientSecret("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")
                .scope(
                        "profile",
                        "email",
                        "https://www.googleapis.com/auth/gmail.send",
                        "https://www.googleapis.com/auth/gmail.compose"
                )
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .tokenUri("https://oauth2.googleapis.com/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/google")
                .userNameAttributeName("sub")
                .build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        Optional<Candidate> candidate = candidateService.findByEmail(principal.getAttribute("email"));
        Optional<Company> company = companyService.findByEmail(principal.getAttribute("email"));

        List<GrantedAuthority> updatedAuthorities = new ArrayList<>(authentication.getAuthorities());
        if (candidate.isPresent()) {
            updatedAuthorities.add(new SimpleGrantedAuthority("ROLE_CANDIDATE"));
        } else if (company.isPresent()) {
            updatedAuthorities.add(new SimpleGrantedAuthority("ROLE_COMPANY"));
        }

        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2AuthToken = (OAuth2AuthenticationToken) authentication;
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(
                            oauth2AuthToken.getPrincipal(),
                            updatedAuthorities,
                            oauth2AuthToken.getAuthorizedClientRegistrationId()
                    )
            );
        }
    }


    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        return userRequest -> {
            OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
            String email = oAuth2User.getAttribute("email");
            List<GrantedAuthority> authorities = new ArrayList<>(oAuth2User.getAuthorities());

            if (candidateService.findByEmail(email).isPresent()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_CANDIDATE"));
            } else if (companyService.findByEmail(email).isPresent()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_COMPANY"));
            }

            return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), "email");
        };
    }

    @Bean
    public DefaultAuthenticationEventPublisher defaultAuthenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .csrf(AbstractHttpConfigurer::disable)
//                .cors(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
//                        authorizationManagerRequestMatcherRegistry
//                                .requestMatchers("/", "/jobs/**", "/assets/**", "/css/**", "/js/**").permitAll() // Cho phép truy cập trang chủ và resources
//                                .requestMatchers("/oauth2/**").permitAll()
//                                .requestMatchers("/candidate", "/candidate/**").hasAuthority("ROLE_CANDIDATE")
//                                .requestMatchers("/company", "/company/**").hasAuthority("ROLE_COMPANY")
//                                .requestMatchers("/skills/**").hasAnyAuthority("ROLE_COMPANY", "ROLE_CANDIDATE")
//                                .anyRequest().authenticated()
//                )
//                .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
//                    httpSecurityExceptionHandlingConfigurer.accessDeniedHandler((request, response, accessDeniedException) -> {
//                        // Gửi phản hồi lỗi HTTP 403 hoặc chuyển hướng đến trang tùy chỉnh
//                        response.sendRedirect("/");
//                    });
//                })
//                .oauth2Login(httpSecurityOAuth2LoginConfigurer ->
//                        httpSecurityOAuth2LoginConfigurer
//                                .successHandler((request, response, authentication) -> {
//                                    System.out.println("Authentication successful 181");
//                                })
//                                .defaultSuccessUrl("/", true)
//                )
//                .addFilterBefore(new RedirectIFilter(candidateService, companyService), UsernamePasswordAuthenticationFilter.class);
//        return httpSecurity.build();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**", "/register/**", "/choose-role").permitAll()
                        .requestMatchers("/candidate/**").hasAuthority("ROLE_CANDIDATE")
                        .requestMatchers("/company/**").hasAuthority("ROLE_COMPANY")
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/")
                        .successHandler((request, response, authentication) -> {
                            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                            String email = oauth2User.getAttribute("email");

                            // Kiểm tra user đã có trong hệ thống chưa
                            if (candidateService.findByEmail(email).isPresent()) {
                                response.sendRedirect("/candidate");
                            } else if (companyService.findByEmail(email).isPresent()) {
                                response.sendRedirect("/company");
                            } else {
                                // Nếu là user mới, chuyển đến trang chọn role
                                response.sendRedirect("/choose-role");
                            }
                        })
                )
                .addFilterBefore(new RedirectIFilter(candidateService, companyService),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {
                OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                String email = oauth2User.getAttribute("email");
                String name = oauth2User.getAttribute("name");

                logger.info("User authenticated successfully - Email: {}, Name: {}", email, name);
                logger.info("Authorities: {}", authentication.getAuthorities());

                // Kiểm tra vai trò
                var candidate = candidateService.findByEmail(email);
                var company = companyService.findByEmail(email);

                if (candidate.isPresent()) {
                    logger.info("User is a candidate");
                    response.sendRedirect("/candidate");
                } else if (company.isPresent()) {
                    logger.info("User is a company");
                    response.sendRedirect("/company");
                } else {
                    logger.info("New user - redirecting to registration");
                    response.sendRedirect("/register");
                }
            }
        };
    }


    @Bean
    public RestClient restClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor requestInterceptor =
                new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        return RestClient.builder()
                .requestInterceptor(requestInterceptor)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
    }
}
