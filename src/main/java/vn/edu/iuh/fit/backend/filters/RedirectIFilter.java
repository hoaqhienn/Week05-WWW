package vn.edu.iuh.fit.backend.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import vn.edu.iuh.fit.backend.services.*;

import java.io.IOException;
import java.util.List;

@Component
public class RedirectIFilter extends OncePerRequestFilter {
    private final CandidateService candidateService;
    private final CompanyService companyService;
    private final List<String> PUBLIC_PATHS = List.of("/", "/index", "/login", "/register", "/assets", "/css", "/js");

    public RedirectIFilter(CandidateService candidateService, CompanyService companyService) {
        this.candidateService = candidateService;
        this.companyService = companyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            response.sendRedirect("/login");
            return;
        }

        if (auth.isAuthenticated()) {
            OAuth2User user = (OAuth2User) auth.getPrincipal();
            String email = user.getAttribute("email");

            if (path.equals("/login")) {
                response.sendRedirect("/");
                return;
            }

            if (path.equals("/")) {
                if (candidateService.findByEmail(email).isPresent()) {
                    response.sendRedirect("/candidate");
                    return;
                } else if (companyService.findByEmail(email).isPresent()) {
                    response.sendRedirect("/company");
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
