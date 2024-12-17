package vn.edu.iuh.fit.backend.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import vn.edu.iuh.fit.backend.services.CandidateService;
import vn.edu.iuh.fit.backend.services.CompanyService;

import java.io.IOException;
import java.util.List;

//@Component
//public class RedirectIFilter extends OncePerRequestFilter {
//    private final CandidateService candidateService;
//    private final CompanyService companyService;
//
//    public RedirectIFilter(CandidateService candidateService, CompanyService companyService) {
//        this.candidateService = candidateService;
//        this.companyService = companyService;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, IOException {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth.isAuthenticated()) {
//            if (request.getRequestURI().equals("/login") || request.getRequestURI().contains("/login")) {
//                response.sendRedirect("/");
//            } else if (request.getRequestURI().equals("/")) {
//                OAuth2User user = (OAuth2User) auth.getPrincipal();
//                if (candidateService.findByEmail(user.getAttribute("email")).isPresent()) {
//                    response.sendRedirect("/candidate");
//                } else if (companyService.findByEmail(user.getAttribute("email")).isPresent()) {
//                    response.sendRedirect("/company");
//                } else {
//                    filterChain.doFilter(request, response);
//                }
//            } else {
//                filterChain.doFilter(request, response);
//            }
//        } else {
//            response.sendRedirect("/login");
//        }
//    }
//}

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

        // Cho phép truy cập các đường dẫn công khai
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Nếu chưa xác thực và không phải đường dẫn công khai
        if (auth == null || !auth.isAuthenticated()) {
            response.sendRedirect("/login");
            return;
        }

        // Xử lý cho người dùng đã xác thực
        if (auth.isAuthenticated()) {
            OAuth2User user = (OAuth2User) auth.getPrincipal();
            String email = user.getAttribute("email");

            // Chuyển hướng về trang chủ nếu đang ở trang login
            if (path.equals("/login")) {
                response.sendRedirect("/");
                return;
            }

            // Chuyển hướng người dùng về trang tương ứng với vai trò
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
