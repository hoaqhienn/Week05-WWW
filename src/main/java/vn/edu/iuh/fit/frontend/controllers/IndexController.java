package vn.edu.iuh.fit.frontend.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import vn.edu.iuh.fit.backend.enums.StatusPostJob;
import vn.edu.iuh.fit.backend.services.JobService;

@Controller
@RequestMapping("/")
public class IndexController {
    private static final Logger logger = LoggerFactory.getLogger(IndexController.class);
    private final JobService jobService;

    public IndexController(JobService jobService) {
        this.jobService = jobService;
    }

    @GetMapping
    public String index(Model model) {
        // Check authentication status
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
                authentication.getPrincipal() instanceof OAuth2User) {

            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name");

            logger.info("Authenticated user accessing index - Email: {}, Name: {}", email, name);
            logger.info("User authorities: {}", authentication.getAuthorities());

            // Add authentication info to model if needed
            model.addAttribute("authenticated", true);
            model.addAttribute("userEmail", email);
            model.addAttribute("userName", name);
        } else {
            logger.info("Anonymous user accessing index");
            model.addAttribute("authenticated", false);
        }

        // Load and add jobs to model
        var jobs = jobService.findByStatus(StatusPostJob.OPEN);
        model.addAttribute("jobs", jobs);
        logger.info("Loaded {} jobs for display", jobs.size());

        return "index";
    }
}