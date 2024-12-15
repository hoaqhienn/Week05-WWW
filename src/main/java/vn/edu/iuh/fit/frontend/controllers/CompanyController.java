package vn.edu.iuh.fit.frontend.controllers;

import com.google.api.services.gmail.model.Message;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import vn.edu.iuh.fit.backend.enums.SkillLevel;
import vn.edu.iuh.fit.backend.enums.StatusPostJob;
import vn.edu.iuh.fit.backend.ids.JobSkillId;
import vn.edu.iuh.fit.backend.models.*;
import vn.edu.iuh.fit.backend.services.*;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Controller
@RequestMapping("/company")
public class CompanyController {
    private final CompanyService companyService;
    private final JobService jobService;
    private final SkillService skillService;
    private final JobSkillService jobSkillService;
    private final CandidateService candidateService;
    private final ExperienceService experienceService;
    private final EmailService emailService;
    private final OAuth2AuthorizedClientService authorizedClientService;

    public CompanyController(CompanyService companyService,
                             JobService jobService,
                             SkillService skillService,
                             JobSkillService jobSkillService,
                             CandidateService candidateService,
                             ExperienceService experienceService,
                             EmailService emailService,
                             OAuth2AuthorizedClientService authorizedClientService) {
        this.companyService = companyService;
        this.jobService = jobService;
        this.skillService = skillService;
        this.jobSkillService = jobSkillService;
        this.candidateService = candidateService;
        this.experienceService = experienceService;
        this.emailService = emailService;
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping
    public String company(Model model, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        Optional<Company> company = companyService.findByEmail(user.getAttribute("email"));
        List<Job> jobs = jobService.findByCompanyId(company.get().getId());
        company.ifPresent(value -> model.addAttribute("company", value));
        jobs.forEach(job -> {
            if (job.getJobSkills() == null) {
                job.setJobSkills(new ArrayList<>());
            }
        });
        model.addAttribute("jobs", jobs);
        return "companies/home";
    }

    @GetMapping
    @RequestMapping("/get-experiences")
    public ResponseEntity<?> getExperiences(@RequestParam("candidateId") Long candidateId) {
        List<Experience> experiences = experienceService.findByCandidateId(candidateId);
        System.out.println(experiences.size());
        if (experiences.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(experiences);

    }

    @PostMapping
    @RequestMapping("/add-job")
    @Transactional
    public String addJob(@Valid JobRequest jobRequest, Model model, BindingResult bindingResult, RedirectAttributes redirectAttributes) {
        // Validate input
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("error", bindingResult.getAllErrors().toString());
            return "redirect:/company";
        }

        // Get company info
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        Optional<Company> companyOptional = companyService.findByEmail(user.getAttribute("email"));

        if (companyOptional.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Company not found for the authenticated user.");
            return "redirect:/company";
        }

        try {
            // Create and save the job
            Company company = companyOptional.get();
            Job job = new Job();
            job.setCompany(company);
            job.setJobDesc(jobRequest.jobDescription);
            job.setJobName(jobRequest.jobName);
            job.setStatus(StatusPostJob.OPEN);
            Job savedJob = jobService.save(job);

            // Process each skill request
            for (SkillRequest skillRequest : jobRequest.skills) {
                Optional<Skill> skillOptional = skillService.findById(skillRequest.id());

                if (skillOptional.isEmpty()) {
                    throw new RuntimeException("Skill with ID " + skillRequest.id() + " not found.");
                }

                JobSkill jobSkill = new JobSkill();
                JobSkillId jobSkillId = new JobSkillId();
                jobSkillId.setJobId(savedJob.getId());
                jobSkillId.setSkillId(skillOptional.get().getId());

                jobSkill.setId(jobSkillId);
                jobSkill.setSkill(skillOptional.get());
                jobSkill.setSkillLevel(skillRequest.skillLevel());
                jobSkill.setJob(savedJob);
                jobSkill.setMoreInfos(skillRequest.moreInfos());

                jobSkillService.save(jobSkill);
            }

            redirectAttributes.addFlashAttribute("message", "Job added successfully!");
            return "redirect:/company";

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error adding job: " + e.getMessage());
            return "redirect:/company";
        }
    }

    @GetMapping
    @RequestMapping("/find-candidates/list")
    public String findCandidatesList(@RequestParam("jobId") long jobId, Model model) {
        List<Candidate> candidates = candidateService.findCandidatesByJobIdAndSkills(jobId);
        model.addAttribute("candidates", candidates);
        model.addAttribute("jobId", jobId);
        return "companies/find-candidate-list";
    }

    @GetMapping
    @RequestMapping("/find-candidates/page")
    public String findCandidatesPage(@RequestParam("jobId") long jobId, @RequestParam("page") Optional<Integer> page, @RequestParam("size") Optional<Integer> size, Model model) {
        int pageCurrent = page.orElse(1);
        int pageSize = size.orElse(10);
        Page<Candidate> candidates = candidateService.findCandidatesByJobIdAndSkills(jobId, pageCurrent, pageSize, "id", "asc");
        model.addAttribute("candidatePage", candidates);
        model.addAttribute("jobId", jobId);
        System.out.println(candidates.getContent().size());
        int totalPages = candidates.getTotalPages();
        if (totalPages > 0) {
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        } else {
            model.addAttribute("pageNumbers", new ArrayList<Integer>().add(1));
        }
        return "companies/find-candidate";
    }

    @GetMapping
    @RequestMapping("/status-job")
    public void closeJob(@RequestParam("jobId") long jobId, @RequestParam("status") StatusPostJob status, HttpServletResponse response) throws IOException {
        jobService.close(jobId, status);
        response.sendRedirect("/company");
    }

    @GetMapping("/invite-candidate")
    public ResponseEntity<?> inviteCandidate(@RequestParam("candidateId") Long candidateId,
                                             @RequestParam("jobId") Long jobId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );

            Optional<Candidate> candidate = candidateService.findById(candidateId);
            Optional<Job> job = jobService.findById(jobId);

            if (candidate.isEmpty() || job.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "Candidate or job not found"));
            }

            String htmlContent = emailService.getHtmlTemplateInviteCandidate(
                    "src/main/resources/templates/email/template.html",
                    job.get()
            );

            Message result = emailService.sendEmail(
                    authentication.getName(),
                    candidate.get().getEmail(),
                    htmlContent,
                    authorizedClient.getAccessToken().getTokenValue()
            );

            return ResponseEntity.ok(Map.of("status", "Email sent successfully"));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    private record SkillRequest(
            @NotNull(message = "Skill ID cannot be null.")
            Long id,
            @NotNull(message = "Skill level is required.")
            SkillLevel skillLevel,
            @Size(max = 255, message = "Additional information must not exceed 255 characters.")
            String moreInfos
    ) {
    }

    private record JobRequest(
            @NotBlank(message = "Job name is required.")
            String jobName,
            @Size(max = 500, message = "Job description must not exceed 500 characters.")
            String jobDescription,
            @NotNull(message = "Skill list cannot be null.")
            @Size(min = 1, message = "At least one skill is required.")
            List<SkillRequest> skills
    ) {
    }

}
