package vn.edu.iuh.fit.frontend.controllers;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class RoleSelectionController {

    @GetMapping("/choose-role")
    public String showRoleSelection() {
        return "choose-role";
    }

    @PostMapping("/choose-role")
    public String processRoleSelection(@RequestParam String role) {
        return "redirect:/register?role=" + role;
    }
}
