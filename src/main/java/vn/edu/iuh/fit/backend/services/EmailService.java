package vn.edu.iuh.fit.backend.services;

import com.google.auth.oauth2.AccessToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Message;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Properties;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;
import vn.edu.iuh.fit.backend.models.Job;
import vn.edu.iuh.fit.backend.models.JobSkill;

@Service
@Slf4j
public class EmailService {

    public EmailService(OAuth2AuthorizedClientManager authorizedClientManager) {
    }

    public Message sendEmail(String fromEmailAddress, String toEmailAddress,
                             String htmlContent, String accessToken)
            throws MessagingException, IOException {

        try {
            GoogleCredentials credentials = GoogleCredentials.create(
                            new AccessToken(accessToken, null))
                    .createScoped(Collections.singleton(GmailScopes.GMAIL_SEND));

            Gmail service = new Gmail.Builder(
                    new NetHttpTransport(),
                    GsonFactory.getDefaultInstance(),
                    new HttpCredentialsAdapter(credentials))
                    .setApplicationName("Job Portal")
                    .build();

            Properties props = new Properties();
            Session session = Session.getDefaultInstance(props, null);
            MimeMessage email = new MimeMessage(session);
            email.setFrom(new InternetAddress(fromEmailAddress));
            email.addRecipient(javax.mail.Message.RecipientType.TO,
                    new InternetAddress(toEmailAddress));
            email.setSubject("Job Invitation");
            email.setContent(htmlContent, "text/html; charset=utf-8");

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            email.writeTo(buffer);
            byte[] rawMessageBytes = buffer.toByteArray();
            String encodedEmail = Base64.encodeBase64URLSafeString(rawMessageBytes);
            Message message = new Message();
            message.setRaw(encodedEmail);

            try {
                message = service.users().messages().send("me", message).execute();
                log.info("Message id: " + message.getId());
                return message;
            } catch (GoogleJsonResponseException e) {
                log.error("GoogleJsonResponseException: " + e.getDetails().toPrettyString());
                throw e;
            }
        } catch (Exception e) {
            log.error("Error sending email", e);
            throw e;
        }
    }

    public static String getHtmlTemplateInviteCandidate(String filePath, Job job) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            // Thay thế các placeholder với giá trị thực tế từ đối tượng Job
            content = content.replace("{{companyName}}", job.getCompany().getName())
                    .replace("{{jobTitle}}", job.getJobName())
                    .replace("{{jobDescription}}", job.getJobDesc())
                    .replace("{{jobStatus}}", job.getStatus().toString());
//                    .replace("{{applyLink}}", "https://example.com/apply") // Đường link apply
//                    .replace("{{companyDomain}}", job.getCompany().getWebUrl());

            // Lấy danh sách kỹ năng từ jobSkills và tạo HTML cho chúng
            StringBuilder jobSkillsHtml = new StringBuilder();
            for (JobSkill jobSkill : job.getJobSkills()) {
                jobSkillsHtml.append("<tr>")
                        .append("<td style='padding: 10px; border: 1px solid #ddd;'>")
                        .append(jobSkill.getSkill().getSkillName()).append("</td>")
                        .append("<td style='padding: 10px; border: 1px solid #ddd;'>")
                        .append(jobSkill.getSkill().getSkillDescription()).append("</td>")
                        .append("<td style='padding: 10px; border: 1px solid #ddd;'>")
                        .append(jobSkill.getSkillLevel().toString()).append("</td>")
                        .append("<td style='padding: 10px; border: 1px solid #ddd;'>")
                        .append(jobSkill.getMoreInfos()).append("</td>")
                        .append("</tr>");
            }

            // Thay thế placeholder {{jobSkills}} với HTML động cho kỹ năng
            content = content.replace("{{jobSkills}}", jobSkillsHtml.toString());

            return content;
        } catch (IOException e) {
            throw new RuntimeException("Error reading email template file", e);
        }
    }
}