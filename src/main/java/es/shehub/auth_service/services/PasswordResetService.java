package es.shehub.auth_service.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.UserRepository;
import es.shehub.auth_service.security.jwt.JwtUtil;

/**
 * Service for handling password reset functionality.
 * 
 * This service provides methods to send password reset emails containing
 * a secure token link and to reset the password after validating the token.
 * 
 */
@Service
public class PasswordResetService {

    private final JavaMailSender mailSender;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * The base URL of the frontend reset password page.
     * The reset token will be appended as a query parameter to this URL.
     * It should be set in .env file
     */
    @Value("${FRONTEND_RESET_PASSWORD_URL}")
    private String resetUrl;

    /**
     * Constructs a PasswordResetService with required dependencies.
     *
     * @param mailSender      the mail sender used to send reset emails
     * @param jwtUtil         utility class for JWT token generation and extraction
     * @param userRepository  repository to access user data
     * @param passwordEncoder encoder to securely hash new passwords
     */
    public PasswordResetService(JavaMailSender mailSender,
            JwtUtil jwtUtil,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        this.mailSender = mailSender;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Sends a password reset email to the given email address.
     * 
     * If the email does not exist in the user repository, the method returns silently.
     * Otherwise, it generates a JWT password reset token and sends an email containing
     * a reset link with the token appended as a query parameter.
     *
     * @param email the email address to send the reset link to
     */
    public void sendResetEmail(String email) {
        if (!userRepository.existsByEmail(email)) {
            return;
        }

        String token = jwtUtil.generatePasswordResetToken(email);
        String link = resetUrl + "?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Reset Your Password");
        message.setText("Click to reset your password: " + link);
        message.setFrom("noreply@shehub.com");

        mailSender.send(message);
    }

    /**
     * Resets the user's password using the provided JWT token and new password.
     *
     * Extracts the user's email from the token, verifies the user exists,
     * encodes the new password, and saves the updated user entity.
     *
     * @param token the JWT token containing the user's email for verification
     * @param newPassword the new password to set for the user
     * @throws RuntimeException if the user is not found or token is invalid
     */
    public void resetPassword(String token, String newPassword) {
        String email = jwtUtil.extractUsername(token);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

}