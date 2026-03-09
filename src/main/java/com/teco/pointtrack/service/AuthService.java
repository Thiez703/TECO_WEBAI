package com.teco.pointtrack.service;

import com.teco.pointtrack.dto.auth.AuthResponse;
import com.teco.pointtrack.dto.auth.GoogleLoginRequest;
import com.teco.pointtrack.dto.auth.LoginRequest;
import com.teco.pointtrack.dto.auth.SignupRequest;
import com.teco.pointtrack.entity.Role;
import com.teco.pointtrack.entity.User;
import com.teco.pointtrack.entity.enums.AuthProvider;
import com.teco.pointtrack.entity.enums.UserStatus;
import com.teco.pointtrack.exception.BadRequestException;
import com.teco.pointtrack.exception.ConflictException;
import com.teco.pointtrack.exception.CustomAuthenticationException;
import com.teco.pointtrack.repository.RoleRepository;
import com.teco.pointtrack.repository.UserRepository;
import com.teco.pointtrack.security.CustomUserDetail;
import com.teco.pointtrack.security.CustomUserDetailsService;
import com.teco.pointtrack.utils.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final CaptchaService captchaService;
    private final JwtUtils jwtUtils;
    private final CustomUserDetailsService userDetailsService;

    private final RestTemplate restTemplate = new RestTemplate();

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$");

    private static final Pattern PHONE_PATTERN =
            Pattern.compile("^\\d{10}$");

    private static final String ROLE_USER = "USER";

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {

        if (!captchaService.verifyCaptcha(request.getCaptchaToken(), httpRequest)) {
            throw new BadRequestException("Xác thực Captcha thất bại");
        }

        String contact = request.getContact().trim();

        User user = userRepository.findByEmail(contact)
                .or(() -> userRepository.findByPhoneNumber(contact))
                .orElseThrow(() -> new CustomAuthenticationException("Email hoặc mật khẩu không chính xác"));

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new BadRequestException(
                    "Tài khoản này đăng nhập bằng " + user.getProvider() + ". Vui lòng dùng đăng nhập Google.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new CustomAuthenticationException("Email hoặc mật khẩu không chính xác");
        }

        checkUserStatus(user);

        CustomUserDetail userDetails = (CustomUserDetail) userDetailsService.loadUserByUsername(contact);
        return buildAuthResponse(userDetails, user);
    }

    @Transactional
    public AuthResponse signup(SignupRequest request, HttpServletRequest httpServletRequest) {

        if (!captchaService.verifyCaptcha(request.getCaptchaToken(), httpServletRequest)) {
            throw new BadRequestException("Xác thực Captcha thất bại");
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Mật khẩu xác nhận không khớp");
        }

        String contact = request.getContact().trim();
        String email = null;
        String phone = null;

        if (EMAIL_PATTERN.matcher(contact).matches()) {
            email = contact;
            if (userRepository.existsByEmail(email)) {
                throw new ConflictException("Email này đã được sử dụng");
            }
        } else if (PHONE_PATTERN.matcher(contact).matches()) {
            phone = contact;
            if (userRepository.existsByPhoneNumber(phone)) {
                throw new ConflictException("Số điện thoại này đã được sử dụng");
            }
        } else {
            throw new BadRequestException("Email hoặc số điện thoại không hợp lệ");
        }

        Role defaultRole = roleRepository.findBySlug(ROLE_USER)
                .orElseThrow(() -> new BadRequestException("Cấu hình hệ thống lỗi: Role USER chưa được tạo"));

        User newUser = User.builder()
                .fullName(request.getFullName().trim())
                .email(email)
                .phoneNumber(phone)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .status(UserStatus.ACTIVE)
                .role(defaultRole)
                .avatarUrl(generateSmartAvatar(request.getFullName()))
                .provider(AuthProvider.LOCAL)
                .build();

        userRepository.save(newUser);

        String username = (email != null) ? email : phone;
        CustomUserDetail userDetails = (CustomUserDetail) userDetailsService.loadUserByUsername(username);
        return buildAuthResponse(userDetails, newUser);
    }

    @Transactional
    public AuthResponse loginWithGoogle(GoogleLoginRequest request) {

        String googleApiUrl = "https://www.googleapis.com/oauth2/v3/userinfo";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(request.getToken());
        HttpEntity<String> entity = new HttpEntity<>(headers);

        Map<String, Object> googleUser;
        try {
            ResponseEntity<Map> response = restTemplate.exchange(googleApiUrl, HttpMethod.GET, entity, Map.class);
            googleUser = response.getBody();
        } catch (Exception e) {
            log.error("Google Login Error: ", e);
            throw new CustomAuthenticationException("Token Google không hợp lệ hoặc đã hết hạn");
        }

        if (googleUser == null || googleUser.get("email") == null) {
            throw new CustomAuthenticationException("Không lấy được thông tin từ Google");
        }

        String email = (String) googleUser.get("email");
        String name = (String) googleUser.get("name");
        String picture = (String) googleUser.get("picture");

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            Role defaultRole = roleRepository.findBySlug(ROLE_USER)
                    .orElseThrow(() -> new BadRequestException("Cấu hình hệ thống lỗi: Role USER chưa được tạo"));

            user = User.builder()
                    .email(email)
                    .fullName(name)
                    .avatarUrl(picture)
                    .role(defaultRole)
                    .status(UserStatus.ACTIVE)
                    .provider(AuthProvider.GOOGLE)
                    .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .build();

            userRepository.save(user);
        } else {
            if (user.getProvider() != AuthProvider.GOOGLE) {
                throw new BadRequestException(
                        "Email này đã đăng ký bằng " + user.getProvider() + ". Vui lòng đăng nhập theo cách đó.");
            }
            checkUserStatus(user);
            if (user.getAvatarUrl() == null && picture != null) {
                user.setAvatarUrl(picture);
                userRepository.save(user);
            }
        }

        CustomUserDetail userDetails = (CustomUserDetail) userDetailsService.loadUserByUsername(email);
        return buildAuthResponse(userDetails, user);
    }

    private AuthResponse buildAuthResponse(CustomUserDetail userDetails, User user) {
        return AuthResponse.builder()
                .accessToken(jwtUtils.generateAccessToken(userDetails))
                .refreshToken(jwtUtils.generateRefreshToken(userDetails))
                .userId(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .contact(user.getEmail() != null ? user.getEmail() : user.getPhoneNumber())
                .avatarUrl(user.getAvatarUrl())
                .role(user.getRole() != null ? user.getRole().getSlug() : null)
                .build();
    }

    private void checkUserStatus(User user) {
        switch (user.getStatus()) {
            case BANNED -> throw new CustomAuthenticationException("Tài khoản đã bị khóa vĩnh viễn");
            case INACTIVE -> throw new CustomAuthenticationException("Tài khoản tạm thời bị vô hiệu hóa");
            case UNVERIFIED -> throw new CustomAuthenticationException("Tài khoản chưa được xác thực");
            default -> { /* ACTIVE — OK */ }
        }
    }

    private String generateSmartAvatar(String fullName) {
        if (fullName == null || fullName.isBlank()) return null;
        try {
            return "https://ui-avatars.com/api/?name=" +
                    URLEncoder.encode(fullName, StandardCharsets.UTF_8) +
                    "&background=random&size=200&color=fff";
        } catch (Exception e) {
            return null;
        }
    }
}
