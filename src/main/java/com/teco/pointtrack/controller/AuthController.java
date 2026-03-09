package com.teco.pointtrack.controller;

import com.teco.pointtrack.dto.auth.AuthResponse;
import com.teco.pointtrack.dto.auth.GoogleLoginRequest;
import com.teco.pointtrack.dto.auth.LoginRequest;
import com.teco.pointtrack.dto.auth.SignupRequest;
import com.teco.pointtrack.dto.auth.TokenRefreshRequest;
import com.teco.pointtrack.dto.common.MessageResponse;
import com.teco.pointtrack.dto.user.RoleDto;
import com.teco.pointtrack.dto.user.UserDetail;
import com.teco.pointtrack.exception.CustomAuthenticationException;
import com.teco.pointtrack.repository.UserRepository;
import com.teco.pointtrack.security.CustomUserDetail;
import com.teco.pointtrack.security.CustomUserDetailsService;
import com.teco.pointtrack.service.AuthService;
import com.teco.pointtrack.utils.CookieUtils;
import com.teco.pointtrack.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Đăng ký, Đăng nhập, Logout, Làm mới token")
public class AuthController {

    private final AuthService authService;
    private final JwtUtils jwtUtils;
    private final CustomUserDetailsService userDetailsService;
    private final CookieUtils cookieUtils;
    private final UserRepository userRepository;

    @Operation(summary = "Lấy thông tin cá nhân", description = "Trả về thông tin người dùng hiện tại từ Database.")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/me")
    public ResponseEntity<UserDetail> getCurrentUser() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            throw new CustomAuthenticationException("Chưa đăng nhập hoặc phiên làm việc hết hạn");
        }

        String contact = auth.getName();

        com.teco.pointtrack.entity.User user = userRepository.findByEmail(contact)
                .or(() -> userRepository.findByPhoneNumber(contact))
                .orElseThrow(() -> new CustomAuthenticationException("Không tìm thấy người dùng"));

        UserDetail userDetail = UserDetail.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .contact(contact)
                .dateOfBirth(user.getDateOfBirth())
                .gender(user.getGender())
                .avatarUrl(user.getAvatarUrl())
                .status(user.getStatus())
                .role(user.getRole() != null ? new RoleDto(user.getRole()) : null)
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();

        return ResponseEntity.ok(userDetail);
    }

    @Operation(summary = "Đăng nhập", description = "Đăng nhập bằng email hoặc số điện thoại kèm mật khẩu và Captcha.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Đăng nhập thành công", content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Captcha thất bại hoặc tài khoản dùng OAuth"),
            @ApiResponse(responseCode = "401", description = "Sai thông tin đăng nhập"),
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.login(request, httpServletRequest);
        cookieUtils.setAuthCookies(response, authResponse.getAccessToken(), authResponse.getRefreshToken());
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Đăng ký tài khoản", description = "Tạo tài khoản mới bằng email/SĐT và mật khẩu.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Đăng ký thành công", content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Dữ liệu không hợp lệ hoặc Captcha thất bại"),
            @ApiResponse(responseCode = "409", description = "Email hoặc SĐT đã tồn tại"),
    })
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(
            @Valid @RequestBody SignupRequest request,
            HttpServletRequest httpServletRequest,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.signup(request, httpServletRequest);
        cookieUtils.setAuthCookies(response, authResponse.getAccessToken(), authResponse.getRefreshToken());
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Đăng nhập Google", description = "Xác thực qua Google Access Token. Tự động tạo tài khoản nếu chưa tồn tại.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Thành công", content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Email đã đăng ký theo cách khác"),
            @ApiResponse(responseCode = "401", description = "Google Token không hợp lệ"),
    })
    @PostMapping("/google-login")
    public ResponseEntity<AuthResponse> googleLogin(
            @RequestBody GoogleLoginRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.loginWithGoogle(request);
        cookieUtils.setAuthCookies(response, authResponse.getAccessToken(), authResponse.getRefreshToken());
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Đăng xuất", description = "Thu hồi token hiện tại và xóa cookie phiên làm việc.")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Đăng xuất thành công"),
            @ApiResponse(responseCode = "401", description = "Chưa đăng nhập hoặc token hết hạn"),
    })
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = null;
        String refreshToken = null;

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (CookieUtils.ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    if (accessToken == null) accessToken = cookie.getValue();
                } else if (CookieUtils.REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if (accessToken != null) {
            try { jwtUtils.revokeToken(accessToken); } catch (Exception ignored) {}
        }
        if (refreshToken != null) {
            try { jwtUtils.revokeToken(refreshToken); } catch (Exception ignored) {}
        }

        cookieUtils.deleteAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("Đăng xuất thành công"));
    }

    @Operation(summary = "Làm mới Access Token", description = "Cấp lại Access Token mới bằng Refresh Token còn hiệu lực.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Thành công", content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Refresh Token không hợp lệ hoặc đã hết hạn"),
    })
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        if (refreshToken == null || !jwtUtils.validateToken(refreshToken)) {
            throw new CustomAuthenticationException("Refresh token không hợp lệ hoặc đã hết hạn");
        }

        String username = jwtUtils.extractUsername(refreshToken);
        CustomUserDetail userDetails = (CustomUserDetail) userDetailsService.loadUserByUsername(username);
        String newAccessToken = jwtUtils.generateAccessToken(userDetails);

        return ResponseEntity.ok(AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build());
    }
}
