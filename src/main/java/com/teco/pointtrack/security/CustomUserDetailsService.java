package com.teco.pointtrack.security;

import com.teco.pointtrack.dto.user.RoleDto;
import com.teco.pointtrack.dto.user.UserDetail;
import com.teco.pointtrack.entity.User;
import com.teco.pointtrack.entity.enums.UserStatus;
import com.teco.pointtrack.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(username)
                .or(() -> userRepository.findByPhoneNumber(username))
                .orElseThrow(() -> new UsernameNotFoundException("Tài khoản không tồn tại hoặc mật khẩu sai"));

        Set<GrantedAuthority> authorities = buildAuthorities(user);

        UserDetail userDetailDto = UserDetail.builder()
                .id(user.getId())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .contact(user.getEmail() != null ? user.getEmail() : user.getPhoneNumber())
                .fullName(user.getFullName())
                .avatarUrl(user.getAvatarUrl())
                .status(user.getStatus())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .role(user.getRole() != null ? new RoleDto(user.getRole()) : null)
                .build();

        boolean enabled = (user.getStatus() == UserStatus.ACTIVE);
        boolean accountNonLocked = (user.getStatus() != UserStatus.BANNED);

        return new CustomUserDetail(username, user.getPasswordHash(), enabled, accountNonLocked, userDetailDto, authorities);
    }

    private Set<GrantedAuthority> buildAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        if (user.getRole() == null) return authorities;

        authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole().getSlug()));

        if (user.getRole().getPermissions() != null) {
            user.getRole().getPermissions().forEach(permission ->
                    authorities.add(new SimpleGrantedAuthority(permission.getCode()))
            );
        }

        return authorities;
    }
}
