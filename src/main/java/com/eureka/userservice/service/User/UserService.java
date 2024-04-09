package com.eureka.userservice.service.User;

import com.eureka.userservice.domain.Authority;
import com.eureka.userservice.domain.User;
import com.eureka.userservice.dto.user.request.SignRequest;
import com.eureka.userservice.dto.user.response.SignResponse;
import com.eureka.userservice.repository.RefreshTokenRepository;
import com.eureka.userservice.repository.UserRepository;
import com.eureka.userservice.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final RedisTemplate redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;

    public SignResponse login(SignRequest request) throws Exception {
        User member = memberRepository.findByAccount(request.getAccount()).orElseThrow(() ->
                new BadCredentialsException("잘못된 계정정보입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정정보입니다.");
        }

        return SignResponse.builder()
                .id(member.getId())
                .account(member.getAccount())
                .name(member.getName())
                .email(member.getEmail())
                .nickname(member.getNickname())
                .roles(member.getRoles())
                .token(jwtProvider.createToken(member.getAccount(), member.getRoles()))
                .build();

    }

    //로그아웃
    @Transactional
    public void logout(String refreshToken, String accessToken){

        Optional<Long> findUserId = jwtProvider.getUserIdToToken(accessToken);

        //액세스 토큰 남은 유효시간
        Long expiration = jwtProvider.getExpiration(accessToken);

        //리프레시 토큰 남은 유효시간
        Long refreshExpiration = jwtProvider.getExpiration(refreshToken);

        // 액세스 토큰 유효시간이 남았을 경우에만 로그아웃 수행
        if (expiration > 0) {
            // 액세스 토큰을 만료시킴
            // Redis Cache에 저장
            redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
        }

        // 리프레시 토큰이 유효할 경우에만 삭제
        if (refreshExpiration > 0) {
            // 리프레시 토큰 삭제
             refreshTokenRepository.deleteByUserId(findUserId.get());
        }
    }

    public boolean register(SignRequest request) throws Exception {
        try {
            User member = User.builder()
                    .account(request.getAccount())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .name(request.getName())
                    .nickname(request.getNickname())
                    .email(request.getEmail())
                    .build();

            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            memberRepository.save(member);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    public SignResponse getMember(String account) throws Exception {
        User member = memberRepository.findByAccount(account)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponse(member);
    }

}