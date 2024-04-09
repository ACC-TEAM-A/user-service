package com.eureka.userservice.controller;

import com.eureka.userservice.dto.user.request.SignRequest;
import com.eureka.userservice.dto.user.response.SignResponse;
import com.eureka.userservice.repository.UserRepository;
import com.eureka.userservice.security.JwtProvider;
import com.eureka.userservice.service.User.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/member")
public class UserController {
    @GetMapping("")
    public String hello() {
        return "hello";
    }

    private final UserRepository userRepository;
    private final UserService userService;

    private final JwtProvider jwtProvider;

    /* 아래 코드는 임시 코드 */
    public UserController(UserRepository memberRepository, UserService memberService, JwtProvider jwtProvider) {
        this.userRepository = memberRepository;
        this.userService = memberService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping(value = "/login")
    public ResponseEntity<SignResponse> signin(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(userService.login(request), HttpStatus.OK);
    }

    @PostMapping(value = "/register")
    public ResponseEntity<Boolean> signup(@RequestBody SignRequest request) throws Exception {
        return new ResponseEntity<>(userService.register(request), HttpStatus.OK);
    }

    @PatchMapping(value = "/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader) throws Exception {
        String accessToken = jwtProvider.resolveAccessToken(authorizationHeader);
        String refreshToken = jwtProvider.resolveRefreshToken(authorizationHeader);

        userService.logout(refreshToken, accessToken);

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/user/get")
    public ResponseEntity<SignResponse> getUser(@RequestParam String account) throws Exception {
        return new ResponseEntity<>( userService.getMember(account), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<SignResponse> getUserForAdmin(@RequestParam String account) throws Exception {
        return new ResponseEntity<>( userService.getMember(account), HttpStatus.OK);
    }

}
