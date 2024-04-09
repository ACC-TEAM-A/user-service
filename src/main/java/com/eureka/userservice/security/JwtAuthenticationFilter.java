package com.eureka.userservice.security;

import com.eureka.userservice.security.JwtProvider;
import com.eureka.userservice.service.User.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Jwt가 유효성을 검증하는 Filter
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private ObjectMapper objectMapper;
    private UserService userService;
    private RedisTemplate<String, String> redisTemplate;
    private AuthenticationManager authenticationManager;


    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    public JwtAuthenticationFilter(JwtProvider jwtProvider, ObjectMapper objectMapper,
                                   UserService userService, RedisTemplate<String, String> redisTemplate) {
        this.jwtProvider = jwtProvider;
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.redisTemplate = redisTemplate;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = jwtProvider.resolveToken(request);

        if (token != null && jwtProvider.validateToken(token)) {
            // check access token
            token = token.split(" ")[1].trim();
            Authentication auth = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
//
//        // 로그인 추가 코드
//        try {
//            //header 에서 JWT 토큰이 있는지 검사
//            if(!StringUtils.hasText(token))  //토큰이 없는 경우
//                throw new NotExistingToken("토큰이 없습니다.");
//
//            //로그아웃된 토큰인지 검사
//            validBlackToken(token);
//
//            //JWT 토큰 만료기간 검증
//            jwtProvider.validTokenExpired(token);
//
//            if(!jwtProvider.validTokenHeaderUser(token))
//                throw new NotValidToken("정상적이지 않은 토큰입니다.");
//
//            Long userId = jwtProvider.getUserIdToToken(token);
//            User findUser = userService.findUserByUserId(userId);
//            PrincipalDetails principalDetails = new PrincipalDetails(findUser);
//            Authentication authentication = new UsernamePasswordAuthenticationToken(
//                    principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
//                    null, // 패스워드는 모르니까 null 처리, 어차피 지금 로그인 인증하는게 아니니까!!(로그인 필터를 사용하는게 아니니깐 지금)
//                    principalDetails.getAuthorities());
//            SecurityContextHolder.getContext().setAuthentication(authentication); //추가로 controller 단에서 해당 객체를 꺼낼수 있다.!
//
//            chain.doFilter(request,response);
//
//        }catch (ExpireTokenException e) { //기한만료된 토큰-201
//            sendResponse(response, e.getMessage(),
//                    HttpStatus.CREATED.value(), HttpStatus.CREATED.getReasonPhrase());
//            return;
//        }catch (BlackToken e) { //로그아웃된 토큰-401
//            sendResponse(response, e.getMessage(),
//                    HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
//            return;
//        } catch (NotExistingToken e){ //헤더에 토큰이 없는경우-412
//            sendResponse(response, e.getMessage(),
//                    HttpStatus.PRECONDITION_FAILED.value(),HttpStatus.PRECONDITION_FAILED.getReasonPhrase() );
//            return;
//        }catch (NotValidToken e) { //정상적이지 않은 토큰-401
//            sendResponse(response, e.getMessage(),
//                    HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
//            return;
//        }
//        catch (Exception e) { //나머지 서버 에러-500
//            sendResponse(response, e.getMessage(),
//                    HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
//            return;
//        }

//
//        // 로그인 추가 코드
//        private void validBlackToken(String accessToken) {
//
//            //Redis에 있는 엑세스 토큰인 경우 로그아웃 처리된 엑세스 토큰임.
//            String blackToken = redisTemplate.opsForValue().get(accessToken);
//            if(StringUtils.hasText(blackToken))
//                throw new BlackToken("로그아웃 처리된 엑세스 토큰입니다.");
//        }
//
//        // 로그인 추가 코드
//        private void sendResponse(HttpServletResponse response, String message, int code, String status ) throws IOException {
//
//            BaseErrorResult result = new BaseErrorResult(message, String.valueOf(code), status);
//
//            String res = objectMapper.writeValueAsString(result);
//            response.setStatus(code);
//            response.setContentType("application/json");
//            response.setCharacterEncoding("UTF-8");
//            response.getWriter().write(res);
//        }


    }




}