package com.eureka.userservice.security;

public interface JwtProperties {
    String SECRET = "{}";
    int EXPIRATION_TIME =  1800000; // 30분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}