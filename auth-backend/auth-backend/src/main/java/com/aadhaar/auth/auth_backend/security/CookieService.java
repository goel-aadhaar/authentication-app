package com.aadhaar.auth.auth_backend.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Data
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    private final Logger logger = LoggerFactory.getLogger(CookieService.class);

    public CookieService(
        @Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
        @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
        @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
        @Value("${security.jwt.cookie-domain}") String cookieDomain,
        @Value("${security.jwt.cookie-same-site}") String cookieSameSite
        ) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    public void attachRefreshCookie(HttpServletResponse response , String value , int maxAge) {

        logger.info("Attaching refresh cookie: name={}, domain={}, httpOnly={}, secure={}, sameSite={}",
                refreshTokenCookieName, cookieDomain, cookieHttpOnly, cookieSecure, cookieSameSite);
        var responseCookieBuilder = ResponseCookie.from(refreshTokenCookieName , value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);

        if(cookieDomain != null && !cookieDomain.isBlank()) {
            responseCookieBuilder.domain(cookieDomain);
        }

        ResponseCookie responseCookie = responseCookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE , responseCookie.toString());
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(refreshTokenCookieName , "")
                .maxAge(0)
                .httpOnly(cookieHttpOnly)
                .path("/")
                .sameSite(cookieSameSite)
                .secure(cookieSecure);

        if(cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }
    }

    public void addNoStoreHeaders(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL , "no-store");
        response.setHeader(HttpHeaders.PRAGMA , "no-cache");
    }
}
