package com.aadhaar.auth.auth_backend.security;

import com.aadhaar.auth.auth_backend.helpers.UserHelper;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.UUID;

@Component
@AllArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final JWTService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

//        no token
        if(header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request , response);
            return;
        }

//        if already authenticated
        if(SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request , response);
            return;
        }

            String token = header.substring(7);


            try {
                if(!jwtService.isAccessToken(token)) {
                    filterChain.doFilter(request , response);
                    return;
                }
                Jws<Claims> parse =  jwtService.parse(token);

                Claims payload = parse.getPayload();

                String userId = payload.getSubject();
                UUID userUUID = UserHelper.parseUUID(userId);

                var userOpt = userRepository.findById(userUUID);

                if(userOpt.isEmpty() || !userOpt.get().isEnable()) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }

                var user = userOpt.get();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                user.getEmail(),
                                null,
                                user.getAuthorities()
                        );
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (ExpiredJwtException e) {
                request.setAttribute("error", "Token Expired");
//                e.printStackTrace();
            } catch (Exception e) {
                request.setAttribute("error", "Invalid Token");
//                e.printStackTrace();
            }
        filterChain.doFilter(request , response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/register")
                || path.equals("/api/v1/auth/refresh")
                || path.equals("/api/v1/auth/logout");
    }
}
