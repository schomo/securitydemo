package com.example.demo.security;

import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestDebugFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RequestDebugFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // 记录请求基本信息
        logger.info("====== Request Debug Info ======");
        logger.info("Request URL: {} {}", httpRequest.getMethod(), httpRequest.getRequestURL());
        logger.info("Origin: {}", httpRequest.getHeader("Origin"));
        logger.info("Referer: {}", httpRequest.getHeader("Referer"));

        // 记录所有请求头
        Collections.list(httpRequest.getHeaderNames()).forEach(headerName -> {
            logger.info("Header '{}': {}", headerName, httpRequest.getHeader(headerName));
        });

        // 记录Cookie信息
        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            logger.info("====== Cookies ======");
            for (Cookie cookie : cookies) {
                logger.info("Cookie '{}': {}", cookie.getName(), cookie.getValue());
            }
        }

        // 如果是POST请求，记录CSRF相关信息
        if ("POST".equalsIgnoreCase(httpRequest.getMethod())) {
            logger.info("====== CSRF Info ======");
            logger.info("CSRF Header: {}", httpRequest.getHeader("X-XSRF-TOKEN"));
            // 获取Spring Security的CSRF token
            CsrfToken csrfToken = (CsrfToken) httpRequest.getAttribute(CsrfToken.class.getName());
            if (csrfToken != null) {
                logger.info("Expected CSRF Token: {}", csrfToken.getToken());
            } else {
                logger.info("No CSRF Token found in request attributes");
            }
        }

        chain.doFilter(request, response);

        // 记录响应状态
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        logger.info("Response Status: {}", httpResponse.getStatus());
    }
}
