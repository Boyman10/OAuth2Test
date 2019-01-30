package com.example.spboottest.interceptors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.time.LocalDateTime;

@Component
public class CustomRequestInterceptor extends HandlerInterceptorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(CustomRequestInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {

        long startTime = Instant.now().toEpochMilli();
        logger.debug("Request URL::" + request.getRequestURL().toString() +
                ":: Start Time=" + Instant.now());
        request.setAttribute("startTime", startTime);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {

        long startTime = (Long) request.getAttribute("startTime");

        logger.debug("Request URL::" + request.getRequestURL().toString() +
                ":: Time Taken=" + (Instant.now().toEpochMilli() - startTime));
    }
}