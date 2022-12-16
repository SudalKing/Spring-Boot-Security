package com.sp.fc.web.config;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;

@Component
public class CustomAuthDetails implements AuthenticationDetailsSource<HttpServletRequest, RequestInfo> {

    @Override
    public RequestInfo buildDetails(HttpServletRequest context) {
        return RequestInfo.builder()
                .remoteIp(context.getRemoteAddr())
                .sessionId(context.getSession().getId())
                .loginTime(LocalDateTime.now())
                .build();
    }

}
