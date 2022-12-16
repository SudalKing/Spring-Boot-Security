package com.sp.fc.web.config;

import com.sp.fc.web.student.StudentAuthenticationToken;
import com.sp.fc.web.teacher.TeacherAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * authenticationManager를 주입하여 CustomLoginFilter을 bean처럼 사용하기 위함
     * @param authenticationManager
     */
    public CustomLoginFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    /**
     * UsernamePasswordAuthenticationFilter.java의
     * attemptAuthentication() method를 재정의하여 CustomFilter로 사용
     * @param request from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a
     * redirect as part of a multi-stage authentication process (such as OpenID).
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        username = (username != null) ? username : "";
        username = username.trim();

        String password = obtainPassword(request);
        password = (password != null) ? password : "";

        String type = request.getParameter("type");
        if(type == null || !type.equals("teacher")){
            // student
            StudentAuthenticationToken token = StudentAuthenticationToken.builder()
                    .credentials(username)
                    .build();
            return this.getAuthenticationManager().authenticate(token);
        } else {
            // teacher
            TeacherAuthenticationToken token = TeacherAuthenticationToken.builder()
                    .credentials(username)
                    .build();
            return this.getAuthenticationManager().authenticate(token);
        }
    }
}
