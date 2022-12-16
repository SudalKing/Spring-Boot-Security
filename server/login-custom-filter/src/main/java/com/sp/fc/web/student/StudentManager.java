package com.sp.fc.web.student;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Set;

/**
 * StudentManager class가 AuthenticationProvider가 되어 Set에 있는 id가 올 경우
 * 그에 대한 통행증을 발급함
 */
@Component
public class StudentManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String, Student> studentDB = new HashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        StudentAuthenticationToken token = (StudentAuthenticationToken) authentication;

        if(studentDB.containsKey(token.getCredentials())){
            Student student = studentDB.get(token.getCredentials());
            return StudentAuthenticationToken.builder()
                    .principal(student)
                    .details(student.getUsername())
                    .authenticated(true)
                    .build();
        }

        return null;
    }

    /**
     * target 설정
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == StudentAuthenticationToken.class;
    }

    /**
     * Test용 세팅
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Set.of(
                new Student("1", "사랑1", Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("2", "사랑2", Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("3", "사랑3", Set.of(new SimpleGrantedAuthority("ROLE_STUDENT")))

        ).forEach(
                s -> studentDB.put(s.getId(), s)
        );


    }
}
