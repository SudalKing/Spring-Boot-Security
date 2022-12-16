package com.sp.fc.web.teacher;

import com.sp.fc.web.student.Student;
import com.sp.fc.web.student.StudentAuthenticationToken;
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
public class TeacherManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String, Teacher> teacherDB = new HashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        TeacherAuthenticationToken token = (TeacherAuthenticationToken) authentication;

        if(teacherDB.containsKey(token.getCredentials())){
            Teacher teacher = teacherDB.get(token.getCredentials());
            return TeacherAuthenticationToken.builder()
                    .principal(teacher)
                    .details(teacher.getUsername())
                    .authenticated(true)
                    .build();
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }

    /**
     * Test용 세팅
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Set.of(
                new Teacher("choi", "최선생", Set.of(new SimpleGrantedAuthority("ROLE_TEACHER")))

        ).forEach(
                s -> teacherDB.put(s.getId(), s)
        );


    }
}
