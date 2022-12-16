package com.sp.fc.web.config;

import com.sp.fc.web.student.StudentAuthenticationToken;
import com.sp.fc.web.student.StudentManager;
import com.sp.fc.web.teacher.Teacher;
import com.sp.fc.web.teacher.TeacherManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final StudentManager studentManager;
    private final TeacherManager teacherManager;

    public SecurityConfig(StudentManager studentManager, TeacherManager teacherManager) {
        this.studentManager = studentManager;
        this.teacherManager = teacherManager;
    }

    /**
     * studentManager를 provider로 사용
     * @param auth the {@link AuthenticationManagerBuilder} to use
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(studentManager);
        auth.authenticationProvider(teacherManager);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // formLogin자리에 CustomFilter삽입
        CustomLoginFilter filter = new CustomLoginFilter(authenticationManager());

        http
                .authorizeRequests(request->
                        request.antMatchers("/", "/login").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(
                        login -> login.loginPage("/login")
                                .permitAll()
                                .defaultSuccessUrl("/", false)
                                .failureUrl("/login-error")
                )
                // CustomFilter는 successUrl이나 failureUrl을 추가 코딩해야함
                // 그래서 formLogin과 같이 사용하며 기능을 지원받아도 크게 문제가 되지 않음
                .addFilterAt(filter, UsernamePasswordAuthenticationFilter.class) // formLogin 자리에 customFilter
                .logout(
                        logout -> logout.logoutSuccessUrl("/")
                )
                .exceptionHandling(
                        e -> e.accessDeniedPage("/access-denied")
                )
                ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                ;
    }
}
