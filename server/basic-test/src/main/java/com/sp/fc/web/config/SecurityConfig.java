package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true) // PrePost로 권한 체크 시작
public class SecurityConfig{

    // void configure(AuthenticationManagerBuilder auth) --> InMemoryUserDetailsManager()
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        List<UserDetails> userDetailsList = new ArrayList<>();
        userDetailsList.add(User.builder()
                        .username("user2")
                        .password(passwordEncoder().encode("2222"))
                        .roles("USER")
                        .build());

        userDetailsList.add((User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("0000")))
                        .roles("ADMIN")
                        .build());

        return new InMemoryUserDetailsManager(userDetailsList);
    }

    // WebSecurityConfigurerAdapter/ HttpSecurity --> SecurityFilterChain(Bean 등록)
    // Chain으로 연결된 filter들 사이사이에 만든 filter를 껴넣는 method
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeRequests((requsts) ->
                requsts.antMatchers("/").permitAll() // home 접근 허용
                        .anyRequest().authenticated() // 그 외 허용 x
        );

        http.formLogin();
        http.httpBasic();

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



}