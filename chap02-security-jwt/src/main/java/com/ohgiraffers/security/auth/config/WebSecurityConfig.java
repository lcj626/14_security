package com.ohgiraffers.security.auth.config;

import com.ohgiraffers.security.auth.filter.CustomAuthenticationFilter;
import com.ohgiraffers.security.auth.handler.CustomAuthFailureHandler;
import com.ohgiraffers.security.auth.handler.CustomAuthSuccessHandler;
import com.ohgiraffers.security.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class WebSecurityConfig {

    /*
    * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메소드
    *
    * @return WebSecurityCustomizer
    * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        // 요청 리소스가 static resources을 등록하지 않겠다
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /*
    * security filter chain 설정
    *
    * @return SecurityFilterChain
    * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        //Cross-Site Request Forgery 사이트 교차 위조(사이트가 나인척 요청 날림)
        http.csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)    //BasicAuth~ 대신에 jwtAuthor를 쓸거다
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  //시큐리티 통해 세션 만들지 않겠다
                .formLogin(form -> form.disable()) // 스프링 시큐리티에서 제공하는 form을 사용하지 않겠다
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic(basic -> basic.disable());

        return http.build();
    }

    /*
    * 3. Authentication의 인증 메소드를 제공하는 매니저로 Provider의 인터페이스를 의미한다.
    * @return AuthenticationManager
    * */
    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(customAuthenticationProvider());
    }

    /*
    * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다.
    *
    * @return CustomAuthenticationProvider
    * */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }

    /*
    * 5. 비밀번호를 암호화 하는 인코더
    *
    * @return BCryptPasswordEncoder
    * */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){ //빈으로 등록
        return new BCryptPasswordEncoder();
    }

    /*
    * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
    * @return CustomAuthenticationFilter
    * */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter(){
        CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        //위 3번에서 만들었던 manager -> Provider를 커스텀마이즈 해서 결합 구조 좀 느슨하게

        authenticationFilter.setFilterProcessesUrl("/login"); // 어떤 요청 리소스가 로그인 요청이야 물어보는 것 /login 에 post 요청 날리면 인식
        authenticationFilter.setAuthenticationSuccessHandler(customAuthSuccessHandler());
        authenticationFilter.setAuthenticationFailureHandler(customAuthFailureHandler());

        return customAuthenticationFilter();

    }

    /**
    * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
    * @return customAuthLoginSuccessHandler
    * */
    @Bean
    public CustomAuthSuccessHandler customAuthSuccessHandler(){
        return new CustomAuthSuccessHandler();
    }

    /**
     * 8. spring security의 사용자 정보가 맞지 않은 경우 수행되는 메서드
     * @return CustomAuthFailureHandler
     * */
    @Bean
    public CustomAuthFailureHandler customAuthFailureHandler(){
        return new CustomAuthFailureHandler();
    }
}
