package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password Token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        // 임시 토큰을 쓸 수 있게 만드렁주느 ㄴ작업
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;
        String username = loginToken.getName(); // 토큰에 있는 name 갖고 옴
        String password = (String) loginToken.getCredentials(); // 토큰이 가지고 있는 값, 아이디랑 비밀번호를 String 값으로 전달


        // 2. DB에서 유제네임에 해당하는 정보를 조회한다.
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username); // 부모객체 형식으로 받아옴

        // 사용자가 입력한 username, password와 아이디의 비밀번호와 비교하는 로직을 수행함
        if(!passwordEncoder.matches(password, foundUser.getPassword())){ // 데이터베이스에 인코딩된 애랑 아닌 애(입력값)랑 같은지 비교
            throw new BadCredentialsException("password가 일치하지 않습니다");
        }

        return new UsernamePasswordAuthenticationToken(foundUser, password, foundUser.getAuthorities()); // 사용자 정보, 비번, 권한 목록
        //foundUser.getUser(), foundUser.getPassword(),foundUser.getAuthorities() 와 동일
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class); // 같은지 비교 같으면 인증 성공
    }
}
