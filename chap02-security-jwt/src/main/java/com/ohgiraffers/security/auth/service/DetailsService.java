package com.ohgiraffers.security.auth.service;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.user.service.UserService;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DetailsService implements UserDetailsService {

    private final UserService userService;

    public DetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //유효성 검사 진행함
//        if(username.isEmpty()){
//            throw new UsernameNotFoundException("사용자 정보가 입력되지 않았습니다");
//        }
        if(username == null || username.equals("")){
            throw new AuthenticationServiceException(username + " is Empty");
        }



        //DB에서 username에 해당하는 정보를 꺼내온다

        return userService.findUser(username)
                .map(data -> new DetailsUser(Optional.of(data)))
                .orElseThrow(()-> new AuthenticationServiceException(username));
    }
}
