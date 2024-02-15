package com.ohgiraffers.security.auth.user.service;

import com.ohgiraffers.security.auth.user.entity.User;
import com.ohgiraffers.security.auth.user.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private UserRepository userRepository;
    private BCryptPasswordEncoder encoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    public Optional<User> findUser(String id){
        Optional<User> user = userRepository.findByUserId(id);

        return user;
    }

    public User signup(User user) {

        user.setUserPass(encoder.encode(user.getUserPass()));
        user.setState("Y");

        User signup = userRepository.save(user);

        return signup;
    }
}
