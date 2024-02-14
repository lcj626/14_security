package com.ohgiraffers.security.auth.model;

import com.ohgiraffers.security.auth.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails { // 우리가 UserDeatils 제공할테니 네가 만든 거 집어 넣어

    private User user;

    public DetailsUser() {
    }

    public DetailsUser(Optional<User> user) {
        this.user = user.get(); // 없는 값을 꺼내오면 에러가 나니 optional로 꺼내와서
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));

        return authorities;
    }

    @Override
    public String getPassword() { // 너가 알아서 만들면 우리가 알아서 가져다 쓸게


        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    /*
    * 계정 만료 여부 표현하는 메소드
    * false 이면 사용 x
    * */
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    /*계정이 잠겨있는지 확인 false이면 해당 계정 사용x
    * 비밀번호 반복 실패로 일시적인 계정 lock경우
    * */
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }


    /*
    * 탈퇴 계정 여부
    * false이면 사용x
    *
    * 데이터 삭제는 즉시 하는 것이 아닌 일정 기간 보관 후 삭제
    * */
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    /*
    * 계정 비화럿ㅇ화 여부로 사용자가 사용할 수 없는 상태
    * false 이면 사용 x
    *
    * 삭제 처리 같은 경우
    * */
    @Override
    public boolean isEnabled() {
        return false;
    }
}
