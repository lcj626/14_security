package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.user.entity.User;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utils.ConvertUtil;
import com.ohgiraffers.security.common.utils.TokenUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler { // 요청 성공 시 수행되는 핸들러


    // 성공된 로그인 정보를 기반으로 토큰을 만들어 줌
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = ((DetailsUser) authentication.getPrincipal()).getUser();
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(user);
        HashMap<String, Object> responseMap = new HashMap<>();
        JSONObject jsonObject;

        if(user.getState().equals("N")){
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "휴면 상태인 계정입니다.");
        }else{
            String token = TokenUtils.generateJwtToken(user);
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "로그인 성공");

            response.addHeader(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);
        }

        jsonObject = new JSONObject(responseMap); // 인증을 실패했거나 성공했을때 담아져 있는 맵
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush(); // stream 값을 내보냄
        printWriter.close(); // 밀어줌

        // 여기까지 로그인에 필요한 successHandler

    }
}
