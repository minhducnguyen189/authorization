package com.dxc.authorization.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dxc.authorization.model.AccountEntity;
import com.dxc.authorization.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.Date;

@Service
public class TokenService {

    @Autowired
    private AccountRepository accountRepository;

    public static final String TOKEN_SECRET = "TOPSECRET";
    private static final String TOP_SECRET = "TOPSECRET";

    public String createToken(String username, String password) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            String token = JWT.create()
                    .withClaim("username", username)
                    .withClaim("password", password)
                    .withClaim("createDate", new Date())
                    .sign(algorithm);
            return token;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String identifyUsernameAndPassword(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            String username = jwt.getClaim("username").asString();
            String password = jwt.getClaim("password").asString();
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            AccountEntity accountEntity = accountRepository.findByUsername(username);
            if(bCryptPasswordEncoder.matches(password,accountEntity.getPassword())) {
                return username+","+password;
            }
            return null;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean isTokenValid(String token) {
        String accountDetails = this.identifyUsernameAndPassword(token);
        return accountDetails != null;
    }
}
