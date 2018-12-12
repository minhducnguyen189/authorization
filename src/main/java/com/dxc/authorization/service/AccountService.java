package com.dxc.authorization.service;

import com.dxc.authorization.api.model.Account;
import com.dxc.authorization.model.AccountEntity;
import com.dxc.authorization.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AccountService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TokenService tokenService;

    private static final String TOP_SECRET = "TOPSECRET";


    public String addAccount(Account account) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String passwordEncoded = bCryptPasswordEncoder.encode(account.getPassword()+","+TOP_SECRET);
        AccountEntity accountEntity = new AccountEntity();
        accountEntity.setUsername(account.getUsername());
        accountEntity.setPassword(passwordEncoded);
        accountRepository.saveAndFlush(accountEntity);
        return "Register Success";
    }

    public String login(String username, String password) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        password = password+","+TOP_SECRET;
        AccountEntity accountEntity = accountRepository.findByUsername(username);
        if(bCryptPasswordEncoder.matches(password,accountEntity.getPassword())) {
            String token =tokenService.createToken(username, password);
            return token;
        }
        return "Account Doesn't existed";
    }

    public Account checkLogin(String authorization) {
        if(tokenService.isTokenValid(authorization)) {
            String accountDetails = tokenService.identifyUsernameAndPassword(authorization);
            List<String> details = Arrays.stream(accountDetails.split(",")).collect(Collectors.toList());
            AccountEntity accountExisted = accountRepository.findByUsername(details.get(0));
            Account account = new Account();
            account.setId(new BigDecimal(accountExisted.getId()));
            account.setUsername(accountExisted.getUsername());
            account.setPassword(accountExisted.getPassword());
            return account;
        }
        return null;
    }
}
