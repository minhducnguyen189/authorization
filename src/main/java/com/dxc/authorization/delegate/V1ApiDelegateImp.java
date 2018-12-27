package com.dxc.authorization.delegate;

import com.dxc.authorization.api.V1ApiDelegate;
import com.dxc.authorization.api.model.Account;
import com.dxc.authorization.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;

@Component
public class V1ApiDelegateImp implements V1ApiDelegate {

    @Autowired
    private AccountService accountService;


    @Override
    public ResponseEntity<String> addAccount(Account account) {
        return ResponseEntity.ok(accountService.addAccount(account));
    }

    @Override
    public ResponseEntity<Account> getAccount(String authorization) {
        return ResponseEntity.ok(accountService.checkLogin(authorization));
    }

    @Override
    public ResponseEntity<String> login(String username, String password) {
        return ResponseEntity.ok(accountService.login(username, password));
    }
}
