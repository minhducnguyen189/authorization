package com.dxc.authorization.repository;

import com.dxc.authorization.model.AccountEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountRepository extends JpaRepository<AccountEntity, Long> {

    @Query("select a from AccountEntity a where a.username = :username and a.password = :password")
    AccountEntity findAccountByUsernameAndPassword(@Param("username") String username, @Param("password") String password);

    AccountEntity findByUsername(String username);

}
