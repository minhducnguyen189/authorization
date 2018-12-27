package com.dxc.authorization.configuration;

import com.dxc.authorization.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.filter.GenericFilterBean;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@CrossOrigin(origins = "*")
public class JWTFilter extends GenericFilterBean {

    @Autowired
    private TokenService tokenService;

    JWTFilter() {
        this.tokenService = new TokenService();
    }


    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterchain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String token = request.getHeader("Authorization");

        if("OPTION".equalsIgnoreCase(request.getMethod())) {
            response.sendError(HttpServletResponse.SC_OK, "success");
            return;
        }

        if(AllowRequestWithoutToken(request)) {
            response.setStatus(HttpServletResponse.SC_OK);
            filterchain.doFilter(req, res);
        } else {
            if(token == null || !tokenService.isTokenValid(token)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else {
                String accountDetails = tokenService.identifyUsernameAndPassword(token);
                List<String> details = Arrays.stream(accountDetails.split(",")).collect(Collectors.toList());
                request.setAttribute("username", details.get(0));
                request.setAttribute("password", details.get(1));
                filterchain.doFilter(req, res);
            }
        }
    }

    public boolean AllowRequestWithoutToken(HttpServletRequest request) {
        System.out.println(request.getRequestURI());
        if(request.getRequestURI().contains("/v1/register")
                || request.getRequestURI().contains("/v1/login")
                || request.getRequestURI().contains("/v2/api-docs")
                || request.getRequestURI().contains("/configuration/ui")
                || request.getRequestURI().contains("/swagger-resources")
                || request.getRequestURI().contains("/configuration/security")
                || request.getRequestURI().contains("/swagger-ui.html")
                || request.getRequestURI().contains("/webjars/**")) {
            return true;
        }
        return false;
    }
}
