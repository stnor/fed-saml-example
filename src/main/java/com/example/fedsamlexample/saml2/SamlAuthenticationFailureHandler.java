package com.example.fedsamlexample.saml2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class SamlAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlAuthenticationFailureHandler.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if (exception.getCause() instanceof UsernameNotFoundException) {
            LOGGER.info("Attempt to log in with SAML, but has no existing Nomp account. Redirecting to /start/login/saml/create for {}", exception.getMessage());
            response.sendRedirect("/start/login/saml/create?username=" + URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8.name()));
        } else {
            LOGGER.warn("Unexpected error in SAML authentication", exception.getCause() == null ? exception : exception.getCause());
            response.sendRedirect("/start/login/saml/failure");
        }
    }
}
