package com.example.fedsamlexample.saml2;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import jakarta.servlet.http.HttpServletRequest;

public class QueryStringRelyingPartyResolver implements RelyingPartyRegistrationResolver {

    private final RelyingPartyRegistrationResolver delegate;

    public QueryStringRelyingPartyResolver(RelyingPartyRegistrationRepository registrations) {
        this.delegate = new DefaultRelyingPartyRegistrationResolver(registrations);
    }

    @Override
    public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
        relyingPartyRegistrationId = relyingPartyRegistrationId == null ? request.getParameter("idp") : relyingPartyRegistrationId;
        return this.delegate.resolve(request, relyingPartyRegistrationId);
    }
}
