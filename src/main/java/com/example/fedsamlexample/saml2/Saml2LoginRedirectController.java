package com.example.fedsamlexample.saml2;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class Saml2LoginRedirectController {
    public final static String LEGACY_DISCOVERY = "/saml/login";
    public final static String DISCOVERY_URL = "/saml/discovery";
    public static final String IDP_SELECTION_REDIRECT_TARGET = "/start/login/saml";

    @RequestMapping(DISCOVERY_URL)
    public RedirectView discovery() {
        return new RedirectView(IDP_SELECTION_REDIRECT_TARGET);
    }

    @RequestMapping(LEGACY_DISCOVERY)
    public RedirectView legacyDiscovery() {
        return new RedirectView(IDP_SELECTION_REDIRECT_TARGET);
    }

}
