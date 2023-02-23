package com.example.fedsamlexample;

import com.example.fedsamlexample.saml2.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.example.fedsamlexample.saml2.Saml2LoginRedirectController.DISCOVERY_URL;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RefreshableRelyingPartyRegistrationRepository rpRepo,
                                           SkolfedSamlResponseAuthenticationConverter authConverter) throws Exception {
        var relyingPartyRegistrationResolver = new QueryStringRelyingPartyResolver(rpRepo);
        var authenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationResolver);
        authenticationRequestResolver.setRequestMatcher(new AntPathRequestMatcher("/saml/login"));
        var authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(authConverter);
        http.saml2Login(samlLogin ->
                samlLogin
                        .loginPage(DISCOVERY_URL)
                        .successHandler(samlSuccessRedirectHandler())
                        .failureHandler(new SamlAuthenticationFailureHandler())
                        .authenticationManager(new ProviderManager(authenticationProvider))
                        .authenticationRequestResolver(authenticationRequestResolver)
                        .authenticationConverter(new Saml2AuthenticationTokenConverter(relyingPartyRegistrationResolver))
                        .loginProcessingUrl("/saml/SSO"));
        http.saml2Logout(samlLogout ->
                samlLogout
                        .logoutUrl("/saml/SingleLogout")
                        .relyingPartyRegistrationRepository(rpRepo));
        Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());
        metadataFilter.setRequestMatcher(new AntPathRequestMatcher("/saml/metadata", "GET"));
        http.addFilterBefore(metadataFilter, BasicAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    SamlSavedRequestAwareAuthenticationSuccessHandler samlSuccessRedirectHandler() {
        var handler = new SamlSavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl("/");
        return handler;
    }
}
