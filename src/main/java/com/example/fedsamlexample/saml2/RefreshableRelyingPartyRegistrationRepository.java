package com.example.fedsamlexample.saml2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Component
public class RefreshableRelyingPartyRegistrationRepository
        implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {
    private final static Logger LOGGER = LoggerFactory.getLogger(RefreshableRelyingPartyRegistrationRepository.class);
    private static final char[] SAML_JKS_PASSWORD = "example".toCharArray();
    public static final String SAML_JKS_PATH = "classpath:saml/saml.jks";
    public static final String SAML_JKS_ALIAS = "saml";
    private final Map<String, RelyingPartyRegistration> relyingPartyRegistrations = new ConcurrentHashMap<>();
    private static final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private final Saml2X509Credential signingCredentials;

    public RefreshableRelyingPartyRegistrationRepository() {
        this.signingCredentials = createSigningCredentials();
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        return this.relyingPartyRegistrations.get(registrationId);
    }

    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        return this.relyingPartyRegistrations.values().iterator();
    }

    @Scheduled(fixedRate = 30, timeUnit = TimeUnit.MINUTES)
    public void refreshMetadata() {
        fetchMetadata();
    }

    void fetchMetadata() {
        LOGGER.info("Fetching metadata from Skolfederation");
        //All IdP:s
        RelyingPartyRegistrations
                .collectionFromMetadataLocation("https://fed.skolfederation.se/prod/md/skolfederation-3_1.xml")
                .forEach(builder -> {
                    builder.entityId("https://nomp.se");
                    builder.assertionConsumerServiceLocation("https://nomp.se/saml/SSO");
                    builder.signingX509Credentials(credentials -> credentials.add(this.signingCredentials));
                    builder.assertingPartyDetails(apdBuilder -> {
                        apdBuilder.wantAuthnRequestsSigned(true);
                    });
                    RelyingPartyRegistration idp = builder.build();
                    this.relyingPartyRegistrations.put(idp.getRegistrationId(), idp);
                });
        LOGGER.info("Registered {} IdPs", this.relyingPartyRegistrations.size());
    }

    /**
     * This project's metadata is not valid in the Skolfederation prod environment
     */
    private Saml2X509Credential createSigningCredentials() {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(resourceLoader.getResource(SAML_JKS_PATH).getInputStream(), SAML_JKS_PASSWORD);
            var cert = (X509Certificate) ks.getCertificate(SAML_JKS_ALIAS);
            var key = (PrivateKey) ks.getKey(SAML_JKS_ALIAS, SAML_JKS_PASSWORD);
            return new Saml2X509Credential(key, cert, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        } catch (Exception e){
           throw new RuntimeException(e);
        }
    }

}
