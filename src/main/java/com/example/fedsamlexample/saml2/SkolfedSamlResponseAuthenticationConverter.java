package com.example.fedsamlexample.saml2;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.List;

@Component
public class SkolfedSamlResponseAuthenticationConverter implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> {

    private static final Logger log = LoggerFactory.getLogger(SkolfedSamlResponseAuthenticationConverter.class);
    private static final String ATTR_EDU_PERSON_PRINCIPAL_NAME = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";
    private static final String ATTR_MAIL = "urn:oid:0.9.2342.19200300.100.1.3";

    @Override
    public Saml2Authentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        Assertion assertion = responseToken.getResponse().getAssertions().get(0);
        assertion.getAttributeStatements().get(0).getAttributes();

        String extUserId = getAttribute(assertion, ATTR_EDU_PERSON_PRINCIPAL_NAME);
        String extUserName = getAttribute(assertion, ATTR_MAIL);

        log.info("eppn={}, mail={}", extUserId, extUserName);

        Assert.notNull(extUserId, "The EPPN attribute (urn:oid:1.3.6.1.4.1.5923.1.1.1.6) is mandatory");
        Assert.notNull(extUserName, "The MAIL attribute (urn:oid:0.9.2342.19200300.100.1.3) is mandatory");

        var userDetails = new CustomUserDetails(extUserName);
        return new Saml2Authentication(userDetails, authentication.getSaml2Response(), userDetails.getAuthorities());
    }

    private String getAttribute(Assertion assertion, String oid)
    {
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements())
        {
            for (Attribute attribute : attributeStatement.getAttributes())
            {
                if (oid.equals(attribute.getName()))
                {
                    List<XMLObject> attributeValues = attribute.getAttributeValues();
                    if (!attributeValues.isEmpty())
                    {
                        return getAttributeValue(attributeValues.get(0));
                    }
                }
            }
        }
        throw new IllegalArgumentException("no username attribute found");
    }

    private String getAttributeValue(XMLObject attributeValue)
    {
        return attributeValue == null ?
                null :
                attributeValue instanceof XSString ?
                        getStringAttributeValue((XSString) attributeValue) :
                        attributeValue instanceof XSAnyImpl ?
                                getAnyAttributeValue((XSAnyImpl) attributeValue) :
                                attributeValue.toString();
    }

    private String getStringAttributeValue(XSString attributeValue)
    {
        return attributeValue.getValue();
    }

    private String getAnyAttributeValue(XSAnyImpl attributeValue)
    {
        return attributeValue.getTextContent();
    }
}
