package com.saml2springsecurity.saml2.configuration;

import java.io.File;
import java.security.cert.X509Certificate;

import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	/**
	 * 1. Activate SAML 2 using http.authorizeRequests 2. Generation of the SP
	 * okta.xml file defined in "Audience URI" adress on Okta using:
	 * RelyingPartyRegistrationResolver
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests(authorize -> authorize.antMatchers("/").permitAll().anyRequest().authenticated())
				.saml2Login();
		
		RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
				relyingPartyRegistrationRepository);

		Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
				new OpenSamlMetadataResolver());

		http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
	}

	/**
	 * Configuring parameters for SAML2: Insert the values taken in Okta 1. Identity
	 * Provider Single Sign-On URL: we put that in "singleSignOnServiceLocation" 2.
	 * Identity Provider Issuer: we put it in "entityId" 3. Add the certificate in
	 * "verificationKey" -------------------------- The content of the certificate
	 * is put in /src/main/resources/saml-certificate/okta.crt
	 * -------------------------- PS: If you don’t want to create this bean we use
	 * the configuration in application.yaml file
	 */
	@Bean
	public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File verificationKey = new File(classLoader.getResource("okta.crt").getFile());
		X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
		Saml2X509Credential credential = Saml2X509Credential.verification(certificate);

		RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("okta-saml")
				.assertingPartyDetails(party -> party.entityId("http://www.okta.com/exk3zeodqse0ZMu065d7")
						.singleSignOnServiceLocation(
								"https://dev-46035401.okta.com/app/dev-46035401_samlapp2_1/exk3zeodqse0ZMu065d7/sso/saml")
						.wantAuthnRequestsSigned(false).verificationX509Credentials(c -> c.add(credential)))
				.build();
		return new InMemoryRelyingPartyRegistrationRepository(registration);
	}
}
