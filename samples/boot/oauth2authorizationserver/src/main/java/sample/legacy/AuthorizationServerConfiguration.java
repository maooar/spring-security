/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.legacy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.security.KeyPair;
import java.util.*;

/**
 * An instance of Legacy Authorization Server (spring-security-oauth2) that uses a single,
 * not-rotating key and exposes a JWK endpoint.
 *
 * See
 * <a
 * 	target="_blank"
 * 	href="https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/">
 * 	Spring Security OAuth Autoconfig's documentation</a> for additional detail
 *
 * @author Josh Cummings
 * @since 5.1
 */
@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	AuthenticationManager authenticationManager;
	@Value("${security.oauth2.authorizationserver.jwt.enabled:true}")
	private boolean jwtEnabled;
	private KeyPair keyPair;
	private TokenStore tokenStore;
	private JwtAccessTokenConverter jwtAccessTokenConverter;
	private SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter;
	private FeignUserDetailService feignUserDetailService;
	private CustomTokenEnhancer customTokenEnhancer;

	public AuthorizationServerConfiguration(
			AuthenticationConfiguration authenticationConfiguration,
			KeyPair keyPair,
			TokenStore tokenStore,
			JwtAccessTokenConverter jwtAccessTokenConverter,
			SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter,
			FeignUserDetailService feignUserDetailService,
			CustomTokenEnhancer customTokenEnhancer
	) throws Exception {
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.tokenStore = tokenStore;
		this.jwtAccessTokenConverter = jwtAccessTokenConverter;
		this.subjectAttributeUserTokenConverter = subjectAttributeUserTokenConverter;
		this.keyPair = keyPair;
		this.feignUserDetailService = feignUserDetailService;
		this.customTokenEnhancer = customTokenEnhancer;
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
//		JdbcClientDetailsService jdbcClientDetailsService=new JdbcClientDetailsService(dataSource);
//		jdbcClientDetailsService.setPasswordEncoder(new BCryptPasswordEncoder());
		InMemoryClientDetailsService InMemoryClientDetailsService=new InMemoryClientDetailsService();
		Map<String, ClientDetails> map = new HashMap();

		BaseClientDetails details = new BaseClientDetails();
//		details.setClientId(UUID.randomUUID().toString());
//		details.setClientSecret(UUID.randomUUID().toString());
		details.setClientId("demo");
		details.setClientSecret("{noop}secret");
//		details.setClientSecret(passwordEncoder().encode("secret"));
		details.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "password", "client_credentials","implicit", "refresh_token"));
		details.setScope(Arrays.asList("message:read"));
//		details.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
		details.setRegisteredRedirectUri(Collections.<String>emptySet());
//		details.setAccessTokenValiditySeconds(10);
//		details.setRefreshTokenValiditySeconds(20);

		map.put(details.getClientId(),details);
		InMemoryClientDetailsService.setClientDetailsStore(map);
		clients.withClientDetails(InMemoryClientDetailsService);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.authenticationManager(this.authenticationManager);
		endpoints.tokenStore(tokenStore);
		if (jwtEnabled) {
			endpoints.accessTokenConverter(jwtAccessTokenConverter);
			endpoints.userDetailsService(feignUserDetailService);
		}
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		List<TokenEnhancer> delegates = new ArrayList<>();
		delegates.add(customTokenEnhancer);
		delegates.add(jwtAccessTokenConverter);
		tokenEnhancerChain.setTokenEnhancers(delegates);
		endpoints.tokenEnhancer(tokenEnhancerChain);
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer
//			.realm("oauth2-resources")
//			url:/oauth/token_key,exposes public key for token verification if using JWT tokens
//			.tokenKeyAccess("permitAll()")
//			url:/oauth/check_token allow check token
//			.checkTokenAccess("isAuthenticated()")
				.allowFormAuthenticationForClients();
	}

//	@Primary
//	@Bean
//	public DefaultTokenServices defaultTokenServices() {
//		DefaultTokenServices tokenServices = new DefaultTokenServices();
//		tokenServices.setTokenStore(tokenStore);
//		tokenServices.setSupportRefreshToken(true);
//		tokenServices.setAccessTokenValiditySeconds(60 * 60 * 12);
//		tokenServices.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7);
//		tokenServices.setReuseRefreshToken(false);
//		return tokenServices;
//	}
}
