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

package sample;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

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

	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	AuthenticationManager authenticationManager;
	KeyPair keyPair;
	boolean jwtEnabled;
	TokenStore tokenStore;

	public AuthorizationServerConfiguration(
			AuthenticationConfiguration authenticationConfiguration,
			KeyPair keyPair,
			@Value("${security.oauth2.authorizationserver.jwt.enabled:true}") boolean jwtEnabled) throws Exception {

		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.jwtEnabled = jwtEnabled;
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
		clients.withClientDetails(clientDetails());
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		// @formatter:off
		endpoints
			.authenticationManager(this.authenticationManager)
			.tokenStore(tokenStore());

		if (this.jwtEnabled) {
			endpoints
				.accessTokenConverter(accessTokenConverter());
		}
		// @formatter:on
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

	@Bean
	public TokenStore tokenStore() {
		if(this.tokenStore != null) {
			return this.tokenStore;
		}
		if (this.jwtEnabled) {
			this.tokenStore = new JwtTokenStore(accessTokenConverter());
		} else {
			this.tokenStore = new InMemoryTokenStore();
		}
		return this.tokenStore;
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(this.keyPair);
		converter.setAccessTokenConverter(accessTokenConverter);
		return converter;
	}

	@Bean
	public ClientDetailsService clientDetails() {
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
		return InMemoryClientDetailsService;
	}

	/**
	 * <p>注意，自定义TokenServices的时候，需要设置@Primary，否则报错，</p>
	 * @return
	 */
	@Primary
	@Bean
	public DefaultTokenServices defaultTokenServices() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setClientDetailsService(clientDetails());
		// token有效期自定义设置，默认12小时
		tokenServices.setAccessTokenValiditySeconds(60 * 60 * 12);
		//默认30天，这里修改
		tokenServices.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7);
		tokenServices.setReuseRefreshToken(false);
		return tokenServices;
	}
}

/**
 * For configuring the end users recognized by this Authorization Server
 */
@Configuration
class UserConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.mvcMatchers("/.well-known/jwks.json")
			.permitAll()
			.anyRequest().authenticated()
			.and()
				.httpBasic()
			.and()
				.csrf().ignoringRequestMatchers((request) -> "/introspect".equals(request.getRequestURI()));
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(new MyUserDetailService())
//			.passwordEncoder(new BCryptPasswordEncoder())
//			.and()
//			.authenticationProvider(smsAuthenticationProvider())
//			.authenticationProvider(authenticationProvider())
		;
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
//		return new InMemoryUserDetailsManager(
//			User.withDefaultPasswordEncoder()
//				.username("lihua")
//				.password("12345678")
//				.roles("USER")
//				.build());
//		}
		return new MyUserDetailService();
	}
}

class MyUserDetailService implements UserDetailsService {
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

//		// 根据用户名查询数据库，查到对应的用户
//		MyUser myUser = authenticationMapper.loadUserByUsername(name);
//		// ... 做一些异常处理，没有找到用户之类的
//		if (myUser == null) {
//			throw new UsernameNotFoundException("用户不存在");
//		}
//		// 根据用户ID，查询用户的角色
//		List<Role> roles = authenticationMapper.findRoleByUserId(myUser.getId());
//		// 添加角色
//		List<GrantedAuthority> authorities = new ArrayList<>();
//		for (Role role : roles) {
//			authorities.add(new SimpleGrantedAuthority(role.getName()));
//		}
//		// 构建 Security 的 User 对象
//		return new User(myUser.getName(), myUser.getPassword(), authorities);

		List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>();
		authList.add(new SimpleGrantedAuthority("USER"));
		UserDetails userDetails = new User("lihua", "{noop}12345678",authList);
		return userDetails;
	}
}

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any
 * Token Introspection endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
@FrameworkEndpoint
class IntrospectEndpoint {
	TokenStore tokenStore;

	IntrospectEndpoint(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@PostMapping("/introspect")
	@ResponseBody
	public Map<String, Object> introspect(@RequestParam("token") String token) {
		OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(token);
		Map<String, Object> attributes = new HashMap<>();
		if (accessToken == null || accessToken.isExpired()) {
			attributes.put("active", false);
			return attributes;
		}

		OAuth2Authentication authentication = this.tokenStore.readAuthentication(token);

		attributes.put("active", true);
		attributes.put("exp", accessToken.getExpiration().getTime());
		attributes.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
		attributes.put("sub", authentication.getName());

		return attributes;
	}
}

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any
 * <a href target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
@FrameworkEndpoint
class JwkSetEndpoint {
	KeyPair keyPair;

	JwkSetEndpoint(KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey() {
		RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
		RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}
}

/**
 * An Authorization Server will more typically have a key rotation strategy, and the keys will not
 * be hard-coded into the application code.
 *
 * For simplicity, though, this sample doesn't demonstrate key rotation.
 */
@Configuration
class KeyConfig {
	@Bean
	KeyPair keyPair() {
		try {
			String privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
			String modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
			String exponent = "65537";

			RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
			RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
			KeyFactory factory = KeyFactory.getInstance("RSA");
			return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}
}

/**
 * Legacy Authorization Server does not support a custom name for the user parameter, so we'll need
 * to extend the default. By default, it uses the attribute {@code user_name}, though it would be
 * better to adhere to the {@code sub} property defined in the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT Specification</a>.
 */
class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
	@Override
	public Map<String, ?> convertUserAuthentication(Authentication authentication) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("sub", authentication.getName());
		if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
			response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
		}
		return response;
	}
}

/**
 * I created this Class extending the JWTAccesTokenConverter that in case the existing
 * refresh token is already a valid JWT it replaced it with the existing one
*/
//class PreserveRefreshTokenJwtAcesTokenConverter extends JwtAccessTokenConverter implements TokenEnhancer {
//	private static final Logger LOG =LoggerFactory.getLogger(PreserveRefreshTokenJwtAcesTokenConverter.class);
//	@Override
//	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
//		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
//		OAuth2AccessToken converted = super.enhance(accessToken, authentication);
//		if(refreshToken!=null&& refreshToken.getValue()!=null) {
//			//Preserve previous refresh token if it was already a valid JWT token.
//			try {
//				JwtHelper.decode(refreshToken.getValue());
//				((DefaultOAuth2AccessToken)converted).setRefreshToken(refreshToken);
//			}catch(IllegalArgumentException e) {
//				LOG.debug("Existing refresh token is not a valid JWT, using the new generated refresh token",e);
//			}
//		}
//		return converted;
//	}
//}

