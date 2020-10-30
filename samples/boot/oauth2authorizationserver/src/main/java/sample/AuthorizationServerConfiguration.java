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
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
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
import org.springframework.security.oauth2.provider.token.*;
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

	AuthenticationManager authenticationManager;
	@Value("${security.oauth2.authorizationserver.jwt.enabled:true}")
	private boolean jwtEnabled;
	private KeyPair keyPair;
	private TokenStore tokenStore;
	private JwtAccessTokenConverter jwtAccessTokenConverter;
	private SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter;
	private MyUserDetailService myUserDetailService;
	private CustomTokenEnhancer customTokenEnhancer;

	public AuthorizationServerConfiguration(
			AuthenticationConfiguration authenticationConfiguration,
			KeyPair keyPair,
			TokenStore tokenStore,
			JwtAccessTokenConverter jwtAccessTokenConverter,
			SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter,
			MyUserDetailService myUserDetailService,
			CustomTokenEnhancer customTokenEnhancer
		) throws Exception {
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.keyPair = keyPair;
		this.tokenStore = tokenStore;
		this.jwtAccessTokenConverter = jwtAccessTokenConverter;
		this.subjectAttributeUserTokenConverter = subjectAttributeUserTokenConverter;
		this.keyPair = keyPair;
		this.myUserDetailService = myUserDetailService;
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
			endpoints.userDetailsService(myUserDetailService);
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

/**
 * For configuring the end users recognized by this Authorization Server
 */
@Configuration
class UserConfig extends WebSecurityConfigurerAdapter {
	private MyUserDetailService myUserDetailService;

	UserConfig(MyUserDetailService myUserDetailService){
		this.myUserDetailService = myUserDetailService;
	}

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

	@Override
	public UserDetailsService userDetailsService() {
		return myUserDetailService;
	}
}

@Component
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
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}
}


@Configuration
class Config {

	@Value("${security.oauth2.authorizationserver.jwt.enabled:true}")
	private boolean jwtEnabled;
	private SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter;

	Config(SubjectAttributeUserTokenConverter subjectAttributeUserTokenConverter) {
		this.subjectAttributeUserTokenConverter = subjectAttributeUserTokenConverter;
	}

	/**
	 * An Authorization Server will more typically have a key rotation strategy, and the keys will not
	 * be hard-coded into the application code.
	 *
	 * For simplicity, though, this sample doesn't demonstrate key rotation.
	 */
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

	@Bean
	public TokenStore tokenStore() {
		if (jwtEnabled) {
			return new JwtTokenStore(jwtAccessTokenConverter());
		} else {
			return new InMemoryTokenStore();
		}
	}

	@Bean
	public AccessTokenConverter AccessTokenConverter() {
		DefaultAccessTokenConverter datc = new DefaultAccessTokenConverter();
		datc.setUserTokenConverter(subjectAttributeUserTokenConverter);
		return datc;
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
//		DefaultAccessTokenConverter datc = new DefaultAccessTokenConverter();
		//TODO refreshToken时subjectAttributeUserTokenConverter失效？？
//		datc.setUserTokenConverter(subjectAttributeUserTokenConverter);
		JwtAccessTokenConverter jatc = new JwtAccessTokenConverter();
		jatc.setKeyPair(keyPair());
//		jatc.setAccessTokenConverter(datc);
		return jatc;
	}
}

//向JSON WEB TOKEN中插入自定义字段
@Component
class CustomTokenEnhancer implements TokenEnhancer {
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
		final Map<String, Object> additionalInfo = new HashMap<>();
		//获取登录信息
		UserDetails user = (UserDetails) oAuth2Authentication.getUserAuthentication().getPrincipal();
		additionalInfo.put("userName", user.getUsername());
//		additionalInfo.put("authorities", user.getAuthorities());
		((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(additionalInfo);
		return oAuth2AccessToken;
	}
}

/**
 * Legacy Authorization Server does not support a custom name for the user parameter, so we'll need
 * to extend the default. By default, it uses the attribute {@code user_name}, though it would be
 * better to adhere to the {@code sub} property defined in the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT Specification</a>.
 */
//修改user_name字段名称
//TODO JwtAccessTokenConverter模式下，修改以后refreshToken会丢失该字段？
@Component
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

