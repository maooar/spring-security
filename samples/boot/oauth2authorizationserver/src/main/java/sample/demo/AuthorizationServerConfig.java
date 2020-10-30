//package sample.demo;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.AuthorityUtils;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
//import org.springframework.security.oauth2.provider.ClientDetailsService;
//import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
//import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
//import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
//import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
//import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
//import org.springframework.stereotype.Component;
//import javax.sql.DataSource;
//import java.math.BigInteger;
//import java.security.KeyFactory;
//import java.security.KeyPair;
//import java.security.spec.RSAPrivateKeySpec;
//import java.security.spec.RSAPublicKeySpec;
//import java.util.Collection;
//import java.util.LinkedHashMap;
//import java.util.Map;
//
//@Configuration
//@EnableAuthorizationServer
//class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
//	@Autowired
//	private DataSource dataSource;
//	//jwt令牌转换器
//	@Autowired
//	private JwtAccessTokenConverter jwtAccessTokenConverter;
//	@Autowired
//	UserDetailsService userDetailsService;
//	@Autowired
//	AuthenticationManager authenticationManager;
//	@Autowired
//	TokenStore tokenStore;
//	@Autowired
//	private CustomUserAuthenticationConverter customUserAuthenticationConverter;
//	@Autowired
//	KeyPair keyPair;
//
//	//客户端配置
//	@Bean
//	public ClientDetailsService clientDetails() {
//		return new JdbcClientDetailsService(dataSource);
//	}
//	@Override
//	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//		clients.jdbc(this.dataSource).clients(this.clientDetails());
//       /* clients.inMemory()
//                .withClient("XcWebApp")//客户端id
//                .secret("XcWebApp")//密码，要保密
//                .accessTokenValiditySeconds(60)//访问令牌有效期
//                .refreshTokenValiditySeconds(60)//刷新令牌有效期
//                //授权客户端请求认证服务的类型authorization_code：根据授权码生成令牌，
//                // client_credentials:客户端认证，refresh_token：刷新令牌，password：密码方式认证
//                .authorizedGrantTypes("authorization_code", "client_credentials", "refresh_token", "password")
//                .scopes("app");//客户端范围，名称自定义，必填*/
//	}
//
//	//token的存储方法
////    @Bean
////    public InMemoryTokenStore tokenStore() {
////        //将令牌存储到内存
////        return new InMemoryTokenStore();
////    }
////    @Bean
////    public TokenStore tokenStore(RedisConnectionFactory redisConnectionFactory){
////        RedisTokenStore redisTokenStore = new RedisTokenStore(redisConnectionFactory);
////        return redisTokenStore;
////    }
//
//	@Bean
//	@Autowired
//	public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
//		return new JwtTokenStore(jwtAccessTokenConverter);
//	}
//
//	@Bean
//	public JwtAccessTokenConverter jwtAccessTokenConverter(CustomUserAuthenticationConverter customUserAuthenticationConverter) {
//		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//		converter.setKeyPair(keyPair);
//		//配置自定义的CustomUserAuthenticationConverter
//		DefaultAccessTokenConverter accessTokenConverter = (DefaultAccessTokenConverter) converter.getAccessTokenConverter();
//		accessTokenConverter.setUserTokenConverter(customUserAuthenticationConverter);
//		return converter;
//	}
//	//授权服务器端点配置
//	@Override
//	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        /*Collection<TokenEnhancer> tokenEnhancers = applicationContext.getBeansOfType(TokenEnhancer.class).values();
//        TokenEnhancerChain tokenEnhancerChain=new TokenEnhancerChain();
//        tokenEnhancerChain.setTokenEnhancers(new ArrayList<>(tokenEnhancers));
//
//        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//        defaultTokenServices.setReuseRefreshToken(true);
//        defaultTokenServices.setSupportRefreshToken(true);
//        defaultTokenServices.setTokenStore(tokenStore);
//        defaultTokenServices.setAccessTokenValiditySeconds(1111111);
//        defaultTokenServices.setRefreshTokenValiditySeconds(1111111);
//        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain);
//
//        endpoints
//                .authenticationManager(authenticationManager)
//                .userDetailsService(userDetailsService)
//                        //.tokenStore(tokenStore);
//                .tokenServices(defaultTokenServices);*/
//		endpoints.accessTokenConverter(jwtAccessTokenConverter)
//				.authenticationManager(authenticationManager)//认证管理器
//				.tokenStore(tokenStore)//令牌存储
//				.userDetailsService(userDetailsService);//用户信息service
//	}
//
//	//授权服务器的安全配置
//	@Override
//	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
////        oauthServer.checkTokenAccess("isAuthenticated()");//校验token需要认证通过，可采用http basic认证
//		oauthServer.allowFormAuthenticationForClients()
//				.passwordEncoder(new BCryptPasswordEncoder())
//				.tokenKeyAccess("permitAll()")
//				.checkTokenAccess("isAuthenticated()");
//	}
//}
//
//@Component
//class CustomUserAuthenticationConverter extends DefaultUserAuthenticationConverter {
//	@Autowired
//	UserDetailsService userDetailsService;
//
//	@Override
//	public Map<String, ?> convertUserAuthentication(Authentication authentication) {
//		LinkedHashMap response = new LinkedHashMap();
//		String name = authentication.getName();
//		response.put("user_name", name);
//
//		Object principal = authentication.getPrincipal();
//		UserJwt userJwt = null;
//		if(principal instanceof  UserJwt){
//			userJwt = (UserJwt) principal;
//		}else{
//			//refresh_token默认不去调用userdetailService获取用户信息，这里我们手动去调用，得到 UserJwt
//			UserDetails userDetails = userDetailsService.loadUserByUsername(name);
//			userJwt = (UserJwt) userDetails;
//		}
//		response.put("name", userJwt.getName());
//		response.put("id", userJwt.getId());
//		response.put("utype",userJwt.getUtype());
//		response.put("userpic",userJwt.getUserpic());
//		response.put("companyId",userJwt.getCompanyId());
//		if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
//			response.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
//		}
//		return response;
//	}
//}
//
//class UserJwt extends User {
//	private String id;
//	private String name;
//	private String userpic;
//	private String utype;
//	private String companyId;
//	public UserJwt(String username, String password, Collection<? extends GrantedAuthority> authorities) {
//		super(username, password, authorities);
//	}
//
//	public String getId() {
//		return id;
//	}
//
//	public void setId(String id) {
//		this.id = id;
//	}
//
//	public String getName() {
//		return name;
//	}
//
//	public void setName(String name) {
//		this.name = name;
//	}
//
//	public String getUserpic() {
//		return userpic;
//	}
//
//	public void setUserpic(String userpic) {
//		this.userpic = userpic;
//	}
//
//	public String getUtype() {
//		return utype;
//	}
//
//	public void setUtype(String utype) {
//		this.utype = utype;
//	}
//
//	public String getCompanyId() {
//		return companyId;
//	}
//
//	public void setCompanyId(String companyId) {
//		this.companyId = companyId;
//	}
//}
//
//@Configuration
//class KeyConfig {
//	@Bean
//	KeyPair keyPair() {
//		try {
//			String privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
//			String modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
//			String exponent = "65537";
//			RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
//			RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
//			KeyFactory factory = KeyFactory.getInstance("RSA");
//			return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));
//		} catch ( Exception e ) {
//			throw new IllegalArgumentException(e);
//		}
//	}
//}
