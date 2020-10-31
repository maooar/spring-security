package sample.legacy;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * For configuring the end users recognized by this Authorization Server
 */
@Configuration
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {
	private FeignUserDetailService feignUserDetailService;

	WebSecurityConfigurer(FeignUserDetailService myUserDetailService){
		this.feignUserDetailService = myUserDetailService;
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
		return feignUserDetailService;
	}
}
