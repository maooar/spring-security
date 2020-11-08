package sample.legacy;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomTokenEnhancer extends JwtAccessTokenConverter implements TokenEnhancer {
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
		final Map<String, Object> additionalInfo = new HashMap<>();
		UserDetails user = (UserDetails) oAuth2Authentication.getUserAuthentication().getPrincipal();
//		additionalInfo.put("userName", user.getUsername());
//		additionalInfo.put("authorities", user.getAuthorities());
		((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(additionalInfo);
		return oAuth2AccessToken;
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
