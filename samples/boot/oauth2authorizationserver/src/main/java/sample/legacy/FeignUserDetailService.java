package sample.legacy;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.ArrayList;
import java.util.List;

public class FeignUserDetailService implements UserDetailsService {
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
		authList.add(new SimpleGrantedAuthority("ADMIN"));
		UserDetails userDetails = new User("lihua", "{noop}12345678",authList);
		return userDetails;
	}
}
