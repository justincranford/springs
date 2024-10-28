package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.Map;

@Service
@SuppressWarnings({"nls"})
public class CustomUserDetailsService implements UserDetailsService {
	@Autowired
    private PersonProperties personProperties;

    @PostConstruct
    public void loadUsers() {
        Map<String, PersonProperties.Person> users = this.personProperties.getUsers();
    }

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("User not found");
    }
}
