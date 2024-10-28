package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

@Service
@SuppressWarnings({"nls"})
public class LoadableUserDetailsService implements UserDetailsService {
	@Autowired
    private PersonProperties personProperties;

    @PostConstruct
    public void loadUsers() {
        List<PersonProperties.Person> users = this.personProperties.getUsers();
    }

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("User not found");
    }
}
