package com.luv2code.springboot.cruddemo.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {

	static String employee_role = "EMPLOYEE";
	static String manager_role = "MANAGER";
	static String admin_role = "ADMIN";
	static String common_url = "/api/employees";

	@Bean
	public UserDetailsManager userDetailsManager(DataSource dataSource) {
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

		// ! define query to retrieve a user by username
		jdbcUserDetailsManager.setUsersByUsernameQuery("select user_id, pw, active from members where user_id=?");

		// ! define query to retrieve the authorities/roles by username
		jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("select user_id, role from roles where user_id=?");

		return jdbcUserDetailsManager;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(
				configurer -> configurer.requestMatchers(HttpMethod.GET, common_url).hasRole(employee_role)
						.requestMatchers(HttpMethod.GET, common_url + "/**").hasRole(employee_role)
						.requestMatchers(HttpMethod.POST, common_url).hasRole(manager_role)
						.requestMatchers(HttpMethod.PUT, common_url).hasRole(manager_role)
						.requestMatchers(HttpMethod.DELETE, common_url + "/**").hasRole(admin_role));

		// use basic authentication
		http.httpBasic(Customizer.withDefaults());

		// disable CSRF
		http.csrf(csrf -> csrf.disable());

		return http.build();

	}

}
