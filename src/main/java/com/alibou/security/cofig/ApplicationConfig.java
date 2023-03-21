package com.alibou.security.cofig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.alibou.security.member.MemberRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

	private final MemberRepository memberRepository;

	@Bean
	public UserDetailsService userDetailsService() {
		return username -> memberRepository.findByEmail(username)
			.orElseThrow(() -> new UsernameNotFoundException("User not found"));
	}
}
