package com.alibou.security.cofig;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.alibou.security.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	// checking jwt token
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		// jwt or bearer token
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			// need to pass the request and the response to the next filter
			filterChain.doFilter(request, response);
			return;
		}
		jwt = authHeader.substring(7);

		// extract the userEmail from JWT token;
		userEmail = jwtService.extractUsername(jwt);
		// 1. if we have our user email and the user not authenticated
		if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			// 2. get the user details from database
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
			// 3. check if the user is valid or not
			if (jwtService.isTokenValid(jwt, userDetails)) {
				// 4. if the user and token is valid, create the authentication token
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					userDetails, null, userDetails.getAuthorities());
				authToken.setDetails(
					new WebAuthenticationDetailsSource().buildDetails(request)
				);
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request, response);
	}
}
