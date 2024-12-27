package com.auth.auth_service.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtConfig jwtService;

	private final UserDetailsService userDetailsService;

	public JwtAuthenticationFilter(JwtConfig jwtService, UserDetailsService userDetailsService) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String header = request.getHeader("Authorization");
		if (header == null || !header.startsWith("Bearer")) {
			filterChain.doFilter(request, response);
			System.err.println("returning");
			return;
		}

		final String jwt = header.substring(7);
		System.out.println("token "+jwt);
		final String username = jwtService.extractUsername(jwt);
		System.out.println("username "+username);

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		System.out.println(auth);
		if (username != null && auth == null) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			if (jwtService.isTokenValid(jwt, userDetails)) {
				System.out.println("token valid "+jwtService.isTokenValid(jwt, userDetails));
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
						null, userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
				System.out.println(SecurityContextHolder.getContext());
			}
		}
		filterChain.doFilter(request, response);
	}

}
