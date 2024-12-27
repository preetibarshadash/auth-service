package com.auth.auth_service.config;

import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.auth.auth_service.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtConfig {

	private String SECRET_KEY = null;

	public String generateToken(User user) {
		System.out.println(user.getUsername());
		HashMap<String, Object> claims = new HashMap<>();
		return Jwts.builder().setClaims(claims).setSubject(user.getUsername()).setIssuer("Preetibarsha")
				.setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				.signWith(generateKey()).compact();
	}

	private SecretKey generateKey() {
		byte[] decode = Decoders.BASE64.decode(getSecretKey());
		return Keys.hmacShaKeyFor(decode);
	}

	private String getSecretKey() {
	
		return SECRET_KEY;
	}

	public String extractUsername(String token) {
		String username = extractClaim(token, Claims::getSubject);
		System.out.println("Extracted Username: " + username); // Debug log
		return username;
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		try {
			Claims claims = Jwts.parserBuilder().setSigningKey(generateKey()).build().parseClaimsJws(token).getBody();
			System.out.println("Extracted Claims: " + claims); // Debug log
			return claims;
		} catch (Exception e) {
			System.err.println("Failed to parse token: " + e.getMessage());
			throw e; // Re-throw for visibility
		}
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
}
