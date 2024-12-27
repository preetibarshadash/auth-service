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
		SECRET_KEY = "4998541c748202359ba94e6a59d35bacf7c99456b2678f2f2c52db755d4b4988c8b52bc6b95f49743c1bf7ed0b739ef8539cdb85b402b2662291192b3dd8668d8ada29a901d7fd6ab7b4b9dd6c84e2d6a8dfa90dfd2de8d49f58627cbbc317886859c30e5cc790049109459f6769d09690d549056d512ac2bcfd667f721ab7d9b333daffe1ae80325d2612a1b85d214ccebaaffa07ceeea644cf68dfae4ac7cf8b16a3d2bc60faaa722b8d4cac1806cdaa293b68aea1ef3814172c877d8a21a8062ffab63de55a623128556f7f60559be6184cf41c87b318f55ad773576148fc703c441dcb095f4b42bbe55c1c072fc5219eba5c41690370e5856f060e31ecd2";
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
