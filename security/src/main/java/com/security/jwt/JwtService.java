package com.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Component
public class JwtService {
    // need to read this two field from properties file and .envfile

    private  final String SECRET_KEY = " 404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970hfhweoihfiohiofhiowehfiohwiofhioehfo";

    @Value("${jwtapp.app.jwtExpirationMs}")
    private  final int jwtExpirationInMs = 86400000;

    private final  long refreshExpiration = 604800000;


    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);



    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
       byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }


    public String extractUserName(String token){
        return  extractClaim(token, Claims::getSubject);
    }


    public<T> T extractClaim(String token, Function<Claims, T> claimsResolver){
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
    }



    public  String generateToken(Map<String, Object> extraClaim, UserDetails userDetails){
        return  Jwts.builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();

    }


    public  String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }


    public boolean isTokenValid(String token , UserDetails userDetails){
        final  String username = extractUserName(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {

        return extractExpiration(token).before(new Date());

    }

    private Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);

    }


}
