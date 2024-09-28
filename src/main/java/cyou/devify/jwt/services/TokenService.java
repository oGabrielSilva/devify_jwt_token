package cyou.devify.jwt.services;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import cyou.devify.jwt.entities.User;
import jakarta.servlet.http.HttpServletRequest;

@Service
public class TokenService {
    private final String issuer;
    private final String audience;
    private Algorithm algorithm;

    public TokenService(@Value("${props.jwt.secret}") String tokenSecret,
            @Value("${props.jwt.issuer}") String issuer,
            @Value("${props.jwt.audience}") String audience) {
        this.algorithm = Algorithm.HMAC256(tokenSecret);
        this.issuer = issuer;
        this.audience = audience;
    }

    public String create(User user) {
        try {
            return JWT.create().withIssuer(issuer).withAudience(audience).withSubject(user.getEmail())
                    .withExpiresAt(LocalDateTime.now().plusHours(12).toInstant(ZoneOffset.UTC)).sign(algorithm);
        } catch (JWTCreationException ex) {
            return "";
        }
    }

    public String requireSubject(String token) {
        try {
            return decode(token).getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    public DecodedJWT decode(String token) {
        try {
            return JWT.require(algorithm).withIssuer(issuer).build().verify(token);
        } catch (Exception e) {
            return null;
        }
    }

    public String recoveryToken(HttpServletRequest req) {
        String authorization = req.getHeader("Authorization");
        if (authorization == null) {
            return "";
        }
        return authorization.startsWith("Bearer") ? authorization.split(" ")[1] : authorization;
    }

}
