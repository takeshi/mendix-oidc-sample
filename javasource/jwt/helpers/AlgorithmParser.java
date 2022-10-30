package jwt.helpers;

import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwt.algorithms.Algorithm;

import jwt.proxies.ENU_Algorithm;

public class AlgorithmParser {

	public Algorithm parseAlgorithm(ENU_Algorithm algorithm, String secret, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException, UnsupportedEncodingException {
		
		switch(algorithm) {
			case HS256:
				return Algorithm.HMAC256(secret);
			case HS384:
				return Algorithm.HMAC384(secret);
			case HS512:
				return Algorithm.HMAC512(secret);
			case RS256:
				return Algorithm.RSA256(publicKey, privateKey);
			case RS384:
				return Algorithm.RSA384(publicKey, privateKey);
			case RS512:
				return Algorithm.RSA512(publicKey, privateKey);
			default:
				return Algorithm.HMAC256(secret);
		}
	}
	
}
