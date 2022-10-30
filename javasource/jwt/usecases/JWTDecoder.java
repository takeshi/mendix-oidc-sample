package jwt.usecases;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.DataValidationRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import jwt.helpers.AlgorithmParser;
import jwt.helpers.AudienceListToStringArrayConverter;
import jwt.helpers.DecodedJWTParser;
import jwt.helpers.RSAKeyPairReader;
import jwt.proxies.ENU_Algorithm;
import jwt.proxies.constants.Constants;

public class JWTDecoder {
	
	private ILogNode logger;
	private IContext context;
	private String token;
	
	public JWTDecoder(IContext context, String token) {
		this.logger = Core.getLogger(Constants.getLOGNODE());
		this.context = context;
		this.token = token;
	}
	
	public IMendixObject decodeToObject() {
		validateToken();
		DecodedJWT decodedJWT = decode();
		return getDecodedJWTObject(decodedJWT);
	}
	
	public IMendixObject verifyAndDecodeToObject(String secret, ENU_Algorithm algorithm, jwt.proxies.JWT claimsToVerify, jwt.proxies.JWTRSAPublicKey publicKey, Long leeway) {
		validateToken();
		validateAlgorithm(algorithm);
		DecodedJWT decodedJWT = verify(secret, algorithm, claimsToVerify, publicKey, leeway);
		return getDecodedJWTObject(decodedJWT);
	}
	
	public IMendixObject decodePlainText() {
		validateToken();
		DecodedJWT decodedJWT = decode();
		return getDecodedJWTPlainText(decodedJWT);
	}
	
	public IMendixObject verifyAndDecodePlainText(String secret, ENU_Algorithm algorithm, jwt.proxies.JWT claimsToVerify, jwt.proxies.JWTRSAPublicKey publicKey, Long leeway) {
		validateToken();
		validateAlgorithm(algorithm);
		DecodedJWT decodedJWT = verify(secret, algorithm, claimsToVerify, publicKey, leeway);
		return getDecodedJWTPlainText(decodedJWT);
	}
	
	private void validateToken() {
		if (this.token == null || this.token.equals("")) {
			logger.error("Cannot decode an empty token.");
			throw new DataValidationRuntimeException("Cannot decode an empty token.");
		}
	}
	
	private void validateAlgorithm(ENU_Algorithm algorithm) {
		if (algorithm == null) {
			logger.error("Cannot decode token using an empty algorithm.");
			throw new DataValidationRuntimeException("Cannot decode token using an empty algorithm.");
		}
	}
	
	private DecodedJWT verify(String secret, ENU_Algorithm algorithm, jwt.proxies.JWT claimsToVerify, jwt.proxies.JWTRSAPublicKey publicKey, Long unvalidatedLeeway) {
		Long leeway = validateLeeway(unvalidatedLeeway);
		
		RSAPublicKey rsaPublicKey = null;
		
		if(publicKey != null) {
			RSAKeyPairReader rsaKeyPairReader = new RSAKeyPairReader();
			try {
				rsaPublicKey = rsaKeyPairReader.getPublicKey(this.context, publicKey);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Could not determine algorithm for public key.", e);
			} catch (InvalidKeySpecException e) {
				throw new RuntimeException("Could not determine public key specification.", e);
			} catch (IOException e) {
				throw new RuntimeException("Could not read public key.", e);
			}
		}
		
		try {
			Algorithm alg = new AlgorithmParser().parseAlgorithm(algorithm, secret, rsaPublicKey, null);
			logger.debug("Starting to decode JWT token with algorithm " + alg.getName() + ".");
			
			Verification verification = JWT.require(alg).acceptLeeway(leeway);
			
			if (claimsToVerify != null) {
				if (claimsToVerify.getiss() != null) {
					logger.debug("Verify issuer with value: " + claimsToVerify.getiss() + ".");
					verification.withIssuer(claimsToVerify.getiss());
				}
			
				if (claimsToVerify.getjti() != null) {
					logger.debug("Verify JWT token ID with value: " + claimsToVerify.getjti() + ".");
					verification.withJWTId(claimsToVerify.getjti());
				}
				
				if (claimsToVerify.getsub() != null) {
					logger.debug("Verify subject with value: " + claimsToVerify.getsub() + ".");
					verification.withSubject(claimsToVerify.getsub());
				}
				
				String[] audienceList = new AudienceListToStringArrayConverter().convert(this.context, claimsToVerify);
				
				if (audienceList.length > 0) {
					logger.debug("Verify with list of " + audienceList.length + " audiences.");
					verification.withAudience(audienceList);
				}
			}
			
			JWTVerifier verifier = verification.build();
			DecodedJWT decodedJWT = verifier.verify(token);
			
			logger.debug("Verifying token successfull.");
			
			return decodedJWT;
			
		} catch (UnsupportedEncodingException exception){
		    logger.error("Token encoding unsupported.", exception);
		    throw new RuntimeException(exception);
		} catch (JWTVerificationException exception){
			logger.warn("Verification of token signature/claims failed: " + exception.getMessage());
			throw exception;
		} 
		
	}
	
	private Long validateLeeway(Long leeway) {
		if(leeway == null || leeway < 0) {
			return 0L;
		}
		
		return leeway;
	}
	
	private DecodedJWT decode() {
		return JWT.decode(this.token);
	}
	
	private IMendixObject getDecodedJWTObject(DecodedJWT jwt) {
		IMendixObject jwtObject =  new DecodedJWTParser()
		.parse(this.context, logger, jwt)
		.getMendixObject();
		
		return jwtObject;
	}
	
	private IMendixObject getDecodedJWTPlainText(DecodedJWT jwt) {
		String header = new String(Base64.getDecoder().decode(jwt.getHeader()));
		String payload = new String(Base64.getDecoder().decode(jwt.getPayload()));
		
		IMendixObject jwtPlainText = Core.instantiate(this.context, "JWT.JWTPlainText");
		jwtPlainText.setValue(this.context, "Header", header);
		jwtPlainText.setValue(this.context, "Payload", payload);
		
		return jwtPlainText;
	}

}