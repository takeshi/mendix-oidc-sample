package jwt.helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;

import jwt.proxies.JWTRSAPrivateKey;
import jwt.proxies.JWTRSAPublicKey;

public class RSAKeyPairReader {
	
	public RSAPublicKey getPublicKey(IContext context, JWTRSAPublicKey publicKeyObject) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		try (	InputStream inputStream = Core.getFileDocumentContent(context, publicKeyObject.getMendixObject());
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();) {
		    
			PublicKey publicKey = null;
			byte[] encodedPublicKey = inputStreamToByteArray(inputStream, buffer);
			
			try {
				CertificateFactory fact = CertificateFactory.getInstance("X.509");
				X509Certificate cer = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(encodedPublicKey));
				publicKey = cer.getPublicKey();
			} catch (CertificateException e) {
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
				publicKey = keyFactory.generatePublic(publicKeySpec);
			}
			
			return (RSAPublicKey) publicKey;
		}
	}
	
	public RSAPrivateKey getPrivateKey(IContext context, JWTRSAPrivateKey privateKeyObject) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		try (	InputStream inputStream = Core.getFileDocumentContent(context, privateKeyObject.getMendixObject());
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();) {
			
		    byte[] encodedPrivateKey = inputStreamToByteArray(inputStream, buffer);
			
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encodedPrivateKey);
			
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
			PrivateKey privateKey = jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
			
			return (RSAPrivateKey) privateKey;
		}
	}
	
	public byte[] inputStreamToByteArray(InputStream inputStream, ByteArrayOutputStream buffer) throws IOException {
		int nRead;
	    byte[] data = new byte[4096];
	    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
	        buffer.write(data, 0, nRead);
	    }
		 
	    buffer.flush();
	    return buffer.toByteArray();
	}
}
