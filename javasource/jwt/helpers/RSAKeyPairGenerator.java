package jwt.helpers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.systemwideinterfaces.core.IContext;

import jwt.proxies.JWTRSAKeyPair;
import jwt.proxies.JWTRSAPrivateKey;
import jwt.proxies.JWTRSAPublicKey;

public class RSAKeyPairGenerator {
	
	public JWTRSAKeyPair generate(IContext context, int keySize, String issuer, String subject, int validity) throws NoSuchAlgorithmException, CoreException, IOException, OperatorCreationException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.genKeyPair(); 
		
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		JWTRSAKeyPair keyPairObject = new JWTRSAKeyPair(context);
		
		JWTRSAPrivateKey privateKeyObject = generatePrivate(context, "private" + keyPairObject.getKeyPairId(context) + ".der", privateKey);
		privateKeyObject.setJWTRSAPrivateKey_JWTRSAKeyPair(context, keyPairObject);
		
		JWTRSAPublicKey publicKeyObject = generatePublic(context, "public" + keyPairObject.getKeyPairId(context) + ".der", publicKey, privateKey, issuer, subject, validity);
		publicKeyObject.setJWTRSAPublicKey_JWTRSAKeyPair(context, keyPairObject);
		
		Core.commit(context, keyPairObject.getMendixObject());
		
		return keyPairObject;	
	}
	
	public JWTRSAPrivateKey generatePrivate(IContext context, String fileName, RSAPrivateKey privateKey) throws CoreException, IOException, OperatorCreationException {
		JWTRSAPrivateKey privateKeyObject = new JWTRSAPrivateKey(context);
		Core.commit(context, privateKeyObject.getMendixObject());
		
		byte[] privateKeyPKCS1 = null;
		
		PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
		privateKeyPKCS1 = privateKeyInfo.toASN1Primitive().getEncoded();
		
		Core.storeFileDocumentContent(context, privateKeyObject.getMendixObject(), fileName, new ByteArrayInputStream(privateKeyPKCS1));
		
		return privateKeyObject;
	}
	
	public JWTRSAPublicKey generatePublic(IContext context, String fileName, RSAPublicKey publicKey, RSAPrivateKey privateKey, String issuer, String subject, int validity) throws CoreException, IOException, OperatorCreationException {
		JWTRSAPublicKey publicKeyObject = new JWTRSAPublicKey(context);
		Core.commit(context, publicKeyObject.getMendixObject());
		
		byte[] pubBytes = publicKey.getEncoded();

		SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(pubBytes);
		
		X500NameBuilder x500NameBuilderIssuer = new X500NameBuilder();
		x500NameBuilderIssuer.addRDN(BCStyle.CN, issuer);
		
		X500Name x500NameIssuer = x500NameBuilderIssuer.build();
		
		X500NameBuilder x500NameBuilderSubject = new X500NameBuilder();
		x500NameBuilderSubject.addRDN(BCStyle.CN, subject);
		
		X500Name x500NameSubject = x500NameBuilderSubject.build();
		
		Date currentDate = new Date(System.currentTimeMillis());
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(currentDate);
		calendar.add(Calendar.YEAR, 3);
		Date futureDate = calendar.getTime();
		
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(x500NameIssuer, new BigInteger("1234"), currentDate, futureDate, x500NameSubject, spkInfo);
		JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = builder.build(privateKey);
		byte[] certBytes = certBuilder.build(signer).getEncoded();
		
		Core.storeFileDocumentContent(context, publicKeyObject.getMendixObject(), fileName, new ByteArrayInputStream(certBytes));
		
		return publicKeyObject;
	}
	
}