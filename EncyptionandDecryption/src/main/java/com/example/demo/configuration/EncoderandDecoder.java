package com.example.demo.configuration;


import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public class EncoderandDecoder {
	
	  private static final String RSA_ALGORITHM = "RSA";

	  public static byte[] encrypt(String pubKey, String plainText) throws Exception {
//		  Resource resource = new ClassPathResource("public_key.pem");

	    byte[] publicKeyBytes = Base64.getDecoder().decode(pubKey);
	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	    PublicKey publicKey = keyFactory.generatePublic(keySpec);
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	    byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
	    return Base64.getEncoder().encode(cipherText);
	  }

	  public static String decrypt(String privKey, byte[] cipherText) throws Exception {
	    byte[] privateKeyBytes = Base64.getDecoder().decode(privKey);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);
	    byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
	    return new String(plainText, StandardCharsets.UTF_8);
	  }
}
