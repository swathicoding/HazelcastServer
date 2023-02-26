package com.example.demo.configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyGenerator {
	
	static String publicKeyStr = "";
    static String privateKeyStr = "";
    
    public static void main(String[] args) throws Exception {
    	encrypt();
    }
	public static void encrypt() throws Exception {
		try {
			// Generate an RSA key pair with a key size of 2048 bits
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(2048);
	        KeyPair keyPair = keyGen.generateKeyPair();

	        // Get the public and private keys
	        byte[] publicKey = keyPair.getPublic().getEncoded();
	        byte[] privateKey = keyPair.getPrivate().getEncoded();

	        // Print the keys as base64-encoded strings
	        publicKeyStr = java.util.Base64.getEncoder().encodeToString(publicKey);
	        privateKeyStr = java.util.Base64.getEncoder().encodeToString(privateKey);
	        System.out.println("Public key: " + publicKeyStr);
	        System.out.println("Private key: " + privateKeyStr);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
//		String publicKey = "your-public-key"; // load the public key from a file or a database
//		String privateKey = "your-private-key"; // load the private key from a secure location

		String plainTextPassword = "your-database-password";
		byte[] encryptedPassword = EncoderandDecoder.encrypt(publicKeyStr, plainTextPassword);
		// store the encrypted password in a secure location, such as a configuration file or a database
		
		
		// when you need to access the database, retrieve the encrypted password and decrypt it
		String decryptedPassword = EncoderandDecoder.decrypt(privateKeyStr, encryptedPassword);
		System.out.println("Decrypted TEXT -----" + decryptedPassword);
		// use the decrypted password to connect to the database

	}
}

// Using Existing Key Files

////Load the public key from the resource file
//Resource resource = new ClassPathResource("public_key.pem");
//byte[] publicKeyBytes = FileCopyUtils.copyToByteArray(resource.getInputStream());
//X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
//KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
//
////Encrypt the database password using the public key
//Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//byte[] encryptedPasswordBytes = cipher.doFinal(databasePassword.getBytes());
//String encryptedPassword = Base64.getEncoder().encodeToString(encryptedPasswordBytes);
//
//
//
//
//
////Load the private key from a file
//Resource resource = new ClassPathResource("private_key.pem");
//byte[] privateKeyBytes = FileCopyUtils.copyToByteArray(resource.getInputStream());
//PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
//KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
//
////Decrypt the encrypted password using the private key
//Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//cipher.init(Cipher.DECRYPT_MODE, privateKey);
//byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
//String decryptedPassword = new String(decryptedPasswordBytes);



