package ro.ase.ism.sap;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class PGP {

    public static byte[] readFromFile(String FileName) throws IOException 
    {
    	File inputFile = new File(FileName);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		byte[] fileContent = fis.readAllBytes();	
		fis.close();
		
		return fileContent;
    }
    
    public static void writeInFile(String FileName, byte[] InputBytes) throws IOException 
    {
		File outputF = new File(FileName);
		if(!outputF.exists()) {
			outputF.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(outputF);
		DataOutputStream dos = new DataOutputStream(fos);
		dos.write(InputBytes);
		dos.close();
    }
	
	public static PublicKey getPublicFromX509(String filename) throws FileNotFoundException, CertificateException {
		File file = new File(filename);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		FileInputStream fis = new FileInputStream(file);
		CertificateFactory factory =  
				CertificateFactory.getInstance("X.509");
		X509Certificate cert = 
				(X509Certificate) factory.generateCertificate(fis);
		return cert.getPublicKey();
	}
	
	public static boolean isValid(String filename, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
	
		Signature sign = Signature.getInstance("SHA512withRSA");
		sign.initVerify(publicKey);
		
		byte[] buffer = readFromFile(filename);
		
		sign.update(buffer);
		return sign.verify(signature);
	}
	
	public static byte[] getSymmetricRandomKey(int noBits, String algorithm) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(noBits);
		return keyGenerator.generateKey().getEncoded();
	}
	
	public static void encryptWithSymKey(String inputFile, String encrypteFile, byte[] key, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		File inputF = new File(inputFile);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("File missing");
		}
		File outputF = new File(encrypteFile);
		if(!outputF.exists()) {
			outputF.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputF);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		FileOutputStream fos = new FileOutputStream(outputF);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		Cipher cipher = Cipher.getInstance(algorithm+"/ECB/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		
		while(true) {
			int noBytes = bis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer,0,noBytes);
			bos.write(output);
		}
		byte[] output = cipher.doFinal();
		bos.write(output);
		
		bis.close();
		bos.close();	
	}
	
	public static byte[] encryptWithRSAKey(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
	
	public static void printKSContent(KeyStore ks) throws KeyStoreException {
		if(ks != null) {
			System.out.println("Key Store content: ");
			
			Enumeration<String> items = ks.aliases();
			
			while(items.hasMoreElements()) {
				String item = items.nextElement();
				System.out.println("Item: " + item);
				if(ks.isKeyEntry(item)) {
					System.out.println("\t - is a key pair");
				}
				if(ks.isCertificateEntry(item)) {
					System.out.println("\t - is a public key");
				}		
			}
		}
	}
	
	public static PublicKey getPublicKey(KeyStore ks, String alias) throws KeyStoreException {
		if(ks != null && ks.containsAlias(alias)) {
			PublicKey pub = ks.getCertificate(alias).getPublicKey();
			return pub;
		} else {
			throw new UnsupportedOperationException("No KS or no alias");
		}
	}
	
	public static PrivateKey getPrivateKey(KeyStore ks, String alias, String ksPass) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		if(ks != null && ks.containsAlias(alias) && 
				ks.isKeyEntry(alias)) {
			PrivateKey priv = 
					(PrivateKey) ks.getKey(alias, ksPass.toCharArray());
			return priv;
		}
		else {
			throw new UnsupportedOperationException("KS issue");
		}
	}
	
	public static KeyStore getKeyStore(String ksFileName, String ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		File ksFile = new File(ksFileName);
		if(!ksFile.exists()) {
			throw new UnsupportedOperationException("KeyStore file missing");
		}
		FileInputStream fis = new FileInputStream(ksFile);
		
		KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(fis, ksPassword.toCharArray());
		fis.close();
		return ks;
	}
	
	public static byte[] getDigitalSignature(String file, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {

		Signature signature = Signature.getInstance("SHA512withRSA");
		signature.initSign(privateKey);
		
		//process the entire file on one round
		byte[] buffer = readFromFile(file);
		signature.update(buffer);
		
		return signature.sign();	
	}
	
	public static void main(String[] args) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, UnrecoverableKeyException {
	
		PublicKey publicProfessorKey = getPublicFromX509("SimplePGP_ISM.cer");
		
		if(isValid("SAPExamSubject1.txt", readFromFile("SAPExamSubject1.signature"), publicProfessorKey))
		{
			System.out.println("Message SAPExamSubject1.txt is valid.");
		}
		if(isValid("SAPExamSubject2.txt", readFromFile("SAPExamSubject2.signature"), publicProfessorKey))
		{
			System.out.println("Message SAPExamSubject2.txt is valid.");
		}
		
		if(isValid("SAPExamSubject3.txt", readFromFile("SAPExamSubject3.signature"), publicProfessorKey))
		{
			System.out.println("Message SAPExamSubject3.txt is valid.");
		}
		
		byte[] randomAESKey = getSymmetricRandomKey(128, "AES");
		encryptWithSymKey ("MyMessageResponse.txt", "response.sec", randomAESKey, "AES");
		
		KeyStore myKeyStore = getKeyStore("ismkeystore.ks", "passks");
		printKSContent(myKeyStore);
		PublicKey myPublicKey = getPublicKey(myKeyStore, "ismkey1");
		PrivateKey myPrivateKey = getPrivateKey(myKeyStore, "ismkey1", "passism1");
		
		byte[] AESEncryptedKey = encryptWithRSAKey(publicProfessorKey, randomAESKey);		
		writeInFile("aes_key.sec", AESEncryptedKey);
		
		byte [] signature = getDigitalSignature ("response.sec", myPrivateKey);
 		writeInFile("signature.ds", signature);
 		
 		
		if(isValid("response.sec", readFromFile("signature.ds"), myPublicKey))
		{
			System.out.println("My signature is valid.");
		}
	}
	
}
