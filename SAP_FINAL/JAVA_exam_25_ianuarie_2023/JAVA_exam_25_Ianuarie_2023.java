package ro.ism.ase.lorena.casuneanu;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JAVA_exam_25_Ianuarie_2023 {
	public static PublicKey getPublicKey(String alias, KeyStore ks) throws KeyStoreException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return ks.getCertificate(alias).getPublicKey();
		} else {
			return null;
		}
	}
	public static boolean hasValidSignature(
			String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		
		FileInputStream fis = new FileInputStream(file);	
		byte[] fileContent = fis.readAllBytes();	
		fis.close();
		
		Signature signatureModule = Signature.getInstance("SHA256withRSA");
		signatureModule.initVerify(key);
		
		signatureModule.update(fileContent);
		return signatureModule.verify(signature);
		
	}
	public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fis = new FileInputStream(file);
		
		byte[] fileContent = fis.readAllBytes();
		
		fis.close();
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		
		signature.update(fileContent);
		return signature.sign();		
	}
	public static KeyStore getKeyStore(
			String keyStoreFile,
			String keyStorePass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		File file = new File(keyStoreFile);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing key store file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(fis, keyStorePass.toCharArray());
		
		fis.close();
		return ks;
	}

	public static PrivateKey getPrivateKey(
			String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
		} else {
			return null;
		}
	}
	
	public static byte[] getSHA256Hash(String file)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//byte[] fileBytes = Files.readAllBytes(file.toPath());
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] buffer = new byte[8];
		while (true) {
			int noBytes = bis.read(buffer);
			if (noBytes == -1) {
				break;
			}
			md.update(buffer, 0, noBytes);
		}
		
		// Get final hash
		byte[] hashValue = md.digest();
		bis.close();
		return hashValue;
	}
	
	public static byte[] AES_CBC_Decrypt(String inputFile, byte[] iv, byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		File inputF = new File(inputFile);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("No File");
		}

		FileInputStream fis  = new FileInputStream(inputF);
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		
	
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
		
		ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
		byte[] buffer = new byte[cipher.getBlockSize()];
		while(true) {
			int noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer,0,noBytes);
			decryptedOutput.write(output);
		}
		byte[] output = cipher.doFinal();
		decryptedOutput.write(output);
		
		fis.close();

		return decryptedOutput.toByteArray();
	}
	
	public static byte[] getPBKDF(
			String userPass, 
			String algorithm, 
			String salt, 
			int noIterations,
			int outputSize) throws NoSuchAlgorithmException, InvalidKeySpecException {

		PBEKeySpec pbeKeySpec = new PBEKeySpec(userPass.toCharArray(),salt.getBytes(), noIterations, outputSize);
		SecretKeyFactory pbkdf = SecretKeyFactory.getInstance(algorithm);

		SecretKey key = pbkdf.generateSecret(pbeKeySpec);
		return key.getEncoded();
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableKeyException, SignatureException {
	
	//Exer 1
		
		String myHash = "40a2axxv4JIFnUiGE5hl4QifwagV/gQl6GC4voDfzI4=";	
		byte[] myinitialHashValue = Base64.getDecoder().decode(myHash);
		
		byte[] IV = { (byte)0x00, (byte)0x00, (byte)0x00, (byte) 0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
				   (byte)0x00, (byte)0x00, (byte) 0xFF, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
		String pwd = "userfilepass%5]2";
		String myFilesFounded = null;
		
		File repository = new File("users");
		if(repository.exists() && repository.isDirectory()) {
			//print location content
			File[] items = repository.listFiles();
			for(File item : items) {
	
				byte[] hashoffile = getSHA256Hash(item.getAbsolutePath());
				
				if(Arrays.equals(myinitialHashValue, hashoffile)) {
					System.out.println("The user is: " + item.getName());
					myFilesFounded = item.getAbsolutePath();
					break;
				}
			}
		}
		
		//Exer 2
		byte[] userPWD = AES_CBC_Decrypt(myFilesFounded, IV, pwd.getBytes());
		System.out.println("The user password is: ");
		System.out.println(new String(userPWD));

		//Exer 3
		String salt = "ism2021";
		//String saltedUserPWD = new String(userPWD) + salt;
		//System.out.println(saltedUserPWD);
		byte [] pbkdf = getPBKDF(new String(userPWD), "PBKDF2WithHmacSHA1", salt, 150, 160);
		
		File binaryFile = new File("PBKDF2WithHmacSHA1.bin");
		if(!binaryFile.exists()) {
			binaryFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(binaryFile);
		DataOutputStream dos = new DataOutputStream(fos);
		dos.write(pbkdf); 
		dos.close();
		
		//Exer 3
		KeyStore myKeyStore = getKeyStore("ismkeystore.ks","passks");
		PrivateKey myPrivateKey = getPrivateKey("ismkey1","passism1",myKeyStore);
		
		byte[] mySignature = signFile("PBKDF2WithHmacSHA1.bin", myPrivateKey);
		
		File SignatureFile = new File("Signature.sig");
		if(!SignatureFile.exists()) {
			SignatureFile.createNewFile();
		}
		FileOutputStream fosSig = new FileOutputStream(SignatureFile);
		DataOutputStream dosSig = new DataOutputStream(fosSig);
		dosSig.write(mySignature);
		dosSig.close();
		
		//Verify
		PublicKey myPublicKey = getPublicKey ("ismkey1", myKeyStore);
		if(hasValidSignature("PBKDF2WithHmacSHA1.bin", myPublicKey, mySignature )){
			System.out.println("The msg is valid");
		} else {
			System.out.println("Someone changed the msg");
		}
	}
}
