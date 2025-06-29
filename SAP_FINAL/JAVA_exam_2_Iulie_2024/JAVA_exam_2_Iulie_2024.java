package ro.ism.ase.lorena.casuneanu;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JAVA_exam_2_Iulie_2024 {
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte b : values) {
			sb.append(String.format(" %02x", b));
		}
		return sb.toString();
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
	
	public static void aesDecrypt(
			String inputFile, String outputFile, byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		File inputF = new File(inputFile);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("No File");
		}
		File outputF = new File(outputFile);
		if(!outputF.exists()){
			outputF.createNewFile();
		}
		
		FileInputStream fis  = new FileInputStream(inputF);
		FileOutputStream fos = new FileOutputStream(outputF);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		//read IV
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[15] = 23;
		IV[14] = 20;
		IV[13] = 2;	
		IV[12] = 3;
		
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		cipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		while(true) {
			int noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer,0,noBytes);
			fos.write(output);
		}
		byte[] output = cipher.doFinal();
		fos.write(output);
		
		fis.close();
		fos.close();
		
	}
	public static byte[] getSHA256Hash(String file)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

		// byte[] fileBytes = Files.readAllBytes(file.toPath());
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

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, SignatureException {

		//Exer 1
		String myFilesFounded = null;
		
		File repository = new File("system32");
		if (repository.exists() && repository.isDirectory()) {
			// print location content
			File[] items = repository.listFiles();
			for (File item : items) {

				byte[] hashofEXEfile = getSHA256Hash(item.getAbsolutePath());

				// reading from text files
				File msgFile = new File("sha2Fingerprints.txt");
				FileReader fileReader = new FileReader(msgFile);
				BufferedReader bufferReader = new BufferedReader(fileReader);
				String line = null;
				do {
					line = bufferReader.readLine();
					if (line != null && line.equals("system32\\" + item.getName())) {
						line = bufferReader.readLine();

						if (line != null && !Arrays.equals(Base64.getDecoder().decode(line), hashofEXEfile)) {
							System.out.println("The changed file is: " + item.getName());
							myFilesFounded = item.getAbsolutePath();
							break;
						}
					}

				} while (line != null);
				bufferReader.close();
			}
		}
		
		//Exer 2
		File fileFoundedKey = new File(myFilesFounded);
		if(!fileFoundedKey.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fisKey = new FileInputStream(fileFoundedKey);	
		byte[] key = fisKey.readAllBytes();	
		fisKey.close();
		
		aesDecrypt("financialdata.enc", "financialdata.txt", key);
		
		//Exer 3
		File file = new File("financialdata.txt");
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		FileReader fis = new FileReader(file);
		BufferedReader bis = new BufferedReader(fis);
		String iban = bis.readLine();	
		bis.close();
		
		File outputF = new File("myresponse.txt");
		if(!outputF.exists()){
			outputF.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(outputF);
		fos.write(iban.getBytes());
		fos.close();
		
		KeyStore myKeyStore = getKeyStore("ismkeystore.ks", "passks");
		PrivateKey myPrivateKey =  getPrivateKey("ismkey1", "passism1", myKeyStore);
		
		byte[] mySignature = signFile("myresponse.txt", myPrivateKey);
		
		File outputSignature = new File("DataSignature.ds");
		if(!outputSignature.exists()){
			outputSignature.createNewFile();
		}
		FileOutputStream fosSig = new FileOutputStream(outputSignature);
		fosSig.write(mySignature);
		fosSig.close();
		
		System.out.println(getHex(mySignature));
	}
}
