package ro.ism.ase.lorena.casuneanu;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
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
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class JAVA_LIVE_Laboratory {
	
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte b : values) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
	
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
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
	
	// 1. Step 1: return your file name
	public static String findFile(String hash) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		String myFilesFounded = null;
		File repository = new File("safecorp_random_messages");
		if(repository.exists() && repository.isDirectory()) {
			
			File[] items = repository.listFiles();
			for(File item : items) {
	
				byte[] hashoffile = getSHA256Hash(item.getAbsolutePath());
				
				if(Arrays.equals(hexStringToByteArray(hash), hashoffile)) {
					//System.out.println("The file is: " + item.getName())
					myFilesFounded = item.getName();
					break;
				}
			}
		}
		
		return myFilesFounded;
	};
	
    // 2. Step 2: Generate HMAC for Authentication
    public static void generateHMAC(String filename, String sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException, IOException{
		Mac hmac = Mac.getInstance("HmacSHA256");
		SecretKeySpec key = new SecretKeySpec(sharedSecret.getBytes(), "HmacSHA256");
		hmac.init(key);
		
		//read the file and process it
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("File is missing");
		}
		FileInputStream fis = new FileInputStream(inputFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		byte[] buffer = new byte[8];
		while(true) {
			int noBytes = bis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			hmac.update(buffer, 0, noBytes);
		}
		
		fis.close();
		
		byte[] result = hmac.doFinal();
		
		File outputF = new File("hmac.txt");
		if(!outputF.exists()){
			outputF.createNewFile();
		}
		FileWriter fileWriter = new FileWriter(outputF, false);   //pun false daca vreau sa suprascriu mereu
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(getHex(result));
		printWriter.close();
    }
    
    // 3. Step 3: Derive Key with PBKDF2
    public static byte[] deriveKeyWithPBKDF2(String password, int noIterations, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	
    	String salt = "lorena";
    	
		File outputF = new File("salt.txt");
		if(!outputF.exists()){
			outputF.createNewFile();
		}
    	
		FileWriter fileWriter = new FileWriter(outputF, false);   //pun false daca vreau sa suprascriu mereu
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(salt);
		printWriter.close();
		    	
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(),  noIterations, keySize);
		SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		
		SecretKey key = pbkdf.generateSecret(pbeKeySpec);
		
		return key.getEncoded();
    }
    
    // 4. Step 4: Encrypt File with AES and Save IV
    public static void encryptFileWithAES(String filename, byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		File inputF = new File(filename);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		File outputF = new File("encrypted_raw.txt");
		if(!outputF.exists()) {
			outputF.createNewFile();
		}
		FileInputStream fis = new FileInputStream(inputF);
		FileOutputStream fos = new FileOutputStream(outputF);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		
		//IV value
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[8] = (byte) 0x80;
		
		//write IV into file
		File outputIV = new File("IV.txt");
		if(!outputIV.exists()) {
			outputIV.createNewFile();
		}
		FileWriter fileWriter = new FileWriter(outputIV, false);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(Base64.getEncoder().encodeToString(IV));
		printWriter.close();

		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec,ivSpec);
		
		while(true) {
			int noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer, 0, noBytes);
			fos.write(output);
		}
		
		byte[] output = cipher.doFinal();
		fos.write(output);
		
		fis.close();
		fos.close();
		
		
		//base64
		
		File resultedFile = new File("encrypted_raw.txt");
		FileInputStream fisResulted = new FileInputStream(resultedFile);
		byte[] reasultedBytes = fisResulted.readAllBytes();
		fisResulted.close();
		
		FileWriter outputFinalBase64 = new FileWriter("encrypted.txt", false);
		PrintWriter printWriterFinalBase64 = new PrintWriter(outputFinalBase64);
		printWriterFinalBase64.println(Base64.getEncoder().encodeToString(reasultedBytes));
		printWriterFinalBase64.close();
		
    }
    
    // 5. Step 5: Encrypt with 3DES for Archival 
    public static void encryptWith3DES(String filename, byte[] key) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		File inputF = new File(filename);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("File missing");
		}
		File outputF = new File("archived.sec");
		if(!outputF.exists()) {
			outputF.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputF);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		FileOutputStream fos = new FileOutputStream(outputF);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
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

    // 6. Step 6: Apply Cyclic Bitwise Shift
    public static void applyCyclicShift(String filename) throws IOException {
		File file = new File("encrypted.txt");

		FileReader fileReader = new FileReader(file);
		BufferedReader bufferReader = new BufferedReader(fileReader);
		String line = bufferReader.readLine();;
		bufferReader.close();
		
		//decoding
		byte[] initialValues = Base64.getDecoder().decode(line);
		byte[] obfuscateBytes = new byte[initialValues.length];
		
		for(int i=0; i<initialValues.length; i++)
		{
			obfuscateBytes[i] = (byte) ((initialValues[i] << 2) | ((initialValues[i] & 0xFF)  >>> 6));	
		}
		
		File binaryFile = new File("obfuscated.txt");
		if(!binaryFile.exists()) {
			binaryFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(binaryFile);
		DataOutputStream dos = new DataOutputStream(fos);
		
		dos.write(obfuscateBytes);
		
		dos.close();
    }
	
	public static void main(String[] args) {

	    	String hash = "123C436DDB8D6E10474D2FBBBD2DF9CE13D0DF788B92E366D25391FB8F4DC179"; //copy it from the given Excel file
	    	String sharedSecret = "_)O%9Hn!,(YO"; //copy it from the given Excel file
	    	int noIterations = 66487; //copy it from the given Excel file
	    	
	        try {
	            // 1. Step 1
	        	String filename = findFile(hash);
	        	System.out.println("The file is: " + filename);
	        	
	            // 2. Step 2: Generate HMAC for Authentication
	        	String path = "safecorp_random_messages\\" + filename;
	            generateHMAC(path, sharedSecret);
	            
	            int keySize = 128;
	            byte[] key;
	            // 3. Step 3: Derive Key with PBKDF2
	            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);

	            // 4. Step 4: Encrypt File with AES and Save IV
	            encryptFileWithAES(path, key);
	          
	            // 5. Step 5: Encrypt with 3DES for Archival
	            keySize = 192;
	            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);
	            encryptWith3DES(path, key);

	            // 6. Step 6: Apply Cyclic Bitwise Shift
	            applyCyclicShift("encrypted.txt");

	        } catch (Exception e) {
	            System.out.println("An error occurred: " + e.getMessage());
	            e.printStackTrace();
	        }
	}
}
