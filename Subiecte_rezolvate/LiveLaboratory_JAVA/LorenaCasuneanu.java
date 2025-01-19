package ro.ase.ism.sap.lorena.casuneanu;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class LorenaCasuneanu {
	//rename the class with your name
	//use a package with the next pattern 
    //		ro.ase.ism.sap.lastname.firstname
	// 1. Step 1: return your file name
	
	static String getHexFromByteArray(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte value : values) {
			sb.append(String.format("%02x", value));
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
    
	   public static String findFile(String hash) throws NoSuchAlgorithmException, IOException {
	        File repository = new File("T:\\workaspace_eclipse_live_lab\\LiveLab\\safecorp_random_messages");
	        String myFile = null;
	        
	        if (repository.exists() && repository.isDirectory()) {
	            File[] items = repository.listFiles();
	            if (items != null) {
	                for (File item : items) {
	                    try (FileInputStream fis = new FileInputStream(item);
	                         BufferedInputStream bis = new BufferedInputStream(fis)) {
	                         
	                        MessageDigest md = MessageDigest.getInstance("SHA-256");
	
	                        byte[] buffer = new byte[8];
	                		while(true) {
	                			int noBytes = bis.read(buffer);
	                			if(noBytes == -1) {
	                				break;
	                			}
	                			md.update(buffer, 0, noBytes);
	                		}

	                        // Get final hash
	                        byte[] hashValue = md.digest();
	                        byte[] hashBytes = hexStringToByteArray(hash);

	                        if (Arrays.equals(hashValue, hashBytes)) {
	                            myFile = item.getName();
	                            System.out.println("Found file: " + item.getName());
	                            break;
	                        }
	                    }
	                }
	            }
	        }
	        return myFile;
	    }
	
    // 2. Step 2: Generate HMAC for Authentication
    public static void generateHMAC(String filename, String sharedSecret) throws IOException, NoSuchAlgorithmException, InvalidKeyException{
    	Mac hmac = Mac.getInstance("HmacSHA256");
		SecretKeySpec key = new SecretKeySpec(
				sharedSecret.getBytes(), "HmacSHA256");
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
		
		File outputtFile = new File("hmac.txt");
		if(!outputtFile.exists()) {
			outputtFile.createNewFile();
		}
		
		FileWriter fileWriter = new FileWriter(outputtFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(getHexFromByteArray(result));
	
		printWriter.close();

    }
    
    // 3. Step 3: Derive Key with PBKDF2
    public static byte[] deriveKeyWithPBKDF2(
    		String password, int noIterations, int keySize) {
        try {
           
        	String salt = "lorenacasuneanu";

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), noIterations, keySize);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();

    		File outputtFile = new File("salt.txt");
    		if(!outputtFile.exists()) {
    			outputtFile.createNewFile();
    		}
    		
    		FileWriter fileWriter = new FileWriter(outputtFile, true);
    		PrintWriter printWriter = new PrintWriter(fileWriter);
    		printWriter.println(salt);
    		
    		printWriter.close();
    		System.out.println(getHexFromByteArray(key));
            return key;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
   

    
    // 4. Step 4: Encrypt File with AES and Save IV
    public static void encryptFileWithAES(String filename, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		File inputF = new File(filename);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		File outputF = new File("encrypted.txt");
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
		IV[9] = (byte) 0x01;
		System.out.println("IV = " + getHexFromByteArray(IV));
		
		//write IV into file
		File outputtFile = new File("IV.txt");
		if(!outputtFile.exists()) {
			outputtFile.createNewFile();
		}
		
		FileWriter fileWriter = new FileWriter(outputtFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(Base64.getEncoder().encode(IV));
		printWriter.close();
		
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		
		while(true) {
			int noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer, 0, noBytes);
			fos.write(Base64.getEncoder().encode(output));
		}
		
		byte[] output = cipher.doFinal();
		fos.write(Base64.getEncoder().encode(output));
		
		fis.close();
		fos.close();
    }
    
    // 5. Step 5: Encrypt with 3DES for Archival 
    public static void encryptWith3DES(String filename, byte[] key) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
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
		
		Cipher cipher = 
				Cipher.getInstance("DES/ECB/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		
		while(true) {
			int noBytes = bis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer,0,noBytes);
			fos.write(Base64.getEncoder().encode(output));
		}
		byte[] output = cipher.doFinal();
		fos.write(Base64.getEncoder().encode(output));
		
		bis.close();
		bos.close();	
    }

    
    // 6. Step 6: Apply Cyclic Bitwise Shift
    public static void applyCyclicShift(String filename) {
    	
    }
	
	public static void main(String[] args) {

	    	String hash = "123C436DDB8D6E10474D2FBBBD2DF9CE13D0DF788B92E366D25391FB8F4DC179"; //copy it from the given Excel file
	    	String sharedSecret = "_)O%9Hn!,(YO"; //copy it from the given Excel file
	    	int noIterations = 66487; //copy it from the given Excel file
	    	
	        try {
	            // 1. Step 1
	        	String filename = findFile(hash);
	        	
	            // 2. Step 2: Generate HMAC for Authentication
	            generateHMAC(filename, sharedSecret);
	            
	            int keySize = 128;
	            byte[] key;
	            // 3. Step 3: Derive Key with PBKDF2
	            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);

	            // 4. Step 4: Encrypt File with AES and Save IV
	            encryptFileWithAES(filename, key);
	          
	            // 5. Step 5: Encrypt with 3DES for Archival
	            keySize = 64;
	            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);
	            encryptWith3DES(filename, key);

	            // 6. Step 6: Apply Cyclic Bitwise Shift
	            applyCyclicShift("encrypted.txt");

	        } catch (Exception e) {
	            System.out.println("An error occurred: " + e.getMessage());
	            e.printStackTrace();
	        }
	}

}

