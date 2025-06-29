package ro.ism.ase.lorena.casuneanu;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JAVA_exam_31_Ianuarie_2025 {
	// Use this static variables to hardcode algorithm names and other important values
    private static final String HASH_ALGORITHM = "MD5";
    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final String SHARED_SECRET = "ZsEE\";t1hFh91234"; // Secret key for HMAC authentication from the Excel file
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String FOLDER_PATH = "messages";
    
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte b : values) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
    
	public static byte[] getHash(String file) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

		// byte[] fileBytes = Files.readAllBytes(file.toPath());
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);

		MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
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

    // Step 1: Generate Digest values of all the files from the given folder
    public static void generateFilesDigest(String folderPath) throws Exception {
		File repository = new File(folderPath);
		if(repository.exists() && repository.isDirectory()) {
			//print location content
			File[] items = repository.listFiles();
			for(File item : items) {
	
				byte[] hashoffile = getHash(item.getAbsolutePath());
				
				String name = item.getName();
				int pos = name.lastIndexOf(".");
				if (pos > 0) {
				    name = name.substring(0, pos);
				}
				
				File outputF = new File("hashes\\" + name + ".digest");
				if(!outputF.exists()) {
					outputF.createNewFile();
				}

				FileWriter fileWriter = new FileWriter(outputF, false);
				PrintWriter printWriter = new PrintWriter(fileWriter);
				printWriter.write(getHex(hashoffile));
				printWriter.close();
			}
		}
    }
	public static byte[] getHMAC(String fileName, String password) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), HMAC_ALGORITHM);
		hmac.init(key);
		
		//read the file and process it
		File inputFile = new File(fileName);
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
		
		return result;
	}
    // Step 2: Generate HMAC-SHA256 authentication code
    public static void generateFilesHMAC(String folderPath, String secretKey) throws Exception {
		File repository = new File(folderPath);
		if(repository.exists() && repository.isDirectory()) {
			//print location content
			File[] items = repository.listFiles();
			for(File item : items) {
	
				byte[] hmacFile = getHMAC(item.getAbsolutePath(), secretKey);
				
				String name = item.getName();
				int pos = name.lastIndexOf(".");
				if (pos > 0) {
				    name = name.substring(0, pos);
				}
				
				File outputF = new File("hmacs\\" + name + ".hmac");
				if(!outputF.exists()) {
					outputF.createNewFile();
				}

				FileWriter fileWriter = new FileWriter(outputF, false);
				PrintWriter printWriter = new PrintWriter(fileWriter);
				printWriter.write(Base64.getEncoder().encodeToString(hmacFile));
				printWriter.close();
			}
		}
    }
    

    // Step 3: Decrypt and verify the document
    public static boolean retrieveAndVerifyDocument(String file, String hashFile, String hmacFile, String secretKey) throws Exception {
        // Verify HMAC and digest for the given file
    	// Return true if the files has not been changed

    	String hashFor10 = getHex(getHash(file));
    	String hmacFor10 = Base64.getEncoder().encodeToString(getHMAC(file, secretKey));
    	
		FileReader HASHfileReader = new FileReader(hashFile);
		BufferedReader HASHbufferReader = new BufferedReader(HASHfileReader);
		String hashFromFile = HASHbufferReader.readLine();
		
		FileReader HMACfileReader = new FileReader(hmacFile);
		BufferedReader HMACbufferReader = new BufferedReader(HMACfileReader);
		String hmacFromFile = HMACbufferReader.readLine();
		
		if(hashFor10.equals(hashFromFile) && hmacFor10.equals(hmacFromFile)) {
			return true;
		}
		else
		{
			return false;
		}
    }
    
    // Step 4: Generate AES key from the shared secret. See Excel for details
    public static byte[] generateSecretKey(String sharedSecret) throws Exception {
    	
    	// Flip the bit 5 of byte 14 from left to right
    	byte[] key = sharedSecret.getBytes();
    	key[13] = (byte) (key[13] ^ 0x20);
    	
    	return key;
    }


    // Step 5: Encrypt document with AES and received key
    public static void encryptDocument(String filePath, byte[] key) throws Exception {
		File inputF = new File(filePath);
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("File missing");
		}
		
		String name = filePath;
		int pos = name.lastIndexOf(".");
		if (pos > 0) {
		    name = name.substring(0, pos);
		}
		File outputF = new File(name + ".enc");
		if(!outputF.exists()) {
			outputF.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputF);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		FileOutputStream fos = new FileOutputStream(outputF);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
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

    
    public static void main(String[] args) {


        try {
            // Step 1: Generate and store file digest
            generateFilesDigest(FOLDER_PATH);

            // Step 2: Generate and store HMAC for file authentication
            generateFilesHMAC(FOLDER_PATH, SHARED_SECRET);
            
            String filename = "messages\\message_10_5emaqc.txt"; //choose any message.txt file from the folder and test it
            String hashFile = "hashes\\message_10_5emaqc.digest"; //the corresponding hash file
            String hmacFile = "hmacs\\message_10_5emaqc.hmac"; //the corresponding hmac file
            
            // Step 3: Verify the document
            if (retrieveAndVerifyDocument(filename, hashFile, hmacFile, SHARED_SECRET)) {
                System.out.println("Document retrieved successfully. Integrity verified.");
            } else {
                System.out.println("Document verification failed!");
            }
            
            //Step 3: Change the file content and re-check it to be sure your solution is correct
            
            
            // Step 4: Get the derived key
            byte[] derivedKey = generateSecretKey(SHARED_SECRET);

            // Step 5: Encrypt the document
            encryptDocument(filename, derivedKey);    // se salveaza in fisierul messagges


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
