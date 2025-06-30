package ro.ism.ase.lorena.casuneanu;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JAVA_exam_Iulie_2022 {
	
	private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
	
	public static void AESDecrypt(String inputFile, String outputFile, byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
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
		
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		
		//read IV
		byte[] IV = new byte[cipher.getBlockSize()];
		//fis.read(IV);
		//for (int i=0;i<cipher.getBlockSize(); i++)
		IV[0] = 0x33;
		
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
	
	public static byte[] getHash(String equation) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

		MessageDigest md = MessageDigest.getInstance("MD5");

		md.update(equation.getBytes());

		// Get final hash
		byte[] hashValue = md.digest();
		return hashValue;
	}
	
	public static byte[] getHMAC(String line, String algorithm, String password) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		byte[] lineBytes = line.getBytes();
		
		Mac hmac = Mac.getInstance(algorithm);
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		hmac.init(key);
		
		hmac.update(lineBytes);
		
		byte[] result = hmac.doFinal();
		
		return result;
	}
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		//Exer 1
		String HMAC = "c1779745da19a6de1795cfcc5cd10f8a8d4ec93be1e27013ffb668a2dcbf7a3d";
		byte[] BytesHMAC = hexStringToByteArray(HMAC);
		String myFilesFounded = null;
		
		byte[] MD5Hash = null;
		
		File repository = new File("Messages");
		if(repository.exists() && repository.isDirectory()) {
			//print location content
			File[] items = repository.listFiles();
			for(File item : items) {
	
				FileReader fileReader = new FileReader(item);
				BufferedReader bufferReader = new BufferedReader(fileReader);
				String line = bufferReader.readLine();;
				bufferReader.close();
				
				byte[] BytesHMACResulted = getHMAC (line, "HmacSHA256", "ismsecret");
				
				if(Arrays.equals(BytesHMACResulted, BytesHMAC)) {
					System.out.println("My file is: " + item.getName());
					myFilesFounded = item.getAbsolutePath();
					break;
				}
			}
		}
		
		
		// Exer 2
		File inputF = new File("Message_696.txt");
		if(!inputF.exists()) {
			throw new UnsupportedOperationException("No File");
		}
		FileReader fileReader = new FileReader(inputF);
		BufferedReader bufferReader = new BufferedReader(fileReader);
		String line = bufferReader.readLine();;
		bufferReader.close();
		MD5Hash = getHash(line);
		
		//Exer 3
		AESDecrypt("Question_696.enc", "Question_696_dec.txt", MD5Hash);
		
		
		
		
	}
}
