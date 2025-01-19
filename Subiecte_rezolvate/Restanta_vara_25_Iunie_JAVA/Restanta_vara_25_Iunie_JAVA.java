package ism.ase.ro.sap.exam.Casuneanu.Lorena;

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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.Spring;

public class Restanta_vara_25_Iunie_JAVA {

	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for (byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}

	public static byte[] calculateHash(String FileName) throws NoSuchAlgorithmException, IOException {

		File msgFile = new File(FileName);
		FileInputStream fis = new FileInputStream(msgFile);
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

	public static void AESEncrypt(String inputFile, String outputFile, byte[] key)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		File inputF = new File(inputFile);
		if (!inputF.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		File outputF = new File(outputFile);
		if (!outputF.exists()) {
			outputF.createNewFile();
		}
		FileInputStream fis = new FileInputStream(inputF);
		FileOutputStream fos = new FileOutputStream(outputF);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

		byte[] buffer = new byte[cipher.getBlockSize()];

		byte[] IV = new byte[cipher.getBlockSize()];
		IV[5] = (byte) 0xCC;

		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

		while (true) {
			int noBytes = fis.read(buffer);
			if (noBytes == -1) {
				break;
			}
			byte[] output = cipher.update(buffer, 0, noBytes);
			fos.write(output);
		}

		byte[] output = cipher.doFinal();
		fos.write(output);

		fis.close();
		fos.close();

	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// Subiectul 1
		byte[] myHash = calculateHash("msg.txt");
		System.out.println("myHash =  " + getHexString(myHash));
		
		// Subiectul 2
		String Key = "passwordsecurity";
		
		AESEncrypt("msg.txt", "enc_msg.aes", Key.getBytes());
 	}
}
