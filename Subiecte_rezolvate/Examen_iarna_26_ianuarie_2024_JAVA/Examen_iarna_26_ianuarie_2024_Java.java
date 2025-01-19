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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Examen_iarna_26_ianuarie_2024_Java {
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for (byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}

	public static String findFile(String givenHash) throws NoSuchAlgorithmException, IOException {
		File repository = new File(
				"C:\\Users\\nxf71449\\eclipse-master-2025\\Examen_iarna_26_ianuarie_2024_Java\\users");
		String myFile = null;

		if (repository.exists() && repository.isDirectory()) {
			File[] items = repository.listFiles();
			if (items != null) {
				for (File item : items) {
					try (FileInputStream fis = new FileInputStream(item);
							BufferedInputStream bis = new BufferedInputStream(fis)) {

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

						byte[] givenHashBytes = Base64.getDecoder().decode(givenHash);
						if (Arrays.equals(hashValue, givenHashBytes) == true) {
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

	public static void AESDecrypt(String inputFile, String outputFile, byte[] key)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		File inputF = new File(inputFile);
		if (!inputF.exists()) {
			throw new UnsupportedOperationException("No File");
		}
		File outputF = new File(outputFile);
		if (!outputF.exists()) {
			outputF.createNewFile();
		}

		FileInputStream fis = new FileInputStream(inputF);
		FileOutputStream fos = new FileOutputStream(outputF);

		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

		// read IV
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[10] = (byte) 0xFF;

		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

		byte[] buffer = new byte[cipher.getBlockSize()];
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

	public static byte[] deriveKeyWithPBKDF2(String password, int noIterations, int keySize) {
		try {

			String salt = "ism2021";

			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), noIterations, keySize);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte[] key = factory.generateSecret(spec).getEncoded();

			FileOutputStream fos = new FileOutputStream("deriveKeyWithPBKDF2.bin");
			fos.write(key);
			fos.close();

			return key;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, SignatureException {

		// Subiectul 1
		String myHash = "40a2axxv4JIFnUiGE5hl4QifwagV/gQl6GC4voDfzI4=";

		// Subiectul 2
		String myFileFounded = findFile(myHash);
		String myKey = "userfilepass%5]2";

		AESDecrypt(("C:\\Users\\nxf71449\\eclipse-master-2025\\Examen_iarna_26_ianuarie_2024_Java\\users\\"
				+ myFileFounded), "pwd.txt", myKey.getBytes());

		FileReader fileReader = new FileReader("pwd.txt");
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		String myPwd = bufferedReader.readLine();
		System.out.println("The password is " + myPwd);
		bufferedReader.close();

		// Subiectul 3
		deriveKeyWithPBKDF2(myPwd, 1500, 160);

		KeyStore ks = KeyStoreManager.getKeyStore("ismkeystore.ks", "passks", "pkcs12");
		KeyStoreManager.list(ks);

		PublicKey pubIsm1 = KeyStoreManager.getPublicKey("ismkey1", ks);
		PrivateKey privIsm1 = KeyStoreManager.getPrivateKey("ismkey1", "passism1", ks);

		System.out.println("Public key:");
		System.out.println(getHexString(pubIsm1.getEncoded()));
		System.out.println("Private key");
		System.out.println(getHexString(privIsm1.getEncoded()));

		// Semnam fisierul mydata.bin
		byte[] signature = RSACipher_Signature.signFile("deriveKeyWithPBKDF2.bin", privIsm1);

		System.out.println("Digital signature value: ");
		System.out.println(getHexString(signature));

		// writing into binary files the signature above created
		File signatureFile = new File("DataSignature.ds");
		FileOutputStream fosSig = new FileOutputStream(signatureFile);
		fosSig.write(signature);
		fosSig.close();
		
		//friend verifies the signature
		PublicKey pubIsm1FromCert = PublicCertificate.getCertificateKey("ISMCertificateX509.cer");
		System.out.println("Public key from certificate: ");
		System.out.println(getHexString(pubIsm1FromCert.getEncoded()));
		
		if(RSACipher_Signature.hasValidSignature("deriveKeyWithPBKDF2.bin", pubIsm1FromCert, signature)) {
			System.out.println("File is the original one");
		} else {
			System.out.println("File has been changed");
		}

	}
}
