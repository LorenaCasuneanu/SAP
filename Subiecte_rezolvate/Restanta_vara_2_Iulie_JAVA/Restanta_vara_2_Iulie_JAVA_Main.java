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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Restanta_vara_2_Iulie_JAVA_Main {

	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for (byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}

	public static String findFile() throws NoSuchAlgorithmException, IOException {
		File repository = new File("C:\\Users\\nxf71449\\eclipse-master-2025\\Restanta_vara_2_Iulie_JAVA\\system32");
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

						FileReader fileReader = new FileReader("sha2Fingerprints.txt");
						BufferedReader bufferReader = new BufferedReader(fileReader);

						String line = null;

						while ((line = bufferReader.readLine()) != null) {
							String nameFile = "system32\\" + item.getName();
							if (line.compareTo(nameFile) == 0) {
								line = bufferReader.readLine();
								byte[] hashBytesExtracted = Base64.getDecoder().decode(line);
								if (Arrays.equals(hashValue, hashBytesExtracted) == false) {
									myFile = item.getName();
									System.out.println("Found file: " + item.getName());
								}
								break;
							}
						}
						bufferReader.close();
						fileReader.close();
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

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// read IV
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[15] = (byte) 0x17;
		IV[14] = (byte) 0x14;
		IV[13] = (byte) 0x02;
		IV[12] = (byte) 0x03;

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

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			KeyStoreException, CertificateException, UnrecoverableKeyException, SignatureException {

		// Subiectul 1
		String myFileFounded = findFile();

		// Subiectul 2
		File exeFile = new File(
				"C:\\Users\\nxf71449\\eclipse-master-2025\\Restanta_vara_2_Iulie_JAVA\\system32\\" + myFileFounded);
		FileInputStream exeFis = new FileInputStream(exeFile);

		byte[] exeFileBytes = new byte[(int) exeFile.length()];
		exeFis.read(exeFileBytes); // Read file into byte array
		exeFis.close();

		AESDecrypt("financialdata.enc", "financialdata.txt", exeFileBytes);

		// Subiectul 3

		KeyStore ks = KeyStoreManager.getKeyStore("ismkeystore.ks", "passks", "pkcs12");
		KeyStoreManager.list(ks);

		PublicKey pubIsm1 = KeyStoreManager.getPublicKey("ismkey1", ks);
		PrivateKey privIsm1 = KeyStoreManager.getPrivateKey("ismkey1", "passism1", ks);

		System.out.println("Public key:");
		System.out.println(getHexString(pubIsm1.getEncoded()));
		System.out.println("Private key");
		System.out.println(getHexString(privIsm1.getEncoded()));

		// Semnam fisierul mydata.bin
		byte[] signature = RSACipher_Signature.signFile("myresponse.txt", privIsm1);

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
		
		if(RSACipher_Signature.hasValidSignature("myresponse.txt", pubIsm1FromCert, signature)) {
			System.out.println("File is the original one");
		} else {
			System.out.println("File has been changed");
		}
		
	} // main
}
