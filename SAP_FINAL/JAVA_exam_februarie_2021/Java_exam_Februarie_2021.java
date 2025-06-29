package ism.ase.ro;



import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;import java.nio.file.Paths;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthSeparatorUI;

public class Java_exam_Februarie_2021 {
	public static boolean isValid(
			String filename, String signatureFile, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		FileInputStream fis = new FileInputStream(inputFile);
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify(publicKey);
		
		byte[] buffer = fis.readAllBytes();		
		fis.close();
		
		sign.update(buffer);
		
		File inputSignatureFile = new File(signatureFile);
		FileInputStream fisSig = new FileInputStream(inputSignatureFile);
		byte[] signature = fisSig.readAllBytes();		
		fisSig.close();
		return sign.verify(signature);
	}
	// provided method for getting the public key from a X509 certificate file
	public static PublicKey getCertificateKey(String file) throws FileNotFoundException, CertificateException {
		FileInputStream fis = new FileInputStream(file);

		CertificateFactory factory = CertificateFactory.getInstance("X509");

		X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);

		return certificate.getPublicKey();
	}
	
	//provided method to print a byte array to console
	public static String getHex(byte[] array) {
		String output = "";
		for(byte value : array) {
			output += String.format("%02x", value);
		}
		return output;
	}
	

	// method for getting the private key from a keystore
	public static PrivateKey getPrivateKey(
			String keyStoreFileName, 
			String keyStorePass, 
			String keyAlias,
			String keyPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
					UnrecoverableKeyException {
		
		File file = new File(keyStoreFileName);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing key store file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(fis, keyStorePass.toCharArray());
		
		if(ks.containsAlias(keyAlias)) {
			return (PrivateKey) ks.getKey(keyAlias, keyPass.toCharArray());
		} else {
			return null;
		}

	}

	
	// method for computing the RSA digital signature
	public static void getDigitalSignature(
			String inputFileName, 
			String signatureFileName, 
			PrivateKey key)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		
		//generate and store the RSA digital signature of the inputFileName file
		//store it in signatureFileName file
		
		File inputFile = new File(inputFileName);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("No FILE");
		}
		FileInputStream fis = new FileInputStream(inputFile);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		
		//process the entire file on one round
		byte[] buffer = fis.readAllBytes();
		signature.update(buffer);
		byte[] digitalSignature = signature.sign();
		
		fis.close();
		File outputFile = new File(signatureFileName);
		FileOutputStream fosSig = new FileOutputStream(outputFile);
		fosSig.write(digitalSignature);
		fosSig.close();

	}


	//proposed function for generating the hash value
	public static byte[] getSHA1Hash(File file)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//byte[] fileBytes = Files.readAllBytes(file.toPath());
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
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

	//proposed function for decryption
	public static void decryptAESCBC(
			File inputFile, 
			File outputFile, 
			byte[] key)
					throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException, BadPaddingException,
			IOException {

		//decrypt the input file using AES in CBC
		//the file was encrypted without using padding - didn't need it
		//the IV is at the beginning of the input file
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outputFile);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		byte[] IV = new byte[cipher.getBlockSize()];
		fis.read(IV);
		
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

    //proposed function for print the text file content
	public static void printTextFileContent(
			String textFileName) throws	IOException {

		//print the text file content on the console
		//you need to do this to get values for the next request

		System.out.println("You must load the OriginalData.txt file and print its content");
		
		FileReader fileReader = new FileReader(textFileName);
		BufferedReader bufferReader = new BufferedReader(fileReader);
		System.out.println("File content:");
		String line = null;
		do {
			line = bufferReader.readLine();
			if(line != null)
				System.out.println(line);
		}while(line != null);
				
		fileReader.close();
		
	}


	public static void main(String[] args) {
		try {

			
			/*
			 * 
			 * @author - Please write your name here and also rename the class
			 * 
			 * 
			 * 
			 */
			/*
			 * Request 1
			 */
			File passFile = new File("Passphrase.txt");
			byte[] hashValue = getSHA1Hash(passFile);
			System.out.println("SHA1: " + getHex(hashValue));
			
			
			//check point - you should get 268F10........ 
			
			
			/*
			 * Request 2
			 */

			//generate the key form previous hash
			byte[] key = null;
			key = Arrays.copyOf(hashValue, 16);
			//decrypt the input file 
			//there is no need for padding and the IV is written at the beginning of the file
			decryptAESCBC(new File("EncryptedData.data"), new File("OriginalData.txt"), key);
			

			printTextFileContent("OriginalData.txt");
			
			//get the keyStorePassword from OriginalMessage.txt. Copy paste the values from the console
			String ksPassword = "you_already_made_it";
			String keyName = "sapexamkey";
			String keyPassword = "grant_access";
			
			/*
			* Request 3
			*/


			//compute the RSA digital signature for the EncryptedMessage.cipher file and store it in the
			//	signature.ds file
			
			PrivateKey privKey = getPrivateKey("sap_exam_keystore.ks",ksPassword,keyName,keyPassword);
			getDigitalSignature("OriginalData.txt", "DataSignature.ds", privKey);
			
			
			//optionally - you can check if the signature is ok using the given SAPExamCertificate.cer
			//not mandatory
			//write code that checks the previous signature
			
			PublicKey public_key = getCertificateKey("SAPExamCertificate.cer");
			if(isValid("OriginalData.txt", "DataSignature.ds", public_key)) {
				System.out.println("The msg is valid");
			} else {
				System.out.println("Someone changed the msg");
			}
			
			System.out.println("Done");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
