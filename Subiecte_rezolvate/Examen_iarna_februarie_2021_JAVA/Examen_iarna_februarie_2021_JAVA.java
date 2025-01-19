package ism.ase.ro.sap.exam.Casuneanu.Lorena;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
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


public class Examen_iarna_februarie_2021_JAVA {
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
		public static PrivateKey getPrivateKey(String keyStoreFileName, String keyStorePass, String keyAlias, String keyPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,UnrecoverableKeyException {

			File file = new File(keyStoreFileName);
			if(!file.exists()) {
				throw new UnsupportedOperationException("Missing key store file");
			}
			
			FileInputStream fis = new FileInputStream(file);
			
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(fis, keyStorePass.toCharArray());
			fis.close();
			
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
			
			File file = new File(inputFileName);
			if(!file.exists()) {
				throw new FileNotFoundException();
			}
			FileInputStream fis = new FileInputStream(file);
			byte[] fileContent = fis.readAllBytes();
			fis.close();
			
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(key);
			signature.update(fileContent);
			byte[] mySig = signature.sign();

			File signatureFile = new File(signatureFileName);
			FileOutputStream fosSig = new FileOutputStream(signatureFile);
			fosSig.write(mySig);
			fosSig.close();

		}


		//proposed function for generating the hash value
		public static byte[] getSHA1Hash(File file)
				throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
			
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);

			MessageDigest md = MessageDigest.getInstance("SHA1");

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

			FileInputStream fis = new FileInputStream(inputFile);
			FileOutputStream fos = new FileOutputStream(outputFile);

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

			//read IV
			byte[] IV = new byte[cipher.getBlockSize()];
			fis.read(IV);

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

	    //proposed function for print the text file content
		public static void printTextFileContent(String textFileName) throws	IOException {

			System.out.println("You must load the OriginalData.txt file and print its content");
			FileReader fileReader = new FileReader(textFileName);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String content = bufferedReader.readLine();
			System.out.println("The test file content is: " + content);
			bufferedReader.close();

		}

		public static void main(String[] args) {
			try {

				/* Request 1 */
				File passFile = new File("Passphrase.txt");
				byte[] hashValue = getSHA1Hash(passFile);
				System.out.println("SHA1: " + getHex(hashValue));
				
				/* Request 2 */
				//generate the key form previous hash
				byte[] key = null;
				key = Arrays.copyOfRange(hashValue, 0, 16);
				System.out.println("key: " + getHex(key));
				
				//decrypt the input file 
				//there is no need for padding and the IV is written at the beginning of the file
				decryptAESCBC(new File("EncryptedData.data"), new File("OriginalData.txt"), key);
				printTextFileContent("OriginalData.txt");
				
				//get the keyStorePassword from OriginalMessage.txt. Copy paste the values from the console
				String ksPassword = "you_already_made_it";
				String keyName = "sapexamkey";
				String keyPassword = "grant_access";
				
				/* Request 3 */
				//compute the RSA digital signature for the EncryptedMessage.cipher file and store it in the
				//	signature.ds file
				
				PrivateKey privKey = getPrivateKey("sap_exam_keystore.ks",ksPassword,keyName,keyPassword);
				getDigitalSignature("OriginalData.txt", "DataSignature.ds", privKey);
				
				
				//optionally - you can check if the signature is ok using the given SAPExamCertificate.cer
				//not mandatory
				//write code that checks the previous signature
				PublicKey pubIsm1FromCert = getCertificateKey("SAPExamCertificate.cer");
				System.out.println("Public key from certificate: ");
				System.out.println(getHex(pubIsm1FromCert.getEncoded()));
				
				
				File file = new File("OriginalData.txt");
				if(!file.exists()) {
					throw new FileNotFoundException();
				}
				
				FileInputStream fis = new FileInputStream(file);	
				byte[] fileContent = fis.readAllBytes();	
				fis.close();
				
				Signature signatureModule = Signature.getInstance("SHA256withRSA");
				signatureModule.initVerify(pubIsm1FromCert);
				
				File sigFile = new File("DataSignature.ds");
				if(!sigFile.exists()) {
					throw new FileNotFoundException();
				}
				FileInputStream fos = new FileInputStream(sigFile);	
				byte[] SignatureContent = fos.readAllBytes();	
				fis.close();
				signatureModule.update(fileContent);				
				
				if(signatureModule.verify(SignatureContent)) {
					System.out.println("File is the original one");
				} else {
					System.out.println("File has been changed");
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
}
