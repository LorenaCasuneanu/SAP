

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthSeparatorUI;

public class YourNameExam {

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

		return null;
	}

	
	// method for computing the RSA digital signature
	public static void getDigitalSignature(
			String inputFileName, 
			String signatureFileName, 
			PrivateKey key)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		
		//generate and store the RSA digital signature of the inputFileName file
		//store it in signatureFileName file

	}


	//proposed function for generating the hash value
	public static byte[] getSHA1Hash(File file)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//generate the SHA-1 value of the received file

		return null;
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

	}

    //proposed function for print the text file content
	public static void printTextFileContent(
			String textFileName) throws	IOException {

		//print the text file content on the console
		//you need to do this to get values for the next request

		System.out.println("You must load the OriginalData.txt file and print its content");

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
			
			//decrypt the input file 
			//there is no need for padding and the IV is written at the beginning of the file
			decryptAESCBC(new File("EncryptedData.data"), new File("OriginalData.txt"), key);
			

			printTextFileContent("OriginalData.txt");
			
			//get the keyStorePassword from OriginalMessage.txt. Copy paste the values from the console
			String ksPassword = "........";
			String keyName = "sapexamkey";
			String keyPassword = "..............";
			
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
			
			
			
			System.out.println("Done");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
