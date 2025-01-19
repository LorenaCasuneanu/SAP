package ro.ase.ism.sap.lorena.casuneanu;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TestLostPassword {

	public static byte[] getHash (byte[] input, String algorithm) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		return md.digest(input);
	}
	
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
	
	boolean founded = true;
	byte[] myHash = hexStringToByteArray("82E14169CED3BD6612336FE774E90DC7EB2E302F8BCC6AEF4EF46CBF6267DB34"); 
	//reading from text file
	File messageTextFile = new File("ignis-10M.txt");
	
	if(!messageTextFile.exists()) {
		throw new UnsupportedOperationException("FOLDER is not there");
	}
	FileReader fileReader = new FileReader(messageTextFile);
	BufferedReader bufferedReader = new BufferedReader(fileReader);
	
	String line;
	long tstart = System.currentTimeMillis();
	while((line = bufferedReader.readLine()) != null)
	{
		String saltedPassword = "ismsap" + line;
		byte[] saltedPasswordHash = getHash(getHash(saltedPassword.getBytes(),"MD5"), "SHA-256");

		if (Arrays.equals(saltedPasswordHash, myHash))
		{
			System.out.println("Found it!\n");
			System.out.println("The password is: " + line);
			
			founded = false;
			break;
		}
	}
	long tfinal = System.currentTimeMillis();
	System.out.println("\nDuration is: " + (tfinal-tstart) + " milliseconds.");
	
	if (founded) {
		System.out.println("No password has been found.\n");
	}
	bufferedReader.close();
	}
}
