

//rename the class with your name
//use a package with the next pattern 
//	ro.ase.ism.sap.lastname.firstname
public class YourSolution {

	// 1. Step 1: return your file name
	public static String findFile(String hash) {
		return "";
	};
	
    // 2. Step 2: Generate HMAC for Authentication
    public static void generateHMAC(String filename, String sharedSecret){
    	
    }
    
    // 3. Step 3: Derive Key with PBKDF2
    public static byte[] deriveKeyWithPBKDF2(
    		String password, int noIterations, int keySize) {
    	return null;
    }
    
    // 4. Step 4: Encrypt File with AES and Save IV
    public static void encryptFileWithAES(String filename, byte[] key) {
    	
    }
    
    // 5. Step 5: Encrypt with 3DES for Archival 
    public static void encryptWith3DES(String filename, byte[] key) {
    	
    }

    // 6. Step 6: Apply Cyclic Bitwise Shift
    public static void applyCyclicShift(String filename) {
    	
    }
	
	public static void main(String[] args) {

	    	String hash = ""; //copy it from the given Excel file
	    	String sharedSecret = ""; //copy it from the given Excel file
	    	int noIterations = 0; //copy it from the given Excel file
	    	
	        try {
	            // 1. Step 1
	        	String filename = findFile(hash);
	        	
	            // 2. Step 2: Generate HMAC for Authentication
	            generateHMAC(filename, sharedSecret);
	            
	            int keySize = 0;
	            byte[] key;
	            // 3. Step 3: Derive Key with PBKDF2
	            key = deriveKeyWithPBKDF2(sharedSecret, noIterations, keySize);

	            // 4. Step 4: Encrypt File with AES and Save IV
	            encryptFileWithAES(filename, key);
	          
	            // 5. Step 5: Encrypt with 3DES for Archival
	            keySize = 0;
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
