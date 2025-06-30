
/// !!!!!!!!!!! .toString() --> [B@53... (o adresa)

/// !!!!!!!!!! copy first 16 bytes from a byte[] in JAVA --> byte[] IV = Arrays.copyOfRange(original,0, 16);     SAAAU for - classic
public static String getHex(byte[] values) {
    StringBuilder sb = new StringBuilder();
    for(byte b : values) {
        sb.append(String.format(" %02x", b));
    }
    return sb.toString();
}

 --> // Daca inputul este String HEX, nu pot sa-l compar ca atare cu Arrays.equals pentru ca HEX NU ESTE INTERPRETAT BINE
private static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
}


--> // Calculeaza pentru fiecare fisier hash (pentru HASH e functia separata)
    File repository = new File("users");
    if(repository.exists() && repository.isDirectory()) {
        //print location content
        File[] items = repository.listFiles();
        for(File item : items) {

            byte[] hashoffile = getSHA256Hash(item.getAbsolutePath());
            
            if(Arrays.equals(myinitialHashValue, hashoffile)) {
                System.out.println("The user is: " + item.getName());
                myFilesFounded = item.getAbsolutePath();
                break;
            }
        }
    }

  --> //CITIRE DUPA UN ANUMIT CHARACTER DINTR-UN FILE
    {
        String text = "Ana = o2";
        char delimiter = '=';

        int pos = text.indexOf(delimiter);
        String result = "";

        if (pos != -1) { // Check if = exists
            result = text.substring(pos + 1).trim(); // Extract substring after '=' and trim spaces
        }

        System.out.println("Substring after '" + delimiter + "': " + result);
    }

--> // Converting numbers to STRING: INT sau BYTE to String sub forma binara sau sub forma hexazecimala
	{	int value = 33;
		String binaryRep = Integer.toBinaryString(value);
		String hexRep = Integer.toHexString(value);
    }

--> // Converting numbers to INT din STRING
	{	///from string to numbers
		Integer initialValue = Integer.parseInt(hexRep,16);
		initialValue = Integer.parseInt(binaryRep,2);
    }

--> // READ all bytes from a file 
    {
		File fileFoundedKey = new File(myFilesFounded);
		if(!fileFoundedKey.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fisKey = new FileInputStream(fileFoundedKey);	
		byte[] key = fisKey.readAllBytes();	
		fisKey.close();
    }

--> // SCRIE all bytes of a byte[] to a file 
    {
    	File outputF = new File("myresponse.txt");
		if(!outputF.exists()){
			outputF.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(outputF);
		fos.write(iban.getBytes());
		fos.close();
    } 
//SAAAAAAAU, DACA vreau sa scriu un STRING intr-un fisier
    {
		File msgFile = new File("Message.txt");
		if(!msgFile.exists()) {
			msgFile.createNewFile();
		}
		
		//write into a text file, append mode
		FileWriter fileWriter = new FileWriter(msgFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println("This is a secret message");
		printWriter.println("Don't tell anyone");
		printWriter.close();
    }


--> // Sa afisezi byte[] sub forma de STRING
    {
    	byte[] userPWD = AES_CBC_Decrypt(myFilesFounded, IV, pwd.getBytes());
		System.out.println("The user password is: ");
		System.out.println(new String(userPWD));
    }