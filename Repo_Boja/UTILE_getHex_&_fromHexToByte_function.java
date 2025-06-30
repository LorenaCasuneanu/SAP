
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


--> // Calculeaza pentru fiecare fisier hash (dar e functia separata)
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

  --> //CITIRE DUPA UN ANUMIT CHARATER DINTR-UN FILE
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