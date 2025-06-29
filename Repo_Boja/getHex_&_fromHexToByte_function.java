package ro.ase.ism.sap;

public class Utility {
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte b : values) {
			sb.append(String.format(" %02x", b));
		}
		return sb.toString();
	}
	
	private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
