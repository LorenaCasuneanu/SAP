import java.io.*;
import java.security.MessageDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileHashCalculator {

    public static void listFolder(File repository) {
        if (repository.exists() && repository.isDirectory()) {
            // Print location content
            File[] items = repository.listFiles();
            for (File item : items) {
                System.out.println(item.getName() + " - " +
                        (item.isFile() ? "FILE" : "FOLDER"));
                System.out.println(item.getAbsolutePath());

                if (item.isFile()) {
                    // Compute the hash of the file
                    try {
                        String hash = calculateFileHash(item);
                        System.out.println("Hash (MD5): " + hash);
                    } catch (Exception e) {
                        System.out.println("Error calculating hash for file: " + item.getName());
                        e.printStackTrace();
                    }
                } else if (item.isDirectory()) {
                    listFolder(item);
                }
            }
        } else {
            System.out.println("************* The directory does not exist");
        }
    }

    private static String calculateFileHash(File file) throws Exception {
        // Create a MessageDigest instance for MD5
        MessageDigest md = MessageDigest.getInstance("MD5", "BC");

        // Read the file and update the MessageDigest
        try (FileInputStream fis = new FileInputStream(file);
             BufferedInputStream bis = new BufferedInputStream(fis)) {
            byte[] buffer = new byte[8192]; // Use a larger buffer for efficiency
            int noBytes;

            while ((noBytes = bis.read(buffer)) != -1) {
                md.update(buffer, 0, noBytes);
            }
        }

        // Convert the hash to a hex string
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        File folder = new File("your/folder/path"); // Change to your folder path
        listFolder(folder);
    }
}