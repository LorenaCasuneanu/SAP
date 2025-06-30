package ro.ase.ism.sap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Certificate {
	String owner;
	List<Byte> publicKey;
	int keySize;
	String domain;
	
	public Certificate(String owner, List<Byte> publicKey, int keySize, String domain) {
		super();
		this.owner = owner;
		//this.publicKey = publicKey; //shallow copy
		this.publicKey = List.copyOf(publicKey);
		this.keySize = keySize;
		this.domain = domain;
	}
	
	void print() {
		System.out.println("Owner: " + this.owner);
		System.out.println("Domain: " + this.domain);
		System.out.println("Key size: " + this.keySize);
		System.out.println("Public key: ");
		for(byte b : this.publicKey) {
			System.out.printf(" %02x", b);
		}
		System.out.println();		
	}

	@Override
	public int hashCode() {
		return this.domain.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		
		if(obj == null || !(obj instanceof Certificate)) {
			return false;
		}
		return this.domain.equals(((Certificate)obj).domain);
	}

	@Override
	protected Object clone() throws CloneNotSupportedException {
		return new Certificate(
				this.owner, 
				this.publicKey, 
				this.keySize, 
				this.domain);
				
	}
	
	
	public static void main(String[] args) {
		
		//collections types
		//Lists - variable size arrays, ordered by insertion
		//Sets - variable size arrays with unique values
		//Map - dictionary of key - value pairs, key is unique
		
		//lists
		List<String> files = new ArrayList<>();
		files.add("Keys.txt");
		files.add("Passwords.txt");
		files.add("Users.txt");
		files.add("Passwords.txt");
		
		for(String filename : files) {
			System.out.println("File: " + filename);
		}
		
		//sets
		Set<String> usernames = new HashSet<String>();
		usernames.add("Alice");
		usernames.add("Alice");
		usernames.add("John");
		usernames.add("Bob");
		
		for(String username : usernames) {
			System.out.println("User: " + username);
		}
		
		//map
		HashMap<Integer, String> users = new HashMap<>();
		users.put(10, "Alice");
		users.put(20, "John");
		users.put(30, "Bob");
		users.put(10, "Vader");
		
		String user = users.get(10);
		if(user != null) {
			System.out.println("User with id 10 is " + user);
		}
		else {
			System.out.println("No user with id 10");
		}
		
		for(Integer id : users.keySet()) {
			System.out.printf("\n Id %d - %s", id, users.get(id));
		}
			
		//Test shallow copy
		List<Byte> key = Arrays.asList(
				(byte)0xA4, (byte)0x10, (byte)0x2F, (byte)0x22);
		Certificate certISM = 
				new Certificate("ISM", key, 1024, "ism.ase.ro");
		certISM.print();
		
		Certificate certPortalISM = 
				new Certificate("PortalISM", key, 1024, "portal.ism.ase.ro");
		certPortalISM.print();
		
		key.set(1, (byte)0xFF);
		
		certISM.print();
		
		//BitSet
		
		BitSet bitSet = new BitSet(32);
		bitSet.set(0);
		bitSet.set(30);
		bitSet.set(29, false);
		
		BitSet register = 
				BitSet.valueOf(new byte[]{(byte)0xA4, (byte)0x10, (byte)0x2F, (byte)0x22});
		
	    System.out.println("Register: ");
	    for(int i = 0; i < register.size(); i++) {
	    	System.out.printf("%d", register.get(i) ? 1 : 0);
	    }
	    
	    System.out.println("Register: ");
	    for(byte b : register.toByteArray()) {
	    	System.out.printf(" %02x", b);
	    }
		
				
	}
	
}
