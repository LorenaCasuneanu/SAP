package ro.ase.ism.sap.lorena.casuneanu;

import java.util.BitSet;
import java.util.Random;

public class TestLFSR {
	// implements a simple LSFR with a 32 bit register and
	// TAP sequence x^31+x^7+x^5+x^3+x^2+x+1

	// implementation - integer vs byte array of 4 values
	// integer implementation

	public static void printRegister(int register) {
		System.out.println("Register: " + Integer.toBinaryString(register));
		System.out.println("Register: " + Integer.toHexString(register));
	}

	public static int initRegister(byte[] initialValues) {
		if (initialValues.length != 4) {
			System.out.println("Wrong initial value. 4 bytes needed");
			return 0;
		}
		int result = 0;
		for (int i = 3; i >= 0; i--) {
			result = result | (((int) initialValues[3 - i] & 0xFF) << (i * 8));
		}
		return result;
	}

	public static byte applyTapSequence(int register) {
		// TAP sequence x^31+x^7+x^5+x^3+x^2+x+1
		byte result = 0;
		byte[] index = { 31, 7, 5, 3, 2, 1, 0 };
		for (int i = 0; i < index.length; i++) {
			byte bitValue = (byte) (((1 << index[i]) & register) >>> index[i]);
			result = (byte) (result ^ bitValue);
		}
		return result;
	}

	public static byte getLeastSignificantBit(int register) {
		return (byte) (register & 1);
	}

	public static int shiftAndInsertTapBit(int register, byte tapBit) {
		register = register >>> 1;
		register = register | (tapBit << 31);
		return register;
	}

	public static int fullLFSRStep(int register) {
		byte tapBit = 0;
		tapBit = applyTapSequence(register);
		register = shiftAndInsertTapBit(register, tapBit);

		return register;
	}

	public static int getBitAtIndex(int number, int index) {
		return (number >> index) & 1;
	}

	public static byte[] generateByteArray(int register, int size) {
		byte[] pseudoRandomArray = new byte[size];
		Random random = new Random();

		// Add the current time in milliseconds with random value
		long timeSeed = System.nanoTime() + random.nextInt();
		register ^= (int) (timeSeed & 0xFFFFFFFF); // XOR to add randomness from the time

		for (int i = 0; i < size; i++) {
			byte oneByte = 0;
			for (int j = 0; j < 8; j++) {
				byte lsb = getLeastSignificantBit(register);
				oneByte = (byte) ((oneByte << 1) | lsb);
				register = fullLFSRStep(register);
			}
			pseudoRandomArray[i] = oneByte;
		}
		return pseudoRandomArray;
	}

	public static void convertByteToHexadecimal(byte[] byteArray) {
		String hex = "";
		for (byte i : byteArray) {
			hex += String.format("%02X", i);
		}
		System.out.println(hex);
	}

	public static boolean applyTapSequence(BitSet register) {
		// TAP sequence x^31+x^7+x^5+x^3+x^2+x+1
		boolean result = false;
		byte[] index = { 31, 7, 5, 3, 2, 1, 0 };
		for (int i = 0; i < index.length; i++) {
			result = result ^ register.get(i);
		}
		return result;
	}

	public static boolean getLeastSignificantBit(BitSet register) {
		return register.get(0);
	}

	public static BitSet shiftAndInsertTapBit(BitSet register, boolean tapBit) {
		BitSet shifted = new BitSet(register.size());
		if (register.length() > 1) {
			shifted.or(register.get(1, register.length()));
		}
		shifted.set(register.size() - 1, tapBit); // insert the tap bit at the highest position
		return shifted;
	}

	public static BitSet fullLFSRStep(BitSet register) {
		boolean tapBit = false;
		tapBit = applyTapSequence(register);
		register = shiftAndInsertTapBit(register, tapBit);

		return register;
	}

	public static byte[] generateByteArray(BitSet register, int size) {
		byte[] pseudoRandomArray = new byte[size];
		Random random = new Random();

		for (int i = 0; i < size; i++) {
			byte oneByte = 0;
			// Add current time and a random number
			long timeSeed = System.nanoTime() + random.nextInt();
			BitSet timeSeedBits = BitSet.valueOf(new long[] { timeSeed });
			register.xor(timeSeedBits);

			for (int j = 0; j < 8; j++) {
				boolean lsb = getLeastSignificantBit(register);
				oneByte = (byte) ((oneByte << 1) | (lsb ? 1 : 0));
				register = fullLFSRStep(register);
			}
			pseudoRandomArray[i] = oneByte;
		}
		return pseudoRandomArray;
	}

	public static BitSet initRegisterBitSet(byte[] seed) {
		BitSet bitSet = BitSet.valueOf(seed);
		BitSet reversedBitSet = new BitSet(seed.length * 8);

		// reverse bit positions to match the endianness
		for (int i = 0; i < seed.length * 8; i++) {
			if (bitSet.get(i)) {
				reversedBitSet.set((seed.length * 8 - 1) - i);
			}
		}
		return reversedBitSet;
	}

	public static void main(String[] argv) {
		// the initial seed
		byte[] seed = { (byte) 0b10101010, (byte) 0b11110000, (byte) 0b00001111, (byte) 0b01010101 };

		// 1.Test for LFSR with integer
		int intRegister = initRegister(seed);
		printRegister(intRegister);

		fullLFSRStep(intRegister);
		printRegister(intRegister);

		System.out.println("Integer: The 20 bytes array of pseudo random values is: ");
		convertByteToHexadecimal(generateByteArray(intRegister, 20));

		System.out.println("Integer: The 50 bytes array of pseudo random values is: ");
		convertByteToHexadecimal(generateByteArray(intRegister, 50));

		// 2.Test for LFSR with BitSet
		BitSet bitSetRegister = initRegisterBitSet(seed);
		System.out.println("BitSet: The 20 bytes array of pseudo random values is: ");
		convertByteToHexadecimal(generateByteArray(bitSetRegister, 20));

		System.out.println("BitSet: The 50 bytes array of pseudo random values is: ");
		convertByteToHexadecimal(generateByteArray(bitSetRegister, 50));
	}
}