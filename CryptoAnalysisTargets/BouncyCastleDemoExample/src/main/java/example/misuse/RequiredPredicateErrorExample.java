package example.misuse;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class RequiredPredicateErrorExample {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BlockCipher engine = new AESEngine();

		// BufferedBlockCipher REQUIRES a generatedMode that is missing
		// But according to BlockCipherVectorTest this is correct
		BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
		System.out.println(cipher.getUnderlyingCipher().getAlgorithmName());

		byte[] plainText   = Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114F3F6752AE8D7831138F041560631B1145A01020304050607");
		byte[] key = Hex.decode("5F060D3716B345C253F6749ABAC10917");

		cipher.init(true, new KeyParameter(key));

		byte[] cipherText = new byte[cipher.getOutputSize(plainText.length)];

		int outputLen = cipher.processBytes(plainText, 0, plainText.length, cipherText, 0);

		try {
			cipher.doFinal(cipherText, outputLen);
		} catch (CryptoException ce) {
			// TODO Auto-generated catch block
			System.err.println(ce);
			System.exit(1);
		}
	}

	public static void useModeInsideAnotherMode() {
		BlockCipher aes = new AESEngine();
		BlockCipher cbc = new CBCBlockCipher(aes);

		// instead of passing an engine, we pass another mode here
		BlockCipher cfb = new CFBBlockCipher(aes, 16);
		BufferedBlockCipher cipher = new BufferedBlockCipher(cfb);

		byte[] plainText   = Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114F3F6752AE8D7831138F041560631B1145A01020304050607");
		byte[] key = Hex.decode("5F060D3716B345C253F6749ABAC10917");

		cipher.init(true, new KeyParameter(key));

		byte[] cipherText = new byte[cipher.getOutputSize(plainText.length)];

		int outputLen = cipher.processBytes(plainText, 0, plainText.length, cipherText, 0);

		try {
			cipher.doFinal(cipherText, outputLen);
		} catch (CryptoException ce) {
			// TODO Auto-generated catch block
			System.err.println(ce);
			System.exit(1);
		}
	}

}