package tests.pattern;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.ec.ECDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class ECElGamalDecryptorTest extends UsagePatternTestingFramework {
	
	BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

    ECCurve.Fp curve = new ECCurve.Fp(
        new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
        new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
        new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
        n, ECConstants.ONE);
    
    ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);
    
	ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

	ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
	    new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
	    params);
	
	ParametersWithRandom pRandom = new ParametersWithRandom(pubKey, new SecureRandom());
	
	@Override
	protected String getSootClassPath() {
		String sootCp = super.getSootClassPath();
		String dir = System.getProperty("user.dir");
		sootCp += File.pathSeparator + dir + "/src/test/java/tests/jars/bouncy_castle/bcprov-jdk15on-1.60.jar";
		return sootCp; 
	}
	
	@Test
	public void testECElGamalDecryptorOne() {
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECEncryptor encryptor = new ECElGamalEncryptor();
        encryptor.init(pRandom);
        ECPair pair = encryptor.encrypt(data);
		ECDecryptor decryptor = (ECDecryptor) new ECElGamalDecryptorTest();
        decryptor.init(priKey);
        ECPair pair2 = new ECPair(pair.getX(), pair.getY());
        decryptor.decrypt(pair2);
        
        Assertions.hasEnsuredPredicate(pair2);
        Assertions.mustBeInAcceptingState(decryptor);
	}
	
	@Test
	public void testECElGamalDecryptorTwo() {
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECEncryptor encryptor = new ECElGamalEncryptor();
        encryptor.init(pRandom);
        ECPair pair = encryptor.encrypt(data);
		ECDecryptor decryptor = (ECDecryptor) new ECElGamalDecryptorTest();
        decryptor.init(priKey);
        ECPair pair2 = new ECPair(pair.getX(), pair.getY());
        decryptor.decrypt(pair2);
        decryptor.decrypt(pair2);
        
        Assertions.hasEnsuredPredicate(pair2);
        Assertions.mustBeInAcceptingState(decryptor);
	}
	
	//Error
	public void testECElGamalDecryptorThree() {
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECEncryptor encryptor = new ECElGamalEncryptor();
        encryptor.init(pRandom);
        ECPair pair = encryptor.encrypt(data);
		ECDecryptor decryptor = (ECDecryptor) new ECElGamalDecryptorTest();
		ECPair pair2 = new ECPair(pair.getX(), pair.getY());
        decryptor.decrypt(pair2);
        
        Assertions.hasEnsuredPredicate(pair2);
        Assertions.mustNotBeInAcceptingState(decryptor);
	}
}
