package tests.pattern;

import java.io.File;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ec.ECFixedTransform;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class ECFixedTransformTest extends UsagePatternTestingFramework {
	
	BigInteger n = new BigInteger("47833908530");
	
	ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);
	    
	ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);
	
	ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
		    new BigInteger("65105615665659"),
		    params);
	
	@Override
	protected String getSootClassPath() {
		String sootCp = super.getSootClassPath();
		String dir = System.getProperty("user.dir");
		sootCp += File.pathSeparator + dir + "/src/test/java/tests/jars/bouncy_castle/bcprov-jdk15on-1.60.jar";
		return sootCp;
	}
	
	@Test
	public void testECFixedTransformOne() {
		ECFixedTransform ecGen = new ECFixedTransform(n);
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
		ecGen.init(keyParams);
        ecGen.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecGen);
		
	}
	
	@Test
	public void testECFixedTransformTwo() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECFixedTransform ecGen = new ECFixedTransform(n);
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
		ecGen.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustNotBeInAcceptingState(ecGen);
	}
	
	@Test
	public void testECFixedTransformThree() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECFixedTransform ecGen = new ECFixedTransform(n);
		ECPair srcPair = null;
		ecGen.init(keyParams);
		ecGen.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.notHasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecGen);
	}
	
	@Test
	public void testECFixedTransformFour() {
		CipherParameters keyParams = null;
		ECFixedTransform ecGen = new ECFixedTransform(n);
		ECPair srcPair = null;
		ecGen.init(keyParams);
		ecGen.transform(srcPair);
        
        Assertions.notHasEnsuredPredicate(keyParams);
        Assertions.notHasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecGen);
	}
	
	@Test
	public void testECFixedTransformFive() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECFixedTransform ecGen = new ECFixedTransform(n);
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
		ecGen.init(keyParams);
		ecGen.transform(srcPair);
		ecGen.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecGen);
	}
}
