package tests.pattern;

import java.io.File;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ec.ECNewRandomnessTransform;
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

public class ECNewRandomnessTransformTest extends UsagePatternTestingFramework {
	
	BigInteger n = new BigInteger("627710173538");
	
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
	public void testECNewRandomnessTransformOne() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECNewRandomnessTransform ecr = new ECNewRandomnessTransform();
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
        ecr.init(keyParams);
        ecr.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecr);
	}
	
	@Test
	public void testECNewRandomnessTransformTwo() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECNewRandomnessTransform ecr = new ECNewRandomnessTransform();
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
        ecr.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustNotBeInAcceptingState(ecr);
	}
	
	@Test
	public void testECNewRandomnessTransformThree() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECNewRandomnessTransform ecr = new ECNewRandomnessTransform();
		ECPair srcPair = null;
        ecr.init(keyParams);
        ecr.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.notHasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecr);
	}
	
	@Test
	public void testECNewRandomnessTransformFour() {
		CipherParameters keyParams = null;
		ECNewRandomnessTransform ecr = new ECNewRandomnessTransform();
		ECPair srcPair = null;
        ecr.init(keyParams);
        ecr.transform(srcPair);
        
        Assertions.notHasEnsuredPredicate(keyParams);
        Assertions.notHasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecr);
	}
	
	@Test
	public void testECNewRandomnessTransformFive() {
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		ECNewRandomnessTransform ecr = new ECNewRandomnessTransform();
		ECPoint data = priKey.getParameters().getG().multiply(n);
		ECPair srcPair = new ECPair(data, data);
        ecr.init(keyParams);
        ecr.transform(srcPair);
        ecr.transform(srcPair);
        
        Assertions.hasEnsuredPredicate(keyParams);
        Assertions.hasEnsuredPredicate(srcPair);
        Assertions.mustBeInAcceptingState(ecr);
	}
}
