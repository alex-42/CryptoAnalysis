package tests.pattern;

import java.io.File;
import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class ECKeyPairGeneratorTest extends UsagePatternTestingFramework {
	
	@Override
	protected String getSootClassPath() {
		String sootCp = super.getSootClassPath();
		String dir = System.getProperty("user.dir");
		sootCp += File.pathSeparator + dir + "/src/test/java/tests/jars/bouncy_castle/bcprov-jdk15on-1.60.jar";
		return sootCp; 
	}
	
	@Test
	public void testECKeyPairGeneratorTestOne() {
		ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
		SecureRandom random = new SecureRandom();
		KeyGenerationParameters keyParams = new KeyGenerationParameters(random, 10);
		ecGen.init(keyParams);
		ecGen.generateKeyPair();
		
		Assertions.hasEnsuredPredicate(random);
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.mustBeInAcceptingState(ecGen);
	}
	
	@Test
	public void testECKeyPairGeneratorTestTwo() {
		ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
		SecureRandom random = new SecureRandom();
		KeyGenerationParameters keyParams = new KeyGenerationParameters(random, 10);
		ecGen.init(keyParams);
		ecGen.generateKeyPair();
		ecGen.generateKeyPair();
		
		Assertions.hasEnsuredPredicate(random);
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.mustNotBeInAcceptingState(ecGen);
	}
}
