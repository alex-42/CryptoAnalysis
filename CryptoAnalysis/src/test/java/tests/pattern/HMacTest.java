package tests.pattern;

import java.io.File;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class HMacTest extends UsagePatternTestingFramework {
	
	private String message = "what do ya want for nothing?";
	
	@Override
	protected String getSootClassPath() {
		String sootCp = super.getSootClassPath();
		String dir = System.getProperty("user.dir");
		sootCp += File.pathSeparator + dir + "/src/test/java/tests/jars/bouncy_castle/bcprov-jdk15on-1.60.jar";
		return sootCp; 
	}
	
	@Test
	public void testHMacOne() {
		Digest digest = new SHA256Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacTwo() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.mustNotBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacThree() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		hmac.reset();
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacFour() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacFive() {
		Digest digest = new SHA1Digest();
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.doFinal(resBuf, 0);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacSix() {
		Digest digest = new SHA1Digest();
		HMac hmac = new HMac(digest);
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.reset();
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.mustNotBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacSeven() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		hmac.reset();
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.mustNotBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacEight() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		hmac.reset();
		hmac.init(keyParams);
		hmac.doFinal(resBuf, 0);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
	
	@Test
	public void testHMacNine() {
		Digest digest = new SHA1Digest();
		byte[] m = message.getBytes();		
		HMac hmac = new HMac(digest);
		byte[] resBuf = new byte[hmac.getMacSize()];
		CipherParameters keyParams = new KeyParameter(Hex.decode("sdfdsfsdf"));
		hmac.init(keyParams);
		hmac.update(m, 0, m.length);
		hmac.doFinal(resBuf, 0);
		
		byte[] m2 = "HelloWorld!".getBytes();
		hmac.init(keyParams);
		hmac.update(m2, 0, m2.length);
		hmac.doFinal(resBuf, 0);
		
		Assertions.hasEnsuredPredicate(keyParams);
		Assertions.hasEnsuredPredicate(hmac);
		Assertions.mustBeInAcceptingState(hmac);
	}
}