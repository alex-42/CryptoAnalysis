package test;

import java.io.File;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;

import crypto.analysis.ClassSpecification;
import crypto.analysis.CrypSLAnalysisDebugger;
import crypto.analysis.CryptoScanner;
import crypto.analysis.ErrorReporter;
import crypto.rules.CryptSLRule;
import crypto.rules.CryptSLRuleReader;
import crypto.rules.StateNode;
import crypto.statemachine.CallSiteWithParamIndex;
import soot.Body;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import test.core.selfrunning.AbstractTestingFramework;
import test.core.selfrunning.ImprecisionException;
import typestate.tests.crypto.Benchmark;

public abstract class UsagePatternTestingFramework extends AbstractTestingFramework{

	protected InfoflowCFG icfg;

	@Override
	protected SceneTransformer createAnalysisTransformer() throws ImprecisionException {
		return new SceneTransformer() {
			protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {
				icfg = new InfoflowCFG(new JimpleBasedInterproceduralCFG(true));
				final Set<Assertion> expectedResults = extractBenchmarkMethods(sootTestMethod);
//				testingResultReporter = new TestingResultReporter<StateNode>(expectedResults);
				CryptoScanner scanner = new CryptoScanner(getRules()) {
					
					@Override
					public IInfoflowCFG icfg() {
						return icfg;
					}

					@Override
					public ErrorReporter errorReporter() {
						// TODO Auto-generated method stub
						return new ErrorReporter(){

							@Override
							public void report(ClassSpecification spec, Unit stmt, Violation details) {
								System.err.println("Class Specification " + spec +" reporter Error at \n\t" + stmt);
							}
							
						};
					}

					@Override
					public CrypSLAnalysisDebugger debugger() {
						return new CrypSLAnalysisDebugger() {
							
							@Override
							public void collectedValues(ClassSpecification classSpecification,
									Multimap<CallSiteWithParamIndex, Value> collectedValues) {
								for(Assertion a: expectedResults){
									if(a instanceof ExtractedValueAssertion){
										((ExtractedValueAssertion) a).computedValues(collectedValues);
									}
								}
							}
						};
					}
				};
				scanner.scan();
				List<Assertion> unsound = Lists.newLinkedList();
				List<Assertion> imprecise = Lists.newLinkedList();
				for (Assertion r : expectedResults) {
					if (!r.isSatisfied()) {
						unsound.add(r);
					}
				}
				for (Assertion r : expectedResults) {
					if (r.isImprecise()) {
						imprecise.add(r);
					}
				}
				if (!unsound.isEmpty())
					throw new RuntimeException("Unsound results: \n" + Joiner.on("\n").join(unsound));
				if (!imprecise.isEmpty()) {
					throw new ImprecisionException("Imprecise results: " + Joiner.on("\n").join(imprecise));
				}
			}

		};
	}
	protected List<CryptSLRule> getRules() {
		LinkedList<CryptSLRule> rules = Lists.newLinkedList();        
//		rules.add(CryptSLRuleReader.readFromFile(new File(IDEALCrossingTestingFramework.RESOURCE_PATH + "Cipher.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(IDEALCrossingTestingFramework.RESOURCE_PATH + "KeyGenerator.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(IDEALCrossingTestingFramework.RESOURCE_PATH + "KeyPairGenerator.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(IDEALCrossingTestingFramework.RESOURCE_PATH + "MessageDigest.cryptslbin")));
		rules.add(CryptSLRuleReader.readFromFile(new File(IDEALCrossingTestingFramework.RESOURCE_PATH + "PBEKeySpec.cryptslbin")));
		return rules;
	}
	private Set<Assertion> extractBenchmarkMethods(SootMethod sootTestMethod) {
		Set<Assertion> results = new HashSet<>();
		extractBenchmarkMethods(sootTestMethod, results, new HashSet<SootMethod>());
		return results;
	}

	private void extractBenchmarkMethods(SootMethod m, Set<Assertion> queries, Set<SootMethod> visited) {
		if (!m.hasActiveBody() || visited.contains(m))
			return;
		visited.add(m);
		Body activeBody = m.getActiveBody();
		for (Unit callSite : icfg.getCallsFromWithin(m)) {
			for (SootMethod callee : icfg.getCalleesOfCallAt(callSite))
				extractBenchmarkMethods(callee, queries, visited);
		}
		for (Unit u : activeBody.getUnits()) {
			if (!(u instanceof Stmt))
				continue;

			Stmt stmt = (Stmt) u;
			if (!(stmt.containsInvokeExpr()))
				continue;
			InvokeExpr invokeExpr = stmt.getInvokeExpr();
			if (!invokeExpr.getMethod().getDeclaringClass().toString().equals(Benchmark.class.getName()))
				continue;
			String invocationName = invokeExpr.getMethod().getName();
			if(invocationName.startsWith("extValue")){
				Value param = invokeExpr.getArg(0);
				if (!(param instanceof IntConstant))
					continue;
				IntConstant paramIndex = (IntConstant) param;
				for(Unit pred : icfg.getPredsOf(stmt))
					queries.add(new ExtractedValueAssertion(pred, paramIndex.value));
			}
		}
	}
}
