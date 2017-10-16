package crypto.analysis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Multimap;
import com.google.common.collect.Table;

import boomerang.accessgraph.AccessGraph;
import boomerang.util.StmtWithMethod;
import crypto.rules.CryptSLPredicate;
import crypto.rules.StateNode;
import crypto.typestate.CallSiteWithParamIndex;
import crypto.typestate.CryptoTypestateAnaylsisProblem.AdditionalBoomerangQuery;
import ideal.AnalysisSolver;
import ideal.IFactAtStatement;
import soot.Unit;
import typestate.TypestateDomainValue;
import typestate.interfaces.ISLConstraint;

public class CrySLResultsReporter  {

	private List<CrySLAnalysisListener> listeners;

	public CrySLResultsReporter() {
		listeners = new ArrayList<CrySLAnalysisListener>();
	}

	public boolean addReportListener(CrySLAnalysisListener listener) {
		return listeners.add(listener);
	}

	public boolean removeReportListener(CrySLAnalysisListener listener) {
		return listeners.remove(listener);
	}

	public void collectedValues(AnalysisSeedWithSpecification seed, Multimap<CallSiteWithParamIndex, Unit> collectedValues) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.collectedValues(seed, collectedValues);
		}
	}

	public void callToForbiddenMethod(ClassSpecification classSpecification, StmtWithMethod callSite) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.callToForbiddenMethod(classSpecification, callSite);
		}
	}

	public void discoveredSeed(IAnalysisSeed curr) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.discoveredSeed(curr);
		}
	}

	public void ensuredPredicates(Table<Unit, AccessGraph, Set<EnsuredCryptSLPredicate>> existingPredicates, Table<Unit, IAnalysisSeed, Set<CryptSLPredicate>> expectedPredicates, Table<Unit, IAnalysisSeed, Set<CryptSLPredicate>> missingPredicates) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.ensuredPredicates(existingPredicates, expectedPredicates, missingPredicates);
		}
	}

	public void predicateContradiction(StmtWithMethod stmt, AccessGraph key, Entry<CryptSLPredicate, CryptSLPredicate> disPair) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.predicateContradiction(stmt, key, disPair);
		}
	}

	public void missingPredicates(AnalysisSeedWithSpecification seed, Set<CryptSLPredicate> missingPredicates) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.missingPredicates(seed, missingPredicates);
		}
	}

	public void constraintViolation(AnalysisSeedWithSpecification analysisSeedWithSpecification, ISLConstraint con, StmtWithMethod unit) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.constraintViolation(analysisSeedWithSpecification, con, unit);
		}
	}

	public void checkedConstraints(AnalysisSeedWithSpecification analysisSeedWithSpecification, Collection<ISLConstraint> relConstraints) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.checkedConstraints(analysisSeedWithSpecification, relConstraints);
		}
	}

	public void beforeAnalysis() {
		for (CrySLAnalysisListener listen : listeners) {
			listen.beforeAnalysis();
		}
	}

	public void afterAnalysis() {
		for (CrySLAnalysisListener listen : listeners) {
			listen.afterAnalysis();
		}
	}

	public void beforeConstraintCheck(AnalysisSeedWithSpecification analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.beforeConstraintCheck(analysisSeedWithSpecification);
		}
	}

	public void afterConstraintCheck(AnalysisSeedWithSpecification analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.afterConstraintCheck(analysisSeedWithSpecification);
		}
	}

	public void beforePredicateCheck(AnalysisSeedWithSpecification analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.beforePredicateCheck(analysisSeedWithSpecification);
		}
	}

	public void afterPredicateCheck(AnalysisSeedWithSpecification analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.afterPredicateCheck(analysisSeedWithSpecification);
		}
	}

	public void seedFinished(IAnalysisSeed analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.seedFinished(analysisSeedWithSpecification);
		}
	}

	public void seedStarted(IAnalysisSeed analysisSeedWithSpecification) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.seedStarted(analysisSeedWithSpecification);
		}
	}

	public void boomerangQueryStarted(IFactAtStatement seed, AdditionalBoomerangQuery q) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.boomerangQueryStarted(seed, q);
		}
	}

	public void boomerangQueryFinished(IFactAtStatement seed, AdditionalBoomerangQuery q) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.boomerangQueryFinished(seed, q);
		}
	}	
	
	public void onSeedFinished(IFactAtStatement seed, AnalysisSolver<TypestateDomainValue<StateNode>> solver) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.onSeedFinished(seed, solver);
		}
	}
	
	public void onSeedTimeout(IFactAtStatement seed) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.onSeedTimeout(seed);
		}
	}
	
	public void typestateErrorAt(AnalysisSeedWithSpecification classSpecification, StmtWithMethod stmt) {
		for (CrySLAnalysisListener listen : listeners) {
			listen.typestateErrorAt(classSpecification, stmt);
			
		}
	}
	
}
