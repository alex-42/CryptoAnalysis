package crypto.analysis.errors;

import boomerang.jimple.Statement;
import crypto.rules.CryptSLRule;
import soot.jimple.internal.JAssignStmt;

public abstract class AbstractError implements IError {
	private final Statement errorLocation;
	private final CryptSLRule rule;
	private final String outerMethod;
	private final String invokeMethod;

	public AbstractError(Statement errorLocation, CryptSLRule rule) {
		this.errorLocation = errorLocation;
		this.rule = rule;
		this.outerMethod = errorLocation.getMethod().getSignature();
		
		if(errorLocation.getUnit().get().containsInvokeExpr()) {
			this.invokeMethod = errorLocation.getUnit().get().getInvokeExpr().getMethod().toString();
		}
		else {
			this.invokeMethod = ((JAssignStmt)errorLocation.getUnit().get()).getLeftOp().toString();
		}	
	}

	public Statement getErrorLocation() {
		return errorLocation;
	}

	public CryptSLRule getRule() {
		return rule;
	}

	public abstract String toErrorMarkerString();

	public String toString() {
		return toErrorMarkerString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((invokeMethod == null) ? 0 : invokeMethod.hashCode());
		result = prime * result + ((outerMethod == null) ? 0 : outerMethod.hashCode());
		result = prime * result + ((rule == null) ? 0 : rule.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractError other = (AbstractError) obj;
		if (invokeMethod == null) {
			if (other.invokeMethod != null)
				return false;
		} else if (!invokeMethod.equals(other.invokeMethod))
			return false;
		if (outerMethod == null) {
			if (other.outerMethod != null)
				return false;
		} else if (!outerMethod.equals(other.outerMethod))
			return false;
		if (rule == null) {
			if (other.rule != null)
				return false;
		} else if (!rule.equals(other.rule))
			return false;
		return true;
	}
	
	

	
}
