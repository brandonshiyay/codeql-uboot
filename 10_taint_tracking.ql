import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(
            MacroInvocation mi | 
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        )
    }
}


class Config extends TaintTracking::Configuration {
    Config() {
        this = "whatever"
    }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(
            FunctionCall c | c.getTarget().getName() = "memcpy" and
            sink.asExpr() = c.getArgument(2)
        )
    }
}

from Config c, DataFlow::PathNode source, DataFlow::PathNode sink
where c.hasFlowPath(source, sink) 
select sink, source, sink, "what"