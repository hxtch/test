package com.pa1m.frameworkbroadcast

import soot.Body
import soot.Local
import soot.Value
import soot.jimple.AssignStmt
import soot.jimple.BinopExpr
import soot.jimple.CastExpr
import soot.jimple.InstanceInvokeExpr
import soot.jimple.IntConstant
import soot.jimple.NewExpr
import soot.jimple.NullConstant
import soot.jimple.SpecialInvokeExpr
import soot.jimple.Stmt
import soot.jimple.StringConstant
import soot.toolkits.graph.ExceptionalUnitGraph
import soot.toolkits.scalar.SimpleLocalDefs
import kotlin.streams.toList

class MethodLocalResolver(private val body: Body) {
    private val units = body.units.toList()
    private val unitIndex = units.withIndex().associate { it.value to it.index }
    private val localDefs = SimpleLocalDefs(ExceptionalUnitGraph(body))

    fun resolveString(value: Value, atStmt: Stmt, seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf()): StringResolution {
        if (!seen.add(value to atStmt)) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        return when (value) {
            is StringConstant -> StringResolution(ResolutionStatus.KNOWN, value.value)
            is NullConstant -> StringResolution(ResolutionStatus.NULL_VALUE, null)
            is Local -> {
                val defs = localDefs.getDefsOfAt(value, atStmt)
                if (defs.isEmpty()) {
                    return StringResolution(ResolutionStatus.UNKNOWN, null)
                }
                val results = defs.mapNotNull { def ->
                    when (def) {
                        is AssignStmt -> resolveString(def.rightOp, def as Stmt, seen)
                        else -> null
                    }
                }
                mergeStringResults(results)
            }
            is CastExpr -> resolveString(value.op, atStmt, seen)
            else -> StringResolution(ResolutionStatus.UNKNOWN, null)
        }
    }

    fun resolveInt(value: Value, atStmt: Stmt, seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf()): IntResolution {
        if (!seen.add(value to atStmt)) {
            return IntResolution(ResolutionStatus.UNKNOWN, null)
        }
        return when (value) {
            is IntConstant -> IntResolution(ResolutionStatus.KNOWN, value.value)
            is NullConstant -> IntResolution(ResolutionStatus.NULL_VALUE, null)
            is Local -> {
                val defs = localDefs.getDefsOfAt(value, atStmt)
                if (defs.isEmpty()) {
                    return IntResolution(ResolutionStatus.UNKNOWN, null)
                }
                val results = defs.mapNotNull { def ->
                    when (def) {
                        is AssignStmt -> resolveInt(def.rightOp, def as Stmt, seen)
                        else -> null
                    }
                }
                mergeIntResults(results)
            }
            is CastExpr -> resolveInt(value.op, atStmt, seen)
            is BinopExpr -> {
                val left = resolveInt(value.op1, atStmt, seen)
                val right = resolveInt(value.op2, atStmt, seen)
                if (left.status != ResolutionStatus.KNOWN || right.status != ResolutionStatus.KNOWN) {
                    IntResolution(ResolutionStatus.UNKNOWN, null)
                } else {
                    val computed = when (value.symbol.trim()) {
                        "|" -> left.value!! or right.value!!
                        "&" -> left.value!! and right.value!!
                        "+" -> left.value!! + right.value!!
                        else -> return IntResolution(ResolutionStatus.UNKNOWN, null)
                    }
                    IntResolution(ResolutionStatus.KNOWN, computed)
                }
            }
            else -> IntResolution(ResolutionStatus.UNKNOWN, null)
        }
    }

    fun resolveActions(value: Value, atStmt: Stmt, seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf()): ActionResolution {
        if (!seen.add(value to atStmt)) {
            return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        }
        return when (value) {
            is Local -> {
                val defs = localDefs.getDefsOfAt(value, atStmt)
                if (defs.isEmpty()) {
                    return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
                }
                val results = defs.map { def ->
                    when (def) {
                        is AssignStmt -> resolveActionsFromDef(value, def, atStmt, seen)
                        else -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
                    }
                }
                mergeActionResults(results)
            }
            is NullConstant -> ActionResolution(ResolutionStatus.NULL_VALUE, emptySet())
            else -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        }
    }

    private fun resolveActionsFromDef(local: Local, defStmt: AssignStmt, atStmt: Stmt, seen: MutableSet<Pair<Value, Stmt>>): ActionResolution {
        val right = defStmt.rightOp
        if (right is Local) {
            return resolveActions(right, defStmt, seen)
        }
        if (right is NullConstant) {
            return ActionResolution(ResolutionStatus.NULL_VALUE, emptySet())
        }
        if (right is NewExpr && right.baseType.toString() == "android.content.IntentFilter") {
            return collectIntentFilterActions(local, defStmt, atStmt)
        }
        return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
    }

    private fun collectIntentFilterActions(local: Local, startStmt: Stmt, endStmt: Stmt): ActionResolution {
        val startIndex = unitIndex[startStmt] ?: return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        val endIndex = unitIndex[endStmt] ?: return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        val actions = linkedSetOf<String>()

        for (index in startIndex + 1 until endIndex) {
            val stmt = units[index] as? Stmt ?: continue
            if (stmt is AssignStmt && stmt.leftOp == local) {
                break
            }
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr
            if (invokeExpr !is InstanceInvokeExpr || invokeExpr.base != local) {
                continue
            }
            val signature = invokeExpr.methodRef.signature
            if (signature == "<android.content.IntentFilter: void addAction(java.lang.String)>") {
                val action = resolveString(invokeExpr.getArg(0), stmt)
                if (action.status == ResolutionStatus.KNOWN && action.value != null) {
                    actions += action.value
                } else {
                    return ActionResolution(ResolutionStatus.UNKNOWN, actions)
                }
            } else if (invokeExpr is SpecialInvokeExpr && invokeExpr.methodRef.name() == "<init>") {
                if (invokeExpr.argCount == 1 && invokeExpr.getArg(0).type.toString() == "java.lang.String") {
                    val action = resolveString(invokeExpr.getArg(0), stmt)
                    if (action.status == ResolutionStatus.KNOWN && action.value != null) {
                        actions += action.value
                    } else {
                        return ActionResolution(ResolutionStatus.UNKNOWN, actions)
                    }
                }
            }
        }

        return if (actions.isEmpty()) {
            ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        } else {
            ActionResolution(ResolutionStatus.KNOWN, actions)
        }
    }

    private fun mergeStringResults(results: List<StringResolution>): StringResolution {
        if (results.isEmpty()) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        val knownValues = results.filter { it.status == ResolutionStatus.KNOWN }.mapNotNull { it.value }.toSet()
        return when {
            knownValues.size == 1 && results.all { it.status == ResolutionStatus.KNOWN } ->
                StringResolution(ResolutionStatus.KNOWN, knownValues.first())
            results.all { it.status == ResolutionStatus.NULL_VALUE } ->
                StringResolution(ResolutionStatus.NULL_VALUE, null)
            else -> StringResolution(ResolutionStatus.UNKNOWN, null)
        }
    }

    private fun mergeIntResults(results: List<IntResolution>): IntResolution {
        if (results.isEmpty()) {
            return IntResolution(ResolutionStatus.UNKNOWN, null)
        }
        val knownValues = results.filter { it.status == ResolutionStatus.KNOWN }.mapNotNull { it.value }.toSet()
        return when {
            knownValues.size == 1 && results.all { it.status == ResolutionStatus.KNOWN } ->
                IntResolution(ResolutionStatus.KNOWN, knownValues.first())
            results.all { it.status == ResolutionStatus.NULL_VALUE } ->
                IntResolution(ResolutionStatus.NULL_VALUE, null)
            else -> IntResolution(ResolutionStatus.UNKNOWN, null)
        }
    }

    private fun mergeActionResults(results: List<ActionResolution>): ActionResolution {
        if (results.isEmpty()) {
            return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        }
        val statuses = results.map { it.status }.toSet()
        val actions = linkedSetOf<String>()
        results.forEach { actions += it.actions }
        return when {
            statuses == setOf(ResolutionStatus.NULL_VALUE) -> ActionResolution(ResolutionStatus.NULL_VALUE, emptySet())
            statuses == setOf(ResolutionStatus.KNOWN) && actions.isNotEmpty() -> ActionResolution(ResolutionStatus.KNOWN, actions)
            actions.isNotEmpty() -> ActionResolution(ResolutionStatus.UNKNOWN, actions)
            else -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        }
    }
}
