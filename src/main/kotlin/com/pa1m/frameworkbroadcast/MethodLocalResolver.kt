package com.pa1m.frameworkbroadcast

import soot.Body
import soot.Local
import soot.SootField
import soot.SootMethod
import soot.Value
import soot.jimple.AssignStmt
import soot.jimple.BinopExpr
import soot.jimple.CastExpr
import soot.jimple.FieldRef
import soot.jimple.InstanceFieldRef
import soot.jimple.InstanceInvokeExpr
import soot.jimple.IntConstant
import soot.jimple.InvokeExpr
import soot.jimple.NewExpr
import soot.jimple.NullConstant
import soot.jimple.ReturnStmt
import soot.jimple.SpecialInvokeExpr
import soot.jimple.StaticFieldRef
import soot.jimple.StaticInvokeExpr
import soot.jimple.Stmt
import soot.jimple.StringConstant
import soot.tagkit.IntegerConstantValueTag
import soot.tagkit.StringConstantValueTag
import soot.toolkits.graph.ExceptionalUnitGraph
import soot.toolkits.scalar.SimpleLocalDefs
import kotlin.math.min
import kotlin.streams.toList

class MethodLocalResolver(
    private val body: Body,
    private val stringSummaryCache: MutableMap<SootMethod, StringResolution> = mutableMapOf(),
) {
    private val units = body.units.toList()
    private val unitIndex = units.withIndex().associate { it.value to it.index }
    private val localDefs = SimpleLocalDefs(ExceptionalUnitGraph(body))

    fun resolveString(
        value: Value,
        atStmt: Stmt,
        seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf(),
        methodDepth: Int = 0,
    ): StringResolution {
        if (!seen.add(value to atStmt)) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        return when (value) {
            is StringConstant -> StringResolution(ResolutionStatus.KNOWN, value.value)
            is NullConstant -> StringResolution(ResolutionStatus.NULL_VALUE, null)
            is FieldRef -> resolveStringField(value, atStmt, methodDepth)
            is Local -> {
                val defs = localDefs.getDefsOfAt(value, atStmt)
                if (defs.isEmpty()) {
                    return StringResolution(ResolutionStatus.UNKNOWN, null)
                }
                val results = defs.mapNotNull { def ->
                    when (def) {
                        is AssignStmt -> resolveString(def.rightOp, def as Stmt, seen, methodDepth)
                        else -> null
                    }
                }
                mergeStringResults(results)
            }
            is CastExpr -> resolveString(value.op, atStmt, seen, methodDepth)
            is InvokeExpr -> resolveStringInvoke(value, seen, methodDepth)
            else -> StringResolution(ResolutionStatus.UNKNOWN, null)
        }
    }

    fun resolveInt(
        value: Value,
        atStmt: Stmt,
        seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf(),
    ): IntResolution {
        if (!seen.add(value to atStmt)) {
            return IntResolution(ResolutionStatus.UNKNOWN, null)
        }
        return when (value) {
            is IntConstant -> IntResolution(ResolutionStatus.KNOWN, value.value)
            is NullConstant -> IntResolution(ResolutionStatus.NULL_VALUE, null)
            is FieldRef -> resolveIntField(value, atStmt)
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

    fun resolveActions(
        value: Value,
        atStmt: Stmt,
        seen: MutableSet<Pair<Value, Stmt>> = mutableSetOf(),
    ): ActionResolution {
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
            is InstanceFieldRef -> {
                if (isThisFieldRef(value)) {
                    collectIntentFilterActions(
                        trackedAliases = linkedSetOf(),
                        trackedField = value.fieldRef.resolve(),
                        startIndex = 0,
                        endStmt = atStmt,
                    )
                } else {
                    ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
                }
            }
            is NullConstant -> ActionResolution(ResolutionStatus.NULL_VALUE, emptySet())
            else -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        }
    }

    private fun resolveStringInvoke(
        invokeExpr: InvokeExpr,
        seen: MutableSet<Pair<Value, Stmt>>,
        methodDepth: Int,
    ): StringResolution {
        if (methodDepth >= MAX_STRING_METHOD_DEPTH) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        if (invokeExpr.argCount != 0 || invokeExpr.methodRef.returnType.toString() != "java.lang.String") {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        val method = try {
            invokeExpr.methodRef.resolve()
        } catch (_: Exception) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        return resolveStringMethodSummary(method, seen, methodDepth + 1)
    }

    private fun resolveStringMethodSummary(
        method: SootMethod,
        seen: MutableSet<Pair<Value, Stmt>>,
        methodDepth: Int,
    ): StringResolution {
        stringSummaryCache[method]?.let { return it }
        if (!method.isConcrete) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        val methodBody = try {
            method.retrieveActiveBody()
        } catch (_: Exception) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        if (methodBody.units.size > MAX_SUMMARY_UNITS) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }

        val resolver = MethodLocalResolver(methodBody, stringSummaryCache)
        val returnStatements = methodBody.units.asSequence()
            .mapNotNull { it as? ReturnStmt }
            .toList()
        if (returnStatements.isEmpty()) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        val result = mergeStringResults(
            returnStatements.map { returnStmt ->
                resolver.resolveString(returnStmt.op, returnStmt, seen.toMutableSet(), methodDepth)
            }
        )
        stringSummaryCache[method] = result
        return result
    }

    private fun resolveActionsFromDef(
        local: Local,
        defStmt: AssignStmt,
        atStmt: Stmt,
        seen: MutableSet<Pair<Value, Stmt>>,
    ): ActionResolution {
        val right = defStmt.rightOp
        if (right is Local) {
            return resolveActions(right, atStmt, seen)
        }
        if (right is CastExpr && right.op is Local) {
            return resolveActions(right.op, atStmt, seen)
        }
        if (right is NullConstant) {
            return ActionResolution(ResolutionStatus.NULL_VALUE, emptySet())
        }
        if (right is InstanceFieldRef && isThisFieldRef(right)) {
            return collectIntentFilterActions(
                trackedAliases = linkedSetOf(local),
                trackedField = right.fieldRef.resolve(),
                startIndex = 0,
                endStmt = atStmt,
            )
        }
        if (right is NewExpr && right.baseType.toString() == "android.content.IntentFilter") {
            return collectIntentFilterActions(
                trackedAliases = linkedSetOf(local),
                trackedField = null,
                startIndex = unitIndex[defStmt] ?: 0,
                endStmt = atStmt,
            )
        }
        return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
    }

    private fun collectIntentFilterActions(
        trackedAliases: LinkedHashSet<Local>,
        trackedField: SootField?,
        startIndex: Int,
        endStmt: Stmt,
    ): ActionResolution {
        val endIndex = unitIndex[endStmt] ?: return ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
        val actions = linkedSetOf<String>()
        var unknownEncountered = false

        for (index in min(startIndex, endIndex)..endIndex) {
            val stmt = units[index] as? Stmt ?: continue
            if (stmt is AssignStmt) {
                updateAliases(stmt, trackedAliases, trackedField)
            }
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr
            if (invokeExpr !is InstanceInvokeExpr) {
                continue
            }
            if (!matchesTrackedBase(invokeExpr.base, trackedAliases, trackedField)) {
                continue
            }
            val signature = invokeExpr.methodRef.signature
            if (signature == INTENT_FILTER_ADD_ACTION_SIGNATURE) {
                val action = resolveString(invokeExpr.getArg(0), stmt)
                if (action.status == ResolutionStatus.KNOWN && action.value != null) {
                    actions += action.value
                } else {
                    unknownEncountered = true
                }
            } else if (invokeExpr is SpecialInvokeExpr && invokeExpr.methodRef.name == "<init>") {
                if (invokeExpr.argCount == 1 && invokeExpr.getArg(0).type.toString() == "java.lang.String") {
                    val action = resolveString(invokeExpr.getArg(0), stmt)
                    if (action.status == ResolutionStatus.KNOWN && action.value != null) {
                        actions += action.value
                    } else {
                        unknownEncountered = true
                    }
                }
            }
        }

        return when {
            actions.isEmpty() && unknownEncountered -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
            actions.isEmpty() -> ActionResolution(ResolutionStatus.UNKNOWN, emptySet())
            unknownEncountered -> ActionResolution(ResolutionStatus.UNKNOWN, actions)
            else -> ActionResolution(ResolutionStatus.KNOWN, actions)
        }
    }

    private fun updateAliases(stmt: AssignStmt, aliases: MutableSet<Local>, trackedField: SootField?) {
        val leftLocal = stmt.leftOp as? Local
        val rightLocal = extractLocal(stmt.rightOp)
        if (leftLocal != null && rightLocal != null && rightLocal in aliases) {
            aliases += leftLocal
            return
        }
        if (leftLocal != null && trackedField != null && matchesTrackedField(stmt.rightOp, trackedField)) {
            aliases += leftLocal
            return
        }
        if (leftLocal != null && leftLocal in aliases && rightLocal != null && rightLocal !in aliases) {
            aliases -= leftLocal
        }
    }

    private fun matchesTrackedBase(base: Value, aliases: Set<Local>, trackedField: SootField?): Boolean {
        val baseLocal = base as? Local
        if (baseLocal != null && baseLocal in aliases) {
            return true
        }
        return trackedField != null && matchesTrackedField(base, trackedField)
    }

    private fun matchesTrackedField(value: Value, trackedField: SootField): Boolean {
        val fieldRef = value as? InstanceFieldRef ?: return false
        return fieldRef.fieldRef.resolve() == trackedField && isThisFieldRef(fieldRef)
    }

    private fun extractLocal(value: Value): Local? {
        return when (value) {
            is Local -> value
            is CastExpr -> value.op as? Local
            else -> null
        }
    }

    private fun resolveStringField(
        value: FieldRef,
        atStmt: Stmt,
        methodDepth: Int,
    ): StringResolution {
        val field = try {
            value.fieldRef.resolve()
        } catch (_: Exception) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        extractStaticStringConstant(field)?.let {
            return StringResolution(ResolutionStatus.KNOWN, it)
        }
        if (value is InstanceFieldRef && field.type.toString() == "java.lang.String") {
            return resolveInstanceStringField(value, field, atStmt, methodDepth)
        }
        return StringResolution(ResolutionStatus.UNKNOWN, null)
    }

    private fun resolveIntField(
        value: FieldRef,
        atStmt: Stmt,
    ): IntResolution {
        val field = try {
            value.fieldRef.resolve()
        } catch (_: Exception) {
            return IntResolution(ResolutionStatus.UNKNOWN, null)
        }
        extractStaticIntConstant(field)?.let {
            return IntResolution(ResolutionStatus.KNOWN, it)
        }
        if (value is InstanceFieldRef && field.type.toString() == "int") {
            return resolveInstanceIntField(value, field, atStmt)
        }
        return IntResolution(ResolutionStatus.UNKNOWN, null)
    }

    private fun resolveInstanceStringField(
        value: InstanceFieldRef,
        field: SootField,
        atStmt: Stmt,
        methodDepth: Int,
    ): StringResolution {
        if (!field.isFinal) {
            return StringResolution(ResolutionStatus.UNKNOWN, null)
        }
        val constructorResults = resolveConstructedFieldValues(value, field, atStmt) { ctorResolver, assignStmt ->
            ctorResolver.resolveString(assignStmt.rightOp, assignStmt, mutableSetOf(), methodDepth)
        }
        return mergeStringResults(constructorResults)
    }

    private fun resolveInstanceIntField(
        value: InstanceFieldRef,
        field: SootField,
        atStmt: Stmt,
    ): IntResolution {
        if (!field.isFinal) {
            return IntResolution(ResolutionStatus.UNKNOWN, null)
        }
        val constructorResults = resolveConstructedFieldValues(value, field, atStmt) { ctorResolver, assignStmt ->
            ctorResolver.resolveInt(assignStmt.rightOp, assignStmt, mutableSetOf())
        }
        return mergeIntResults(constructorResults)
    }

    private fun <T> resolveConstructedFieldValues(
        value: InstanceFieldRef,
        field: SootField,
        atStmt: Stmt,
        resolver: (MethodLocalResolver, AssignStmt) -> T,
    ): List<T> {
        val constructors = resolveRelevantConstructors(value.base as? Local, atStmt, field.declaringClass)
        if (constructors.isEmpty()) {
            return emptyList()
        }
        return constructors.mapNotNull { constructor ->
            val ctorBody = try {
                constructor.retrieveActiveBody()
            } catch (_: Exception) {
                return@mapNotNull null
            }
            val ctorResolver = MethodLocalResolver(ctorBody, stringSummaryCache)
            val assigns = ctorBody.units.asSequence()
                .mapNotNull { it as? AssignStmt }
                .filter { assignStmt ->
                    val left = assignStmt.leftOp as? InstanceFieldRef ?: return@filter false
                    left.fieldRef.resolve() == field && isThisFieldRef(left, ctorBody)
                }
                .toList()
            if (assigns.size != 1) {
                null
            } else {
                resolver(ctorResolver, assigns.single())
            }
        }
    }

    private fun resolveRelevantConstructors(baseLocal: Local?, atStmt: Stmt, declaringClass: soot.SootClass): List<SootMethod> {
        if (baseLocal == null) {
            return emptyList()
        }
        if (baseLocal == body.thisLocal) {
            return declaringClass.methods.filter { it.isConstructor }
        }
        val defs = localDefs.getDefsOfAt(baseLocal, atStmt)
        return defs.mapNotNull { def ->
            val assignStmt = def as? AssignStmt ?: return@mapNotNull null
            val right = assignStmt.rightOp as? NewExpr ?: return@mapNotNull null
            if (right.baseType.toString() != declaringClass.name) {
                return@mapNotNull null
            }
            findConstructorInvocation(baseLocal, assignStmt, atStmt)
        }.distinct()
    }

    private fun findConstructorInvocation(baseLocal: Local, assignStmt: AssignStmt, atStmt: Stmt): SootMethod? {
        val startIndex = unitIndex[assignStmt] ?: return null
        val endIndex = unitIndex[atStmt] ?: return null
        for (index in startIndex..endIndex) {
            val stmt = units[index] as? Stmt ?: continue
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr as? SpecialInvokeExpr ?: continue
            val invokeBase = invokeExpr.base as? Local ?: continue
            if (invokeBase == baseLocal && invokeExpr.methodRef.name == "<init>") {
                return try {
                    invokeExpr.methodRef.resolve()
                } catch (_: Exception) {
                    null
                }
            }
        }
        return null
    }

    private fun extractStaticStringConstant(field: SootField): String? {
        if (!field.isStatic || !field.isFinal) {
            return null
        }
        val tag = field.tags.firstOrNull { it is StringConstantValueTag } as? StringConstantValueTag
        return tag?.stringValue
    }

    private fun extractStaticIntConstant(field: SootField): Int? {
        if (!field.isStatic || !field.isFinal) {
            return null
        }
        val tag = field.tags.firstOrNull { it is IntegerConstantValueTag } as? IntegerConstantValueTag
        return tag?.intValue
    }

    private fun isThisFieldRef(fieldRef: InstanceFieldRef, targetBody: Body = body): Boolean {
        val baseLocal = fieldRef.base as? Local ?: return false
        return baseLocal == targetBody.thisLocal
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

    companion object {
        private const val MAX_STRING_METHOD_DEPTH = 2
        private const val MAX_SUMMARY_UNITS = 24
        private const val INTENT_FILTER_ADD_ACTION_SIGNATURE =
            "<android.content.IntentFilter: void addAction(java.lang.String)>"
    }
}
