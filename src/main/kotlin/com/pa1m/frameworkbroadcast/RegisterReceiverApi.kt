package com.pa1m.frameworkbroadcast

import soot.SootMethodRef

object RegisterReceiverApi {
    private val allowedOwners = setOf(
        "android.content.Context",
        "android.content.ContextWrapper",
        "android.app.ContextImpl",
    )

    private val allowedNames = setOf(
        "registerReceiver",
        "registerReceiverAsUser",
        "registerReceiverForAllUsers",
        "registerReceiverInternal",
    )

    private const val RECEIVER_TYPE = "android.content.BroadcastReceiver"
    private const val FILTER_TYPE = "android.content.IntentFilter"
    fun matches(methodRef: SootMethodRef): Boolean {
        if (methodRef.name() !in allowedNames) {
            return false
        }
        if (methodRef.declaringClass().name !in allowedOwners) {
            return false
        }
        val parameterTypes = methodRef.parameterTypes().map { it.toString() }
        return parameterTypes.any { it == RECEIVER_TYPE } && parameterTypes.any { it == FILTER_TYPE }
    }

    fun receiverIndex(methodRef: SootMethodRef): Int? =
        methodRef.parameterTypes().indexOfFirst { it.toString() == RECEIVER_TYPE }.takeIf { it >= 0 }

    fun filterIndex(methodRef: SootMethodRef): Int? =
        methodRef.parameterTypes().indexOfFirst { it.toString() == FILTER_TYPE }.takeIf { it >= 0 }

    fun permissionIndex(methodRef: SootMethodRef): Int? {
        val filterIndex = filterIndex(methodRef) ?: return null
        val params = methodRef.parameterTypes()
        for (index in filterIndex + 1 until params.size) {
            if (params[index].toString() == "java.lang.String") {
                return index
            }
        }
        return null
    }

    fun flagsIndex(methodRef: SootMethodRef): Int? {
        val params = methodRef.parameterTypes()
        if (methodRef.name() == "registerReceiver" && params.size >= 5 && params.last().toString() == "int") {
            return params.lastIndex
        }
        if (methodRef.name() == "registerReceiverAsUser" && params.isNotEmpty() && params.last().toString() == "int") {
            return params.lastIndex
        }
        if (methodRef.name() == "registerReceiverForAllUsers" && params.isNotEmpty() && params.last().toString() == "int") {
            return params.lastIndex
        }
        if (methodRef.name() == "registerReceiverInternal" && params.isNotEmpty() && params.last().toString() == "int") {
            return params.lastIndex
        }
        return null
    }
}
