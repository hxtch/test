package com.pa1m.frameworkbroadcast

import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.nio.file.Files
import java.nio.file.Path

object WorkerProtocol {
    fun writeResult(path: Path, result: JarScanResult) {
        Files.createDirectories(path.parent)
        ObjectOutputStream(Files.newOutputStream(path)).use { output ->
            output.writeObject(result)
        }
    }

    fun readResult(path: Path): JarScanResult {
        ObjectInputStream(Files.newInputStream(path)).use { input ->
            return input.readObject() as JarScanResult
        }
    }
}
