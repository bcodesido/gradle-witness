package org.whispersystems.witness

import org.gradle.api.InvalidUserDataException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.create
import java.io.File
import java.security.MessageDigest

open class WitnessPluginExtension {
    var verify: List<String> = listOf()
    var exclude: List<String> = listOf()
}

class WitnessPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create<WitnessPluginExtension>("dependencyVerification")
        project.afterEvaluate {
            validateResolvedDependencies(project, extension)
        }

        project.task("calculateChecksums").doLast {
            println("dependencyVerification {")
            println("    verify = [")

            project.resolvedArtifacts.forEach { dep ->
                println("        '" + dep.moduleVersion.id.group + ":" + dep.name + ":" + calculateSha256(dep.file) + "',")
            }

            println("    ]")
            println("}")
        }
    }

    private fun validateResolvedDependencies(project: Project, extension: WitnessPluginExtension) {
        val resolvedArtifacts = project.resolvedArtifacts
        extension.exclude.forEach { assertion ->
            val (group, name) = assertion.split(":")

            val dependency = resolvedArtifacts.find { it.name == name && it.moduleVersion.id.group == group }
                ?: throw InvalidUserDataException("No dependency for integrity exclusion found: $group:$name")

            println("Skipping verification for $group:$name")

            resolvedArtifacts.remove(dependency)
        }

        extension.verify.forEach { assertion ->
            val (group, name, hash) = assertion.split(":")

            val dependency = resolvedArtifacts.find { it.name == name && it.moduleVersion.id.group == group }
                ?: throw InvalidUserDataException("No dependency for integrity assertion found: $group:$name")

            println("Verifying $group:$name")

            if (hash != calculateSha256(dependency.file)) {
                throw InvalidUserDataException("Checksum failed for $assertion")
            }

            resolvedArtifacts.remove(dependency)
        }

        if (resolvedArtifacts.isNotEmpty()) {
            val errorMessage = resolvedArtifacts.joinToString("\n", "No dependency for integrity assertion found for: \n") {
                "- " + it.moduleVersion.id.group + ":" + it.name
            }
            throw InvalidUserDataException(errorMessage)
        }
    }

    private val Project.resolvedArtifacts
        get() = project.configurations
            .filter { it.isCanBeResolved }
            .flatMap { it.resolvedConfiguration.resolvedArtifacts }
            .toMutableSet()

    private fun calculateSha256(file: File): String {
        val md: MessageDigest = MessageDigest.getInstance("SHA-256")
        file.forEachBlock(4096) { bytes, size ->
            md.update(bytes, 0, size)
        }

        return md.digest().joinToString(separator = "") { String.format("%02x", it) }
    }
}
