/**
 * Serializable function one-arg shape. Flink serialises operator
 * closures; plain java.util.function.Function is not Serializable.
 * Same rationale as Python's client_factory pattern.
 */
package world.chio.flink

import java.io.Serializable
import java.util.function.Function

fun interface SerializableFunction<T, R> :
    Function<T, R>,
    Serializable
