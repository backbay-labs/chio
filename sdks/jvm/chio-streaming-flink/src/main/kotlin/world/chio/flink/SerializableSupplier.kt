/**
 * Serializable zero-arg supplier. Flink serialises operator closures
 * across the JobManager -> TaskManager boundary; plain
 * java.util.function.Supplier is not Serializable. Factories (not
 * instances) are the safe shape for ChioClient / DlqRouter, mirroring
 * Python's client_factory / dlq_router_factory pattern.
 */
package world.chio.flink

import java.io.Serializable
import java.util.function.Supplier

fun interface SerializableSupplier<T> :
    Supplier<T>,
    Serializable
