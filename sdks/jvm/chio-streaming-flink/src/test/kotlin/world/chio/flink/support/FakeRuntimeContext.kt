package world.chio.flink.support

import org.apache.flink.api.common.JobInfo
import org.apache.flink.api.common.TaskInfo
import org.apache.flink.api.common.accumulators.Accumulator
import org.apache.flink.api.common.accumulators.DoubleCounter
import org.apache.flink.api.common.accumulators.Histogram
import org.apache.flink.api.common.accumulators.IntCounter
import org.apache.flink.api.common.accumulators.LongCounter
import org.apache.flink.api.common.cache.DistributedCache
import org.apache.flink.api.common.externalresource.ExternalResourceInfo
import org.apache.flink.api.common.functions.BroadcastVariableInitializer
import org.apache.flink.api.common.functions.RuntimeContext
import org.apache.flink.api.common.state.AggregatingState
import org.apache.flink.api.common.state.AggregatingStateDescriptor
import org.apache.flink.api.common.state.ListState
import org.apache.flink.api.common.state.ListStateDescriptor
import org.apache.flink.api.common.state.MapState
import org.apache.flink.api.common.state.MapStateDescriptor
import org.apache.flink.api.common.state.ReducingState
import org.apache.flink.api.common.state.ReducingStateDescriptor
import org.apache.flink.api.common.state.ValueState
import org.apache.flink.api.common.state.ValueStateDescriptor
import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.common.typeutils.TypeSerializer
import org.apache.flink.metrics.Counter
import org.apache.flink.metrics.Gauge
import org.apache.flink.metrics.Meter
import org.apache.flink.metrics.MetricGroup
import org.apache.flink.metrics.SimpleCounter
import org.apache.flink.metrics.groups.OperatorMetricGroup
import java.util.concurrent.ConcurrentHashMap
import org.apache.flink.metrics.Histogram as FlinkHistogram

/**
 * Minimal RuntimeContext for operator unit tests. Exposes subtask /
 * attempt numbers, a fake metric group that records counters and
 * gauges, and returns empty/unsupported for every state-handling
 * method we do not need.
 *
 * Stubs UnsupportedOperationException for features the evaluator
 * never touches so the test fails loudly if we start relying on one.
 */
class FakeRuntimeContext(
    private val subtaskIndex: Int = 0,
    private val subtaskCount: Int = 1,
    private val attempt: Int = 0,
) : RuntimeContext {
    val metrics: FakeMetricGroup = FakeMetricGroup("")

    override fun getMetricGroup(): OperatorMetricGroup = metrics

    override fun getTaskInfo(): TaskInfo =
        object : TaskInfo {
            override fun getTaskName(): String = "fake"

            override fun getMaxNumberOfParallelSubtasks(): Int = subtaskCount

            override fun getIndexOfThisSubtask(): Int = subtaskIndex

            override fun getNumberOfParallelSubtasks(): Int = subtaskCount

            override fun getAttemptNumber(): Int = attempt

            override fun getTaskNameWithSubtasks(): String = "fake (1/1)#0"

            override fun getAllocationIDAsString(): String = "fake-alloc"
        }

    override fun getJobInfo(): JobInfo =
        object : JobInfo {
            override fun getJobId(): org.apache.flink.api.common.JobID =
                org.apache.flink.api.common
                    .JobID()

            override fun getJobName(): String = "fake-job"
        }

    override fun <T> createSerializer(typeInformation: TypeInformation<T>): TypeSerializer<T> = throw UnsupportedOperationException()

    override fun getGlobalJobParameters(): Map<String, String> = emptyMap()

    override fun isObjectReuseEnabled(): Boolean = false

    override fun getUserCodeClassLoader(): ClassLoader = javaClass.classLoader

    override fun registerUserCodeClassLoaderReleaseHookIfAbsent(
        releaseHookName: String,
        releaseHook: Runnable,
    ) = Unit

    override fun <V : Any?, A : java.io.Serializable> addAccumulator(
        name: String,
        accumulator: Accumulator<V, A>,
    ) = Unit

    override fun <V : Any?, A : java.io.Serializable> getAccumulator(name: String): Accumulator<V, A>? = null

    override fun getIntCounter(name: String): IntCounter = IntCounter()

    override fun getLongCounter(name: String): LongCounter = LongCounter()

    override fun getDoubleCounter(name: String): DoubleCounter = DoubleCounter()

    override fun getHistogram(name: String): Histogram = throw UnsupportedOperationException()

    override fun getExternalResourceInfos(name: String): MutableSet<ExternalResourceInfo> = mutableSetOf()

    override fun hasBroadcastVariable(name: String): Boolean = false

    override fun <RT : Any?> getBroadcastVariable(name: String): MutableList<RT> = mutableListOf()

    override fun <T : Any?, C : Any?> getBroadcastVariableWithInitializer(
        name: String,
        initializer: BroadcastVariableInitializer<T, C>,
    ): C = throw UnsupportedOperationException()

    override fun getDistributedCache(): DistributedCache = throw UnsupportedOperationException()

    override fun <T : Any?> getState(descriptor: ValueStateDescriptor<T>): ValueState<T> = throw UnsupportedOperationException()

    override fun <T : Any?> getListState(descriptor: ListStateDescriptor<T>): ListState<T> = throw UnsupportedOperationException()

    override fun <T : Any?> getReducingState(descriptor: ReducingStateDescriptor<T>): ReducingState<T> =
        throw UnsupportedOperationException()

    override fun <IN : Any?, ACC : Any?, OUT : Any?> getAggregatingState(
        descriptor: AggregatingStateDescriptor<IN, ACC, OUT>,
    ): AggregatingState<IN, OUT> = throw UnsupportedOperationException()

    override fun <UK : Any?, UV : Any?> getMapState(descriptor: MapStateDescriptor<UK, UV>): MapState<UK, UV> =
        throw UnsupportedOperationException()

    override fun <T : Any?> getState(
        descriptor: org.apache.flink.api.common.state.v2.ValueStateDescriptor<T>,
    ): org.apache.flink.api.common.state.v2.ValueState<T> = throw UnsupportedOperationException()

    override fun <T : Any?> getListState(
        descriptor: org.apache.flink.api.common.state.v2.ListStateDescriptor<T>,
    ): org.apache.flink.api.common.state.v2.ListState<T> = throw UnsupportedOperationException()

    override fun <T : Any?> getReducingState(
        descriptor: org.apache.flink.api.common.state.v2.ReducingStateDescriptor<T>,
    ): org.apache.flink.api.common.state.v2.ReducingState<T> = throw UnsupportedOperationException()

    override fun <IN : Any?, ACC : Any?, OUT : Any?> getAggregatingState(
        descriptor: org.apache.flink.api.common.state.v2.AggregatingStateDescriptor<IN, ACC, OUT>,
    ): org.apache.flink.api.common.state.v2.AggregatingState<IN, OUT> = throw UnsupportedOperationException()

    override fun <UK : Any?, UV : Any?> getMapState(
        descriptor: org.apache.flink.api.common.state.v2.MapStateDescriptor<UK, UV>,
    ): org.apache.flink.api.common.state.v2.MapState<UK, UV> = throw UnsupportedOperationException()
}

/**
 * Minimal OperatorMetricGroup recording counters + gauges for test
 * assertions. The real MetricGroup API is huge; we only need the
 * subset the evaluator touches.
 */
class FakeMetricGroup(
    private val namePrefix: String,
) : OperatorMetricGroup {
    val counters: MutableMap<String, SimpleCounter> = ConcurrentHashMap()
    val gauges: MutableMap<String, Gauge<*>> = ConcurrentHashMap()
    val subgroups: MutableMap<String, FakeMetricGroup> = ConcurrentHashMap()

    private fun qualify(name: String): String = if (namePrefix.isEmpty()) name else "$namePrefix.$name"

    override fun counter(name: String): Counter {
        val key = qualify(name)
        return counters.computeIfAbsent(key) { SimpleCounter() }
    }

    override fun <C : Counter> counter(
        name: String,
        counter: C,
    ): C {
        val key = qualify(name)
        if (counter is SimpleCounter) {
            counters[key] = counter
        }
        return counter
    }

    override fun <T, G : Gauge<T>> gauge(
        name: String,
        gauge: G,
    ): G {
        gauges[qualify(name)] = gauge
        return gauge
    }

    override fun <H : FlinkHistogram> histogram(
        name: String,
        histogram: H,
    ): H = histogram

    override fun <M : Meter> meter(
        name: String,
        meter: M,
    ): M = meter

    override fun addGroup(name: String): MetricGroup = subgroups.computeIfAbsent(name) { FakeMetricGroup(qualify(name)) }

    override fun addGroup(
        key: String,
        value: String,
    ): MetricGroup = addGroup("$key.$value")

    override fun getScopeComponents(): Array<String> = emptyArray()

    override fun getAllVariables(): Map<String, String> = emptyMap()

    override fun getMetricIdentifier(metricName: String): String = qualify(metricName)

    override fun getMetricIdentifier(
        metricName: String,
        filter: org.apache.flink.metrics.CharacterFilter,
    ): String = qualify(metricName)

    override fun getIOMetricGroup(): org.apache.flink.runtime.metrics.groups.InternalOperatorIOMetricGroup? = null

    @Suppress("UNCHECKED_CAST")
    fun gaugeValue(name: String): Int? = (gauges[qualify(name)] as? Gauge<Int>)?.value

    fun counterValue(name: String): Long? = counters[qualify(name)]?.count

    fun gaugeFor(name: String): Gauge<*>? = gauges[qualify(name)]
}
