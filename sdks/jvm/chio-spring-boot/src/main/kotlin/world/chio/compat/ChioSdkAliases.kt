/**
 * Typealias shims that keep the legacy `world.chio.*` imports
 * working for one release after the SDK moved to the new module.
 * Remove in 0.2.0.
 */
@file:JvmName("ChioSdkAliases")

package world.chio

typealias AuthMethod = world.chio.sdk.AuthMethod
typealias CallerIdentity = world.chio.sdk.CallerIdentity
typealias Verdict = world.chio.sdk.Verdict
typealias GuardEvidence = world.chio.sdk.GuardEvidence
typealias HttpReceipt = world.chio.sdk.HttpReceipt
typealias ChioHttpRequest = world.chio.sdk.ChioHttpRequest
typealias EvaluateResponse = world.chio.sdk.EvaluateResponse
typealias ChioPassthrough = world.chio.sdk.ChioPassthrough
typealias ChioErrorResponse = world.chio.sdk.ChioErrorResponse
typealias ChioErrorCodes = world.chio.sdk.ChioErrorCodes
