/*
 * Chio C++ kernel FFI ABI.
 *
 * This header is generated from crates/sdk/chio-cpp-kernel-ffi with cbindgen.
 * The ABI is intentionally narrow: JSON strings in, JSON strings out, and
 * explicit Rust-owned buffer release.
 */


#ifndef CHIO_CPP_KERNEL_FFI_H
#define CHIO_CPP_KERNEL_FFI_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C ABI version of this kernel FFI surface.
 *
 * Bumped from 1 to 2 when `chio_kernel_sign_receipt_json` gained a third
 * pointer argument (`canonical_content_hex`, the WYSIWYS preimage). The symbol
 * name is unchanged, so an old 2-arg client linked against v1 would call the
 * 3-arg symbol with a missing third pointer (undefined behavior). Clients that
 * gate on `chio_kernel_ffi_abi_version()` now fail closed against this v2
 * surface instead of invoking the signer with a dangling argument.
 */
#define CHIO_CPP_KERNEL_FFI_ABI_VERSION 2

#define CHIO_KERNEL_FFI_STATUS_OK 0

#define CHIO_KERNEL_FFI_STATUS_ERROR 1

#define CHIO_KERNEL_FFI_STATUS_PANIC 2

#define CHIO_KERNEL_FFI_STATUS_NULL_ARGUMENT 3

#define CHIO_KERNEL_FFI_ERROR_NONE 0

#define CHIO_KERNEL_FFI_ERROR_INVALID_JSON 1

#define CHIO_KERNEL_FFI_ERROR_INVALID_HEX 2

#define CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY 3

#define CHIO_KERNEL_FFI_ERROR_INVALID_PASSPORT 4

#define CHIO_KERNEL_FFI_ERROR_KEY_MISMATCH 5

#define CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED 6

#define CHIO_KERNEL_FFI_ERROR_INTERNAL 255

typedef struct ChioKernelFfiBuffer {
  uint8_t *ptr;
  size_t len;
} ChioKernelFfiBuffer;

typedef struct ChioKernelFfiResult {
  int32_t status;
  int32_t error_code;
  struct ChioKernelFfiBuffer data;
} ChioKernelFfiResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

uint32_t chio_kernel_ffi_abi_version(void);

struct ChioKernelFfiResult chio_kernel_build_info(void);

void chio_kernel_buffer_free(struct ChioKernelFfiBuffer buffer);

struct ChioKernelFfiResult chio_kernel_evaluate_json(const char *request_json);

/**
 * PUBLIC WYSIWYS signer (fail-closed). `canonical_content_hex` is the
 * lowercase-hex preimage `content_hash` was derived from; the signer recomputes
 * the hash inside the trust boundary and refuses on mismatch. This
 * does NOT relay a trusted body; use
 * `chio_kernel_sign_receipt_relaying_trusted_body_json` for the relay seam.
 */
struct ChioKernelFfiResult chio_kernel_sign_receipt_json(const char *body_json,
                                                         const char *canonical_content_hex,
                                                         const char *signing_seed_hex);

/**
 * Relay-sign an already-minted, upstream-trusted receipt body. This is NOT the
 * default public signer. Trusts the caller-supplied `content_hash` and
 * does NOT recompute it. Content-bearing callers MUST use
 * `chio_kernel_sign_receipt_json` instead so the WYSIWYS recompute gate runs.
 */
struct ChioKernelFfiResult chio_kernel_sign_receipt_relaying_trusted_body_json(const char *body_json,
                                                                               const char *signing_seed_hex);

struct ChioKernelFfiResult chio_kernel_verify_capability_json(const char *token_json,
                                                              const char *authority_pub_hex,
                                                              int64_t now_secs);

struct ChioKernelFfiResult chio_kernel_verify_capability_with_context_json(const char *request_json);

struct ChioKernelFfiResult chio_kernel_verify_passport_json(const char *envelope_json,
                                                            const char *issuer_pub_hex,
                                                            int64_t now_secs);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* CHIO_CPP_KERNEL_FFI_H */
