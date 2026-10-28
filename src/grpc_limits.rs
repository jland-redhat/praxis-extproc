// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Red Hat, Inc.

//! gRPC per-message receive size for the ExtProc tonic server.
//!
//! Envoy delivers each buffered request/response body chunk as one gRPC
//! message. tonic's compiled default (`4 MiB`) rejects multimodal / agent
//! chat bodies with `decoded message length too large`, which Envoy surfaces
//! as an empty HTTP 500. The default here matches Go IPP / llm-d-router
//! operator practice (`32 MiB`) while remaining a DoS bound.
//!
//! Override with [`GRPC_MAX_RECV_MSG_SIZE_ENV`] (plain bytes or a Kubernetes
//! quantity such as `64Mi`). This is a **per-message** cap only; cumulative
//! body accumulation across streamed chunks is still governed by
//! `server.max_body_bytes` / `insecure_options.allow_unbounded_body`.

use std::env;

/// Environment variable that overrides [`DEFAULT_GRPC_MAX_RECV_MSG_SIZE`].
pub const GRPC_MAX_RECV_MSG_SIZE_ENV: &str = "GRPC_MAX_RECV_MSG_SIZE";

/// Default max decoding message size: above tonic's 4 MiB compiled default,
/// aligned with Go `ai-gateway-payload-processing` / RHAI-13005.
pub const DEFAULT_GRPC_MAX_RECV_MSG_SIZE: usize = 32 * 1024 * 1024;

/// tonic / gRPC compiled default receive limit (bytes).
pub const GRPC_COMPILED_MAX_RECV_DEFAULT: usize = 4 * 1024 * 1024;

/// Resolve the ExtProc gRPC max decoding message size from the process env.
///
/// # Errors
///
/// Returns an error when [`GRPC_MAX_RECV_MSG_SIZE_ENV`] is set to a non-empty
/// value that is not a positive integer or Kubernetes quantity.
pub fn resolve_grpc_max_recv_msg_size() -> Result<usize, String> {
    resolve_grpc_max_recv_msg_size_from(env::var(GRPC_MAX_RECV_MSG_SIZE_ENV).ok().as_deref())
}

/// Resolve from an optional raw string (tests inject values without touching env).
pub fn resolve_grpc_max_recv_msg_size_from(raw: Option<&str>) -> Result<usize, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_GRPC_MAX_RECV_MSG_SIZE);
    };

    let n = parse_msg_size_bytes(raw)
        .map_err(|e| format!("{GRPC_MAX_RECV_MSG_SIZE_ENV}={raw:?}: {e}"))?;
    if n == 0 {
        return Err(format!("{GRPC_MAX_RECV_MSG_SIZE_ENV}={raw:?}: must be a positive size"));
    }
    Ok(n)
}

fn parse_msg_size_bytes(raw: &str) -> Result<usize, String> {
    // Prefer plain integers so operators can pass exact byte counts from logs
    // (e.g. the 4194304 from "decoded message length too large").
    if let Ok(n) = raw.parse::<usize>() {
        return Ok(n);
    }

    parse_k8s_quantity(raw)
}

/// Parse a subset of Kubernetes resource quantities used for byte sizes.
///
/// Supports binary (`Ki`/`Mi`/`Gi`) and decimal (`K`/`M`/`G`) suffixes, matching
/// what operators commonly set on `GRPC_MAX_RECV_MSG_SIZE` in the Go IPP image.
fn parse_k8s_quantity(raw: &str) -> Result<usize, String> {
    const SUFFIXES: &[(&str, u128)] = &[
        ("Ki", 1024),
        ("Mi", 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("K", 1000),
        ("M", 1000 * 1000),
        ("G", 1000 * 1000 * 1000),
    ];

    for &(suffix, mul) in SUFFIXES {
        if let Some(num) = raw.strip_suffix(suffix) {
            let n: u128 = num
                .trim()
                .parse()
                .map_err(|_| format!("parse size: invalid quantity {raw:?}"))?;
            if n == 0 {
                return Err("size must be positive".into());
            }
            let bytes = n
                .checked_mul(mul)
                .ok_or_else(|| format!("size {raw:?} overflows"))?;
            return u128_to_usize(bytes);
        }
    }

    Err(format!("parse size: invalid quantity {raw:?}"))
}

fn u128_to_usize(v: u128) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| format!("size {v} overflows usize"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_uses_default() {
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(None).unwrap(),
            DEFAULT_GRPC_MAX_RECV_MSG_SIZE
        );
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("")).unwrap(),
            DEFAULT_GRPC_MAX_RECV_MSG_SIZE
        );
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("  \t ")).unwrap(),
            DEFAULT_GRPC_MAX_RECV_MSG_SIZE
        );
    }

    #[test]
    fn plain_bytes_and_quantities() {
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("67108864")).unwrap(),
            64 * 1024 * 1024
        );
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("32Mi")).unwrap(),
            32 * 1024 * 1024
        );
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("1Gi")).unwrap(),
            1024 * 1024 * 1024
        );
        assert_eq!(
            resolve_grpc_max_recv_msg_size_from(Some("64M")).unwrap(),
            64 * 1000 * 1000
        );
    }

    #[test]
    fn rejects_invalid() {
        for raw in ["0", "-1", "lots", "Mi"] {
            assert!(
                resolve_grpc_max_recv_msg_size_from(Some(raw)).is_err(),
                "expected error for {raw:?}"
            );
        }
    }

    #[test]
    fn default_above_grpc_compiled() {
        assert!(DEFAULT_GRPC_MAX_RECV_MSG_SIZE > GRPC_COMPILED_MAX_RECV_DEFAULT);
    }
}
