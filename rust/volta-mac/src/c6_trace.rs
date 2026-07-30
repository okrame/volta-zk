//! Diagnostic-only C6 authenticated-value provenance recorder.
//!
//! The ordinary build uses a zero-sized token and records nothing.  The
//! `c6-trace` feature turns the token into a compact handle and enables one
//! process-local, fail-closed prover trace.  This module deliberately does
//! not infer provenance from plaintexts, tags, keys, or addresses.

use std::fmt;
use volta_field::Fp2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6TraceError(String);

impl C6TraceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6TraceError {}

/// Copyable ghost provenance attached only by a `c6-trace` build.
#[cfg(not(feature = "c6-trace"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct C6TraceToken;

/// Copyable ghost provenance attached only by a `c6-trace` build.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct C6TraceToken(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6TraceNode {
    Public(Fp2),
    Add { lhs: C6TraceToken, rhs: C6TraceToken },
    Sub { lhs: C6TraceToken, rhs: C6TraceToken },
    Scale { value: C6TraceToken, scalar: Fp2 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6TraceProductClosure {
    pub triples: Vec<[C6TraceToken; 3]>,
    pub mask: C6TraceToken,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ProverTraceSnapshot {
    pub source_count: u32,
    pub nodes: Vec<C6TraceNode>,
    pub zero_roots: Vec<C6TraceToken>,
    pub products: Vec<C6TraceProductClosure>,
}

#[cfg(feature = "c6-trace")]
const PUBLIC_ZERO_TOKEN: u32 = 1;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_BIT: u32 = 1 << 31;
#[cfg(feature = "c6-trace")]
const SOURCE_TOKEN_MASK: u32 = SOURCE_TOKEN_BIT - 1;

#[cfg(feature = "c6-trace")]
#[derive(Default)]
struct C6TraceRuntime {
    active: bool,
    source_count: u32,
    nodes: Vec<C6TraceNode>,
    zero_roots: Vec<C6TraceToken>,
    products: Vec<C6TraceProductClosure>,
}

#[cfg(feature = "c6-trace")]
fn runtime() -> &'static std::sync::Mutex<C6TraceRuntime> {
    static RUNTIME: std::sync::OnceLock<std::sync::Mutex<C6TraceRuntime>> =
        std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| std::sync::Mutex::new(C6TraceRuntime::default()))
}

#[cfg(feature = "c6-trace")]
fn with_runtime<T>(
    operation: impl FnOnce(&mut C6TraceRuntime) -> Result<T, C6TraceError>,
) -> Result<T, C6TraceError> {
    let mut runtime =
        runtime().lock().map_err(|_| C6TraceError::new("C6 trace mutex is poisoned"))?;
    operation(&mut runtime)
}

pub fn begin_c6_prover_trace() -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if runtime.active {
                return Err(C6TraceError::new("a C6 prover trace is already active"));
            }
            runtime.active = true;
            runtime.source_count = 0;
            runtime.nodes.clear();
            runtime.zero_roots.clear();
            runtime.products.clear();
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

pub fn finish_c6_prover_trace() -> Result<C6ProverTraceSnapshot, C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Err(C6TraceError::new("no C6 prover trace is active"));
            }
            runtime.active = false;
            Ok(C6ProverTraceSnapshot {
                source_count: runtime.source_count,
                nodes: std::mem::take(&mut runtime.nodes),
                zero_roots: std::mem::take(&mut runtime.zero_roots),
                products: std::mem::take(&mut runtime.products),
            })
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        Err(C6TraceError::new("C6 prover tracing requires the diagnostic c6-trace feature"))
    }
}

impl C6TraceToken {
    pub(crate) const fn untracked() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self(0)
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    pub(crate) const fn public_zero() -> Self {
        #[cfg(feature = "c6-trace")]
        {
            Self(PUBLIC_ZERO_TOKEN)
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Self
        }
    }

    #[cfg(feature = "c6-trace")]
    fn is_untracked(self) -> bool {
        self.0 == 0
    }

    #[cfg(feature = "c6-trace")]
    fn is_source(self) -> bool {
        self.0 & SOURCE_TOKEN_BIT != 0
    }

    pub fn source_index(self) -> Option<u32> {
        #[cfg(feature = "c6-trace")]
        {
            return self.is_source().then_some((self.0 & SOURCE_TOKEN_MASK).checked_sub(1)?);
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            None
        }
    }

    pub fn is_tracked(self) -> bool {
        #[cfg(feature = "c6-trace")]
        {
            return !self.is_untracked();
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            false
        }
    }

    #[cfg(feature = "c6-trace")]
    pub(crate) fn source(index: u32) -> Result<Self, C6TraceError> {
        if index >= SOURCE_TOKEN_MASK - 1 {
            return Err(C6TraceError::new("C6 trace source index exceeds token capacity"));
        }
        with_runtime(|runtime| {
            if !runtime.active {
                return Err(C6TraceError::new("C6 trace source allocated without an active trace"));
            }
            if index != runtime.source_count {
                return Err(C6TraceError::new(format!(
                    "C6 trace source index {index} is not canonical next index {}",
                    runtime.source_count
                )));
            }
            runtime.source_count = runtime
                .source_count
                .checked_add(1)
                .ok_or_else(|| C6TraceError::new("C6 trace source count overflows"))?;
            Ok(Self(SOURCE_TOKEN_BIT | (index + 1)))
        })
    }

    pub(crate) fn public(value: Fp2) -> Self {
        #[cfg(feature = "c6-trace")]
        {
            if value == Fp2::ZERO {
                return Self::public_zero();
            }
            return record_node(C6TraceNode::Public(value));
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            let _ = value;
            Self
        }
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        record_binary(self, rhs, |lhs, rhs| C6TraceNode::Add { lhs, rhs })
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        record_binary(self, rhs, |lhs, rhs| C6TraceNode::Sub { lhs, rhs })
    }

    pub(crate) fn scale(self, scalar: Fp2) -> Self {
        #[cfg(feature = "c6-trace")]
        {
            if self.is_untracked() {
                return Self::untracked();
            }
            return record_node(C6TraceNode::Scale { value: self, scalar });
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            let _ = scalar;
            Self
        }
    }
}

fn record_binary(
    lhs: C6TraceToken,
    rhs: C6TraceToken,
    node: impl FnOnce(C6TraceToken, C6TraceToken) -> C6TraceNode,
) -> C6TraceToken {
    #[cfg(feature = "c6-trace")]
    {
        if lhs.is_untracked() || rhs.is_untracked() {
            return C6TraceToken::untracked();
        }
        return record_node(node(lhs, rhs));
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (lhs, rhs, node);
        C6TraceToken
    }
}

#[cfg(feature = "c6-trace")]
fn record_node(node: C6TraceNode) -> C6TraceToken {
    with_runtime(|runtime| {
        if !runtime.active {
            return Ok(C6TraceToken::untracked());
        }
        let index = u32::try_from(runtime.nodes.len())
            .map_err(|_| C6TraceError::new("C6 trace operation count exceeds u32"))?;
        if index >= SOURCE_TOKEN_BIT - 2 {
            return Err(C6TraceError::new("C6 trace operation token capacity exhausted"));
        }
        runtime.nodes.push(node);
        Ok(C6TraceToken(index + 2))
    })
    .unwrap_or_else(|error| panic!("C6 trace node HARD STOP: {error}"))
}

#[doc(hidden)]
pub fn record_c6_zero_roots(values: &[C6TraceToken]) -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Ok(());
            }
            if let Some(index) = values.iter().position(|token| !token.is_tracked()) {
                return Err(C6TraceError::new(format!("C6 zero root {index} lacks provenance")));
            }
            runtime.zero_roots.extend_from_slice(values);
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = values;
        Ok(())
    }
}

#[doc(hidden)]
pub fn record_c6_product_closure(
    triples: &[[C6TraceToken; 3]],
    mask: C6TraceToken,
) -> Result<(), C6TraceError> {
    #[cfg(feature = "c6-trace")]
    {
        return with_runtime(|runtime| {
            if !runtime.active {
                return Ok(());
            }
            if !mask.is_tracked() {
                return Err(C6TraceError::new("C6 ProductClosure mask lacks provenance"));
            }
            if mask.source_index().is_none() {
                return Err(C6TraceError::new(
                    "C6 ProductClosure mask is not a source provenance token",
                ));
            }
            for (triple_index, triple) in triples.iter().enumerate() {
                if let Some(operand) = triple.iter().position(|token| !token.is_tracked()) {
                    return Err(C6TraceError::new(format!(
                        "C6 ProductClosure triple {triple_index} operand {operand} lacks provenance"
                    )));
                }
            }
            runtime.products.push(C6TraceProductClosure { triples: triples.to_vec(), mask });
            Ok(())
        });
    }
    #[cfg(not(feature = "c6-trace"))]
    {
        let _ = (triples, mask);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_trace_token_is_zero_sized() {
        #[cfg(not(feature = "c6-trace"))]
        assert_eq!(std::mem::size_of::<C6TraceToken>(), 0);
        #[cfg(feature = "c6-trace")]
        assert_eq!(std::mem::size_of::<C6TraceToken>(), 4);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn trace_rejects_missing_provenance_and_censuses_sources() {
        begin_c6_prover_trace().unwrap();
        let source = C6TraceToken::source(0).unwrap();
        let public = C6TraceToken::public(Fp2::ONE);
        let sum = source.add(public);
        record_c6_product_closure(&[[source, public, sum]], source).unwrap();
        let error = record_c6_zero_roots(&[C6TraceToken::untracked()]).unwrap_err();
        assert!(error.to_string().contains("lacks provenance"));
        record_c6_zero_roots(&[sum]).unwrap();
        let snapshot = finish_c6_prover_trace().unwrap();
        assert_eq!(snapshot.source_count, 1);
        assert_eq!(snapshot.products.len(), 1);
        assert_eq!(snapshot.zero_roots, vec![sum]);
    }
}
