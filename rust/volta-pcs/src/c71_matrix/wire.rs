//! Canonical bounded component transport for the composed certificate.
//! Decoding never creates a transcript or authenticates a new endpoint.

use super::Fp3;

pub(super) const MAX_BYTES: usize = 16 << 20;
// Canonical D35/D34 shape upper <93 MB including all four PCS and header.
pub(super) const CANONICAL_MAX_BYTES: usize = 96 << 20;

pub(super) trait Wire: Sized {
    const MIN_BYTES: usize;
    fn write(&self, out: &mut Vec<u8>);
    fn read(input: &mut &[u8]) -> Result<Self, String>;
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity;
}

/// Test-only typed proof census. Inline fields are charged by their enclosing
/// Vec's sizeof(T); only owned nested allocations are added recursively.
#[cfg(test)]
#[derive(Clone, Copy, Default)]
pub(super) struct HeapCapacity {
    pub retained: usize,
    pub shape_upper: usize,
    pub largest_vector_upper: usize,
    pub array_decode_temporary_upper: usize,
}

#[cfg(test)]
impl HeapCapacity {
    pub fn add(self, other: Self) -> Self {
        Self { retained: self.retained + other.retained,
            shape_upper: self.shape_upper + other.shape_upper,
            largest_vector_upper: self.largest_vector_upper.max(other.largest_vector_upper),
            array_decode_temporary_upper: self.array_decode_temporary_upper
                .max(other.array_decode_temporary_upper) }
    }
    pub fn decoder_peak_upper(self) -> usize {
        self.shape_upper + self.largest_vector_upper / 2 + self.array_decode_temporary_upper
    }
}

/// Monotone push/extend, exact with_capacity and collect/clone constructors used
/// by these proof fields have cap <=2*max(len, MIN_NON_ZERO_CAP) on the pinned
/// Rust allocator. Zero-length proof vectors start empty; no proof field retains
/// a truncated witness/workspace. This is a shape bound, not wire_len*ratio.
#[cfg(test)]
pub(super) fn vector_shape_upper<T>(count: usize) -> usize {
    let item = std::mem::size_of::<T>();
    if count == 0 || item == 0 { return 0; }
    let minimum = if item == 1 { 8 } else if item <= 1024 { 4 } else { 1 };
    2 * count.max(minimum) * item
}

#[cfg(test)]
pub(super) fn vector_heap<T>(values: &Vec<T>, nested: impl Fn(&T) -> HeapCapacity) -> HeapCapacity {
    let shape_upper = vector_shape_upper::<T>(values.len());
    let retained = values.capacity() * std::mem::size_of::<T>();
    assert!(retained <= shape_upper, "proof Vec capacity exceeds monotone typed shape bound");
    values.iter().fold(HeapCapacity { retained, shape_upper,
        largest_vector_upper: shape_upper, array_decode_temporary_upper: 0 },
        |heap, value| heap.add(nested(value)))
}

pub(super) fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], String> {
    if count > input.len() {
        return Err("truncated composed certificate".into());
    }
    let (value, rest) = input.split_at(count);
    *input = rest;
    Ok(value)
}

impl Wire for Fp3 {
    const MIN_BYTES: usize = 24;
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.to_bytes());
    }
    fn read(input: &mut &[u8]) -> Result<Self, String> {
        Self::from_bytes(take(input, 24)?).map_err(|e| e.to_string())
    }
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity { HeapCapacity::default() }
}

impl<T: Wire, const N: usize> Wire for [T; N] {
    const MIN_BYTES: usize = N * T::MIN_BYTES;
    fn write(&self, out: &mut Vec<u8>) {
        for value in self {
            value.write(out);
        }
    }
    fn read(input: &mut &[u8]) -> Result<Self, String> {
        (0..N)
            .map(|_| T::read(input))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "certificate array shape".into())
    }
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity {
        let mut heap = self.iter().fold(HeapCapacity::default(), |h, value| h.add(value.heap_capacity()));
        // Wire::read temporarily collects arrays to Vec before try_into.
        heap.array_decode_temporary_upper += vector_shape_upper::<T>(N);
        heap
    }
}

impl<T: Wire> Wire for Vec<T> {
    const MIN_BYTES: usize = 4;
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(
            u32::try_from(self.len()).expect("certificate vector exceeds u32").to_le_bytes(),
        );
        for value in self {
            value.write(out);
        }
    }
    fn read(input: &mut &[u8]) -> Result<Self, String> {
        let count = u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize;
        if count > 65536 || count > input.len() / T::MIN_BYTES.max(1) {
            return Err("certificate vector exceeds remaining frame".into());
        }
        (0..count).map(|_| T::read(input)).collect()
    }
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity { vector_heap(self, Wire::heap_capacity) }
}

impl<T: Wire> Wire for Option<T> {
    const MIN_BYTES: usize = 1;
    fn write(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.is_some()));
        if let Some(value) = self {
            value.write(out);
        }
    }
    fn read(input: &mut &[u8]) -> Result<Self, String> {
        match take(input, 1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(T::read(input)?)),
            _ => Err("noncanonical certificate option".into()),
        }
    }
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity {
        self.as_ref().map_or_else(HeapCapacity::default, Wire::heap_capacity)
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    const MIN_BYTES: usize = A::MIN_BYTES + B::MIN_BYTES;
    fn write(&self, out: &mut Vec<u8>) {
        self.0.write(out);
        self.1.write(out);
    }
    fn read(input: &mut &[u8]) -> Result<Self, String> {
        Ok((A::read(input)?, B::read(input)?))
    }
    #[cfg(test)]
    fn heap_capacity(&self) -> HeapCapacity { self.0.heap_capacity().add(self.1.heap_capacity()) }
}

// Invoke in the defining module: proof fields remain private to their kernel.
macro_rules! component_wire {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        impl crate::c71_matrix::wire::Wire for $name {
            // All component records have at least one field element or count.
            const MIN_BYTES: usize = 1;
            fn write(&self, out: &mut Vec<u8>) {
                $(crate::c71_matrix::wire::Wire::write(&self.$field, out);)+
            }
            fn read(input: &mut &[u8]) -> Result<Self, String> {
                Ok(Self { $($field: crate::c71_matrix::wire::Wire::read(input)?),+ })
            }
            #[cfg(test)]
            fn heap_capacity(&self) -> crate::c71_matrix::wire::HeapCapacity {
                crate::c71_matrix::wire::HeapCapacity::default()
                    $(.add(crate::c71_matrix::wire::Wire::heap_capacity(&self.$field)))+
            }
        }
    };
}

#[cfg(test)]
mod heap_tests {
    use super::*;

    #[test]
    fn c71_wire_typed_heap_counts_option_vectors_and_moving_growth() {
        let value = vec![Some(vec![Fp3::ZERO; 9]), None, Some(Vec::new())];
        let heap = value.heap_capacity();
        let expected = value.capacity() * std::mem::size_of::<Option<Vec<Fp3>>>()
            + value.iter().flatten().map(|row| row.capacity() * std::mem::size_of::<Fp3>()).sum::<usize>();
        assert_eq!(heap.retained, expected);
        assert!(heap.shape_upper >= expected);
        let mut bytes = Vec::new();
        value.write(&mut bytes);
        let mut input = bytes.as_slice();
        let decoded = Vec::<Option<Vec<Fp3>>>::read(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, value);
        assert!(decoded.heap_capacity().retained <= heap.shape_upper);
        assert_eq!(decoded.heap_capacity().shape_upper, heap.shape_upper);
        let array = [Fp3::ZERO; 9].heap_capacity();
        assert_eq!(array.retained, 0);
        assert_eq!(array.array_decode_temporary_upper, vector_shape_upper::<Fp3>(9));
        assert_eq!(vector_shape_upper::<u8>(0), 0);
        for size in [1usize, 7, 8, 9, 24, 32, 1024] {
            let mut output = Vec::new();
            for _ in 0..size { output.push(0u8); }
            assert!(output.capacity() <= vector_shape_upper::<u8>(size));
        }
        println!("C71_WIRE_HEAP_PRIMITIVES {{\"option_vec_inline_bytes\":{},\"retained_heap_bytes\":{},\"shape_heap_upper_bytes\":{},\"decoder_moving_peak_upper_bytes\":{},\"credit\":false}}",
            std::mem::size_of::<Option<Vec<Fp3>>>(), heap.retained, heap.shape_upper, heap.decoder_peak_upper());
    }
}
