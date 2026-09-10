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
        }
    };
}
