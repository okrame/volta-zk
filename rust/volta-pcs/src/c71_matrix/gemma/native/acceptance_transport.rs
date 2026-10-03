//! Completion records on a caller-owned authenticated, dedicated channel.
//! Framing/binding is not authentication: never use this on an untrusted raw
//! socket. A received record is checked against the pending local transcript;
//! it cannot import history or substitute for verifier acceptance/journaling.
use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"C71ACC01";
pub(in crate::c71_matrix::gemma::native) const BYTES: usize = 73;

pub(in crate::c71_matrix::gemma::native) fn send(
    channel: &mut impl Write,
    completion: Option<([u8; 32], [u8; 32])>,
) -> io::Result<()> {
    let mut frame = [0; BYTES];
    frame[..8].copy_from_slice(MAGIC);
    if let Some((context, receipt)) = completion {
        frame[8] = 1;
        frame[9..41].copy_from_slice(&context);
        frame[41..].copy_from_slice(&receipt);
    }
    channel.write_all(&frame)?;
    channel.flush()
}

pub(in crate::c71_matrix::gemma::native) fn receive(
    channel: &mut impl Read,
    context: [u8; 32],
    receipt: [u8; 32],
) -> io::Result<()> {
    let mut frame = [0; BYTES];
    channel.read_exact(&mut frame)?;
    if &frame[..8] != MAGIC || frame[8] != 1 || frame[9..41] != context || frame[41..] != receipt {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Stop"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_acceptance_transport_binds_pending_context_and_receipt() {
        let mut frame = Vec::new();
        send(&mut frame, Some(([1; 32], [2; 32]))).unwrap();
        assert_eq!(frame.len(), BYTES);
        receive(&mut &frame[..], [1; 32], [2; 32]).unwrap();
        for index in 0..BYTES {
            let mut altered = frame.clone();
            altered[index] ^= 1;
            assert!(receive(&mut &altered[..], [1; 32], [2; 32]).is_err());
            assert!(receive(&mut &frame[..index], [1; 32], [2; 32]).is_err());
        }
        assert!(receive(&mut &frame[..], [3; 32], [2; 32]).is_err());
        assert!(receive(&mut &frame[..], [1; 32], [3; 32]).is_err());
        let mut stop = Vec::new();
        send(&mut stop, None).unwrap();
        assert!(receive(&mut &stop[..], [0; 32], [0; 32]).is_err());
        assert!(send(&mut &mut [0u8; BYTES - 1][..], None).is_err());
    }
}
