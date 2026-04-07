/// Fixed-size file chunking (512KB default).

/// Default chunk size: 512KB.
pub const DEFAULT_CHUNK_SIZE: usize = 512 * 1024;

/// Split data into fixed-size chunks.
/// Returns a Vec of byte slices, each up to `chunk_size` bytes.
/// The last chunk may be smaller.
pub fn chunk_file(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(chunk_size).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_zero_chunks() {
        let chunks = chunk_file(b"", DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn exact_one_chunk() {
        let data = vec![0xABu8; DEFAULT_CHUNK_SIZE];
        let chunks = chunk_file(&data, DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn one_byte_over_splits_to_two() {
        let data = vec![0xCDu8; DEFAULT_CHUNK_SIZE + 1];
        let chunks = chunk_file(&data, DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn large_file_correct_chunk_count() {
        // 2.5 * 512KB = 5 chunks (4 full + 1 half)
        let size = DEFAULT_CHUNK_SIZE * 2 + DEFAULT_CHUNK_SIZE / 2;
        let data = vec![0xEFu8; size];
        let chunks = chunk_file(&data, DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks[1].len(), DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks[2].len(), DEFAULT_CHUNK_SIZE / 2);
    }

    #[test]
    fn chunks_concatenate_to_original() {
        let data = b"hello world, this is a chunking test!";
        let chunks = chunk_file(data, 10);
        let reassembled: Vec<u8> = chunks.into_iter().flatten().copied().collect();
        assert_eq!(reassembled, data);
    }
}
