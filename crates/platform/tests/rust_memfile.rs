// SPDX-License-Identifier: MIT
//! Sealed read-only memfds.
use enzimos_platform::memfile;
use std::io::{Seek, SeekFrom};
#[test]
fn sealed_request_reader_refuses_wrong_owner_regular_files_and_excess_length() {
    let uid = enzimos_platform::process_identity::effective_uid();
    let mut file = memfile::sealed("request-reader", b"sealed request").unwrap();
    file.seek(SeekFrom::Start(3)).unwrap();
    assert_eq!(
        memfile::read_sealed(&file, 64, uid).unwrap(),
        b"sealed request"
    );
    assert_eq!(file.stream_position().unwrap(), 3);
    assert!(memfile::read_sealed(&file, 3, uid).is_err());
    assert!(memfile::read_sealed(&file, 64, uid + 1).is_err());
    let ordinary = tempfile::tempfile().unwrap();
    assert!(memfile::read_sealed(&ordinary, 64, uid).is_err());
}
