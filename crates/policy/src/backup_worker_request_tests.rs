// SPDX-License-Identifier: MIT
use super::*;
use serde_json::json as value;
fn image(path: &str) -> Value {
    value!({"path":path,"inode":[1,2,4096,0,0,0,0,libc::S_IFREG|0o755,0,0,1],"mount":2,"sha256":"a".repeat(64)})
}
pub(crate) fn fixture() -> Value {
    let plan = crate::backup_setup_plan::tests::plan();
    let config = value!({"repository":crate::backup_configuration::REPOSITORY,
        "password_file":crate::backup_configuration::PASSWORD,"destination_uuid":plan["destination"]["filesystem_uuid"]});
    let original = value!([1, 3, 32, 0, 0, 0, 0, libc::S_IFREG | 0o600, 0, 0, 1]);
    let mut request = value!({"schema":3,"id":"1".repeat(32),"stage":"provision","task":"initialize","boot_id":plan["source"]["boot_id"],"header":null,
        "caller":{"pid":123,"start_ticks":4,"executable_sha256":plan["implementation_sha256"]},"plan":plan,
        "mount":{"mount_id":8,"unique_mount_id":9,"target":"/backup-repository","filesystem_uuid":config["destination_uuid"]},
        "root":{"device":8,"inode":256,"mount":9,"mode":libc::S_IFDIR|0o700,"uid":0,"gid":0},
        "repository":{"device":8,"inode":300,"mount":9,"mode":libc::S_IFDIR|0o700,"uid":0,"gid":0},
        "credential":{"kind":"published-root-credential","identity":original},"reader":null,"consumer_input":null,
        "restic":image("/usr/bin/restic"),"outer":{"identity":original,"sha256":"b".repeat(64)},
        "configuration":{"identity":original,"sha256":"c".repeat(64),"value":config}});
    request["outer"]["identity"][1] = value!(6);
    request["configuration"]["identity"][1] = value!(7);
    request
}

#[test]
fn frame_requires_original_root_sender_exact_hash_and_unique_fd_roles() {
    let request = fixture();
    let frame_value = value!({"schema":1,"id":request["id"],"request_sha256":json::fingerprint(&request).unwrap(),"descriptor_numbers":(10..21).collect::<Vec<_>>()});
    let sender = enzimos_platform::fd_packet::Credentials {
        pid: 123,
        uid: 0,
        gid: 0,
    };
    assert_eq!(frame(&frame_value, &request, &sender).unwrap().len(), 11);
    for sender in [
        enzimos_platform::fd_packet::Credentials {
            pid: 124,
            uid: 0,
            gid: 0,
        },
        enzimos_platform::fd_packet::Credentials {
            pid: 123,
            uid: 1000,
            gid: 1000,
        },
    ] {
        assert!(frame(&frame_value, &request, &sender).is_err());
    }
    for replacement in [
        value!(vec![10; 11]),
        value!((0..11).collect::<Vec<_>>()),
        value!((10..20).collect::<Vec<_>>()),
    ] {
        let mut bad = frame_value.clone();
        bad["descriptor_numbers"] = replacement;
        assert!(frame(&bad, &request, &sender).is_err());
    }
    let mut bad = frame_value;
    bad["request_sha256"] = value!("f".repeat(64));
    assert!(frame(&bad, &request, &sender).is_err());
}
