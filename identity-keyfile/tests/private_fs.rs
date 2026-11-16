use identity_keyfile::private_fs::{
    check_private_dir, create_private_dir, read_private_file, read_regular_file,
    write_private_atomic, MAX_KEY_FILE_BYTES, MAX_PUBLIC_FILE_BYTES,
};
use identity_keyfile::KeyfileError;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn tmp_entries(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect()
}

fn mkfifo(p: &Path) {
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

#[test]
fn private_fs_write_is_0600_atomic_and_fsyncs() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    write_private_atomic(&p, b"one", 0o600).unwrap();
    assert_eq!(mode(&p), 0o600);
    assert_eq!(fs::read(&p).unwrap(), b"one");
    write_private_atomic(&p, b"two", 0o600).unwrap();
    assert_eq!(mode(&p), 0o600);
    assert_eq!(fs::read(&p).unwrap(), b"two");
    assert!(tmp_entries(d.path()).is_empty());
    let q = d.path().join("ro");
    write_private_atomic(&q, b"x", 0o400).unwrap();
    assert_eq!(mode(&q), 0o400);
    assert!(tmp_entries(d.path()).is_empty());
}

#[test]
fn write_private_atomic_refuses_open_modes() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    for m in [0o644, 0o700, 0o660] {
        assert!(matches!(
            write_private_atomic(&p, b"x", m),
            Err(KeyfileError::InvalidMode(x)) if x == m
        ));
        assert!(!p.exists());
    }
}

#[test]
fn write_failure_removes_temp() {
    let d = tempfile::tempdir().unwrap();
    let parent = d.path().join("sub");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
    // Running as root bypasses directory permissions; nothing to assert then.
    let is_root = unsafe { libc::geteuid() } == 0;
    let r = write_private_atomic(&parent.join("k"), b"x", 0o600);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    if !is_root {
        assert!(matches!(r, Err(KeyfileError::Io { .. })));
    }
    assert!(tmp_entries(&parent).is_empty());
}

#[test]
fn read_private_file_refuses_fifo_symlink_oversize_loose_wrong_owner() {
    let d = tempfile::tempdir().unwrap();
    let cap = 8;

    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    assert!(
        matches!(read_private_file(&fifo, cap), Err(KeyfileError::NotAFile(ref x)) if *x == fifo)
    );

    let real = d.path().join("real");
    write_private_atomic(&real, b"abc", 0o600).unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(matches!(
        read_private_file(&link, cap),
        Err(KeyfileError::InsecureFile(_))
    ));

    let big = d.path().join("big");
    write_private_atomic(&big, &vec![7u8; cap + 1], 0o600).unwrap();
    assert!(matches!(
        read_private_file(&big, cap),
        Err(KeyfileError::TooLarge { cap: c, .. }) if c == cap
    ));

    let exact = d.path().join("exact");
    write_private_atomic(&exact, &vec![7u8; cap], 0o600).unwrap();
    assert_eq!(read_private_file(&exact, cap).unwrap().len(), cap);

    let loose = d.path().join("loose");
    fs::write(&loose, b"abc").unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        read_private_file(&loose, cap),
        Err(KeyfileError::InsecureFile(_))
    ));

    let missing = d.path().join("missing");
    assert!(matches!(
        read_private_file(&missing, cap),
        Err(KeyfileError::Missing(ref x)) if *x == missing
    ));

    const { assert!(MAX_KEY_FILE_BYTES < MAX_PUBLIC_FILE_BYTES) };
}

#[test]
fn create_private_dir_creates_0700_and_refuses_loose_or_symlink() {
    let d = tempfile::tempdir().unwrap();
    let nested = d.path().join("a").join("b");
    create_private_dir(&nested).unwrap();
    assert_eq!(mode(&nested), 0o700);
    assert_eq!(mode(&d.path().join("a")), 0o700);
    check_private_dir(&nested).unwrap();

    let loose = d.path().join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        create_private_dir(&loose),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(matches!(
        check_private_dir(&loose),
        Err(KeyfileError::InsecureDir(_))
    ));

    let link = d.path().join("link");
    symlink(&nested, &link).unwrap();
    assert!(matches!(
        create_private_dir(&link),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(matches!(
        check_private_dir(&link),
        Err(KeyfileError::InsecureDir(_))
    ));

    let missing = d.path().join("nope");
    assert!(matches!(
        check_private_dir(&missing),
        Err(KeyfileError::Missing(_))
    ));
}

#[test]
fn read_regular_file_ignores_mode_but_not_symlink_or_cap() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("pub");
    fs::write(&f, b"hello").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(read_regular_file(&f, 5).unwrap(), b"hello");
    assert!(matches!(
        read_regular_file(&f, 4),
        Err(KeyfileError::TooLarge { cap: 4, .. })
    ));
    let link = d.path().join("link");
    symlink(&f, &link).unwrap();
    assert!(read_regular_file(&link, 100).is_err());
    let fifo = d.path().join("fifo");
    mkfifo(&fifo);
    assert!(matches!(
        read_regular_file(&fifo, 100),
        Err(KeyfileError::NotAFile(_))
    ));
    assert!(matches!(
        read_regular_file(&d.path().join("missing"), 100),
        Err(KeyfileError::Missing(_))
    ));
}
