#![cfg(feature = "testkit")]

use identity_keyfile::testkit::TempIdentityDir;

#[test]
fn temp_agent_dir_is_cleaned_on_drop() {
    let path = {
        let fixture = TempIdentityDir::new(100, 50);
        let path = fixture.path().to_path_buf();
        assert!(fixture.load().is_ok());
        assert!(path.join("agent_id").is_file());
        path
    };
    assert!(!path.exists());
}

#[test]
fn kept_temp_agent_dir_survives_drop() {
    let path = TempIdentityDir::new(100, 50).keep();
    assert!(
        path.join("agent_id").is_file(),
        "keep() disables the cleanup"
    );
    std::fs::remove_dir_all(&path).unwrap();
}
