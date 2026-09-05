use pacvamp::aur::environment::{new_root, validate_packages};
#[test]
fn provisioning_rejects_existing_roots_and_option_injection() {
    let dir = tempfile::tempdir().unwrap();
    assert!(new_root(dir.path()).is_err());
    assert!(new_root(std::path::Path::new("/")).is_err());
    assert!(new_root(&dir.path().join("../escape")).is_err());
    assert!(new_root(&dir.path().join("new")).is_ok());
    for name in ["--config=/tmp/config", "core/foo bar", "", "foo\nbar"] {
        assert!(validate_packages(&[name.into()]).is_err());
    }
    validate_packages(&["core/gcc".into(), "libfoo++".into()]).unwrap();
}
