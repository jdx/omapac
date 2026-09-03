//! The pickers refuse to open without a terminal, and the commands that
//! grow `--pick` still validate their arguments.

mod common;

use common::Rig;

#[test]
fn pickers_need_a_terminal() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["search", "--pick", "pacman"], "", 0);
    assert_ne!(code, 0);
    assert!(err.contains("search --pick needs a terminal"), "{err}");
    let (code, _, err) = rig.run(&["remove", "--pick"], "", 0);
    assert_ne!(code, 0);
    assert!(err.contains("remove --pick needs a terminal"), "{err}");
    let (code, _, err) = rig.run(&["remove"], "", 0);
    assert_ne!(code, 0);
    assert!(err.contains("give package names, or --pick"), "{err}");
    assert!(rig.log().is_empty(), "no pacman calls: {:?}", rig.log());
}
