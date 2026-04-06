fn main() {
    // UniFFI proc-macro подход не требует UDL-файла.
    // build.rs нужен только если захочешь переключиться на UDL-режим:
    //   uniffi::generate_scaffolding("./src/plex.udl").unwrap();
    //
    // Сейчас мы используем #[uniffi::export] + uniffi::setup_scaffolding!().
}
