fn main() {
    // Use Slint's cross-platform Fluent widgets so Fedora's native/Qt palette
    // cannot produce unreadable unfocused fields in a light or dark desktop.
    // Build scripts run in a single-threaded process here, before Slint reads
    // the style, so changing this process-local variable is safe.
    unsafe { std::env::set_var("SLINT_STYLE", "fluent"); }
    slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");
}
