cfg_if::cfg_if! {
    if #[cfg(feature = "native")] {
        mod native;

        pub(crate) use native::Barretenberg;
    } else {
        mod wasm;

        pub(crate) use wasm::Barretenberg;
    }
}
