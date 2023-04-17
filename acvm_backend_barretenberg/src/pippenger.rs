cfg_if::cfg_if! {
    if #[cfg(feature = "native")] {
        pub(crate) struct Pippenger {
            pippenger_ptr: *mut std::os::raw::c_void,
        }

        impl Pippenger {
            pub(crate) fn new(crs_data: &[u8]) -> Pippenger {
                let pippenger_ptr = barretenberg_sys::pippenger::new(crs_data);
                Pippenger { pippenger_ptr }
            }

            pub(crate) fn pointer(&self) -> *mut std::os::raw::c_void {
                self.pippenger_ptr
            }
        }
    } else {
        use super::Barretenberg;
        use wasmer::Value;

        pub(crate) struct Pippenger {
            pippenger_ptr: Value,
        }

        impl Pippenger {
            pub(crate) fn new(crs_data: &[u8], barretenberg: &mut Barretenberg) -> Pippenger {
                let num_points = Value::I32((crs_data.len() / 64) as i32);

                let crs_ptr = barretenberg.allocate(crs_data);

                let pippenger_ptr = barretenberg
                    .call_multiple("new_pippenger", vec![&crs_ptr, &num_points])
                    .value();

                barretenberg.free(crs_ptr);

                Pippenger { pippenger_ptr }
            }

            pub(crate) fn pointer(&self) -> Value {
                self.pippenger_ptr.clone()
            }
        }
    }
}
