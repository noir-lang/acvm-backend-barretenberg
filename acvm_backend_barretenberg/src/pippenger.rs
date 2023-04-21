use crate::Barretenberg;

pub(crate) struct Pippenger {
    #[cfg(feature = "native")]
    pippenger_ptr: *mut std::os::raw::c_void,
    #[cfg(not(feature = "native"))]
    pippenger_ptr: wasmer::Value,
}

impl Barretenberg {
    pub(crate) fn get_pippenger(&self, crs_data: &[u8]) -> Pippenger {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                let pippenger_ptr = barretenberg_sys::pippenger::new(crs_data);
            } else {
                use wasmer::Value;

                let num_points = Value::I32((crs_data.len() / 64) as i32);

                let crs_ptr = self.allocate(crs_data);

                let pippenger_ptr = self
                    .call_multiple("new_pippenger", vec![&crs_ptr, &num_points])
                    .value();

                self.free(crs_ptr);
            }
        }
        Pippenger { pippenger_ptr }
    }
}

impl Pippenger {
    #[cfg(feature = "native")]
    pub(crate) fn pointer(&self) -> *mut std::os::raw::c_void {
        self.pippenger_ptr
    }

    #[cfg(not(feature = "native"))]
    pub(crate) fn pointer(&self) -> wasmer::Value {
        self.pippenger_ptr.clone()
    }
}
