use crate::{Barretenberg, Error};

pub(crate) struct Pippenger {
    #[cfg(not(any(feature = "wasm", target_arch = "wasm32")))]
    pippenger_ptr: *mut std::os::raw::c_void,
    #[cfg(any(feature = "wasm", target_arch = "wasm32"))]
    pippenger_ptr: crate::wasm::WASMValue,
}

#[cfg(not(any(feature = "wasm", target_arch = "wasm32")))]
impl Pippenger {
    pub(crate) fn pointer(&self) -> *mut std::os::raw::c_void {
        self.pippenger_ptr
    }
}

#[cfg(any(feature = "wasm", target_arch = "wasm32"))]
impl Pippenger {
    pub(crate) fn pointer(&self) -> crate::wasm::WASMValue {
        self.pippenger_ptr.clone()
    }
}

#[cfg(not(any(feature = "wasm", target_arch = "wasm32")))]
impl Barretenberg {
    pub(crate) fn get_pippenger(&self, crs_data: &[u8]) -> Result<Pippenger, Error> {
        let pippenger_ptr = barretenberg_sys::pippenger::new(crs_data);

        Ok(Pippenger { pippenger_ptr })
    }
}

#[cfg(any(feature = "wasm", target_arch = "wasm32"))]
impl Barretenberg {
    pub(crate) fn get_pippenger(&self, crs_data: &[u8]) -> Result<Pippenger, Error> {
        use super::FIELD_BYTES;

        let num_points = crs_data.len() / (2 * FIELD_BYTES);

        let crs_ptr = self.allocate(crs_data)?;

        // This doesn't unwrap the result because we need to free even if there is a failure
        let pippenger_ptr = self.call_multiple("new_pippenger", vec![&crs_ptr, &num_points.into()]);

        self.free(crs_ptr)?;

        Ok(Pippenger {
            pippenger_ptr: pippenger_ptr?,
        })
    }
}
