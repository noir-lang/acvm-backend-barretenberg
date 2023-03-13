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
