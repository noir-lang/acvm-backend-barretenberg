#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

// `acvm-backend-barretenberg` can either interact with the Barretenberg backend through a static library
// or through an embedded wasm binary. It does not make sense to include both of these backends at the same time.
// We then throw a compilation error if both flags are set.
// TODO: handle JS target.
#[cfg(all(feature = "native", feature = "wasm"))]
compile_error!("feature \"native\" and feature \"wasm\" cannot be enabled at the same time");

mod acvm_interop;
mod composer;
#[cfg(all(feature = "native", test))]
mod crs;
#[cfg(test)]
mod merkle;
mod pedersen;
mod pippenger;
mod scalar_mul;
mod schnorr;

/// The number of bytes necessary to store a `FieldElement`.
const FIELD_BYTES: usize = 32;

pub struct Barretenberg {
    #[cfg(feature = "wasm")]
    memory: wasmer::Memory,
    #[cfg(feature = "wasm")]
    instance: wasmer::Instance,
}

impl Default for Barretenberg {
    fn default() -> Barretenberg {
        Barretenberg::new()
    }
}

#[test]
fn smoke() {
    use crate::pedersen::Pedersen;

    let b = Barretenberg::new();
    let (x, y) = b.encrypt(vec![
        common::acvm::FieldElement::zero(),
        common::acvm::FieldElement::one(),
    ]);
    dbg!(x.to_hex(), y.to_hex());
}

#[cfg(feature = "native")]
mod native {
    use super::Barretenberg;

    impl Barretenberg {
        pub(crate) fn new() -> Barretenberg {
            Barretenberg {}
        }
    }

    pub(super) fn field_to_array(f: &common::acvm::FieldElement) -> [u8; 32] {
        let v = f.to_be_bytes();
        let result: [u8; 32] = v.try_into().unwrap_or_else(|v: Vec<u8>| {
            panic!("Expected a Vec of length {} but it was {}", 32, v.len())
        });
        result
    }
}

#[cfg(not(feature = "native"))]
mod wasm {
    use std::cell::Cell;
    use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, Store, Value};

    use super::Barretenberg;

    /// The number of bytes necessary to represent a pointer to memory inside the wasm.
    pub(super) const POINTER_BYTES: usize = 4;

    /// The Barretenberg WASM gives us 1024 bytes of scratch space which we can use without
    /// needing to allocate/free it ourselves. This can be useful for when we need to pass in several small variables
    /// when calling functions on the wasm, however it's important to not overrun this scratch space as otherwise
    /// the written data will begin to corrupt the stack.
    ///
    /// Using this scratch space isn't particularly safe if we have multiple threads interacting with the wasm however,
    /// each thread could write to the same pointer address simultaneously.
    pub(super) const WASM_SCRATCH_BYTES: usize = 1024;

    /// Embed the Barretenberg WASM file
    #[derive(rust_embed::RustEmbed)]
    #[folder = "$BARRETENBERG_BIN_DIR"]
    #[include = "barretenberg.wasm"]
    struct Wasm;

    impl Barretenberg {
        pub(crate) fn new() -> Barretenberg {
            let (instance, memory) = instance_load();
            Barretenberg { memory, instance }
        }
    }

    #[derive(wasmer::WasmerEnv, Clone)]
    struct Env {
        memory: Memory,
    }

    /// A wrapper around the return value from a WASM call.
    /// Notice, `Option<Value>` is used because not every call returns a value,
    /// some calls are simply made to free a pointer or manipulate the heap.
    #[derive(Debug)]
    pub(super) struct WASMValue(Option<Value>);

    impl WASMValue {
        pub(super) fn value(self) -> Value {
            self.0.unwrap()
        }
        pub(super) fn into_i32(self) -> i32 {
            i32::try_from(self.0.unwrap()).expect("expected an i32 value")
        }
    }

    impl Barretenberg {
        /// Transfer bytes to WASM heap
        pub(super) fn transfer_to_heap(&self, arr: &[u8], offset: usize) {
            let memory = &self.memory;

            #[cfg(feature = "js")]
            {
                let view: js_sys::Uint8Array = memory.uint8view();
                for (byte_id, cell_id) in (offset..(offset + arr.len())).enumerate() {
                    view.set_index(cell_id as u32, arr[byte_id])
                }
                return;
            }

            #[cfg(not(feature = "js"))]
            {
                for (byte_id, cell) in memory.uint8view()[offset..(offset + arr.len())]
                    .iter()
                    .enumerate()
                {
                    cell.set(arr[byte_id]);
                }
            }
        }

        // XXX: change to read_mem
        pub(super) fn slice_memory(&self, start: usize, length: usize) -> Vec<u8> {
            let memory = &self.memory;
            let end = start + length;

            #[cfg(feature = "js")]
            return memory.uint8view().to_vec()[start as usize..end].to_vec();

            #[cfg(not(feature = "js"))]
            return memory.view()[start..end]
                .iter()
                .map(|cell: &Cell<u8>| cell.get())
                .collect();
        }

        pub(super) fn call(&self, name: &str, param: &Value) -> WASMValue {
            self.call_multiple(name, vec![param])
        }

        pub(super) fn call_multiple(&self, name: &str, params: Vec<&Value>) -> WASMValue {
            // We take in a reference to values, since they do not implement Copy.
            // We then clone them inside of this function, so that the API does not have a bunch of Clones everywhere

            let params: Vec<_> = params.into_iter().cloned().collect();
            let func = self.instance.exports.get_function(name).unwrap();
            let option_value = func.call(&params).unwrap().first().cloned();

            WASMValue(option_value)
        }

        /// Creates a pointer and allocates the bytes that the pointer references to, to the heap
        pub(super) fn allocate(&self, bytes: &[u8]) -> Value {
            let ptr = self
                .call("bbmalloc", &Value::I32(bytes.len() as i32))
                .value();

            let i32_bytes = ptr.unwrap_i32().to_be_bytes();
            let u32_bytes = u32::from_be_bytes(i32_bytes);

            self.transfer_to_heap(bytes, u32_bytes as usize);
            ptr
        }

        /// Frees a pointer.
        /// Notice we consume the Value, if you clone the value before passing it to free
        /// It most likely is a bug
        pub(super) fn free(&self, pointer: Value) {
            self.call("bbfree", &pointer);
        }
    }

    fn load_module() -> (Module, Store) {
        let store = Store::default();

        let module = Module::new(&store, Wasm::get("barretenberg.wasm").unwrap().data).unwrap();
        (module, store)
    }

    fn instance_load() -> (Instance, Memory) {
        let (module, store) = load_module();

        let mem_type = MemoryType::new(130, None, false);
        let memory = Memory::new(&store, mem_type).unwrap();

        let custom_imports = imports! {
            "env" => {
                "logstr" => Function::new_native_with_env(
                    &store,
                    Env {
                        memory: memory.clone(),
                    },
                    logstr,
                ),
                "set_data" => Function::new_native(&store, set_data),
                "get_data" => Function::new_native(&store, get_data),
                "env_load_verifier_crs" => Function::new_native(&store, env_load_verifier_crs),
                "env_load_prover_crs" => Function::new_native(&store, env_load_prover_crs),
                "memory" => memory.clone(),
            },
            "wasi_snapshot_preview1" => {
                "fd_read" => Function::new_native(&store, fd_read),
                "fd_close" => Function::new_native(&store, fd_close),
                "proc_exit" =>  Function::new_native(&store, proc_exit),
                "fd_fdstat_get" => Function::new_native(&store, fd_fdstat_get),
                "random_get" => Function::new_native_with_env(
                    &store,
                    Env {
                        memory: memory.clone(),
                    },
                    random_get
                ),
                "fd_seek" => Function::new_native(&store, fd_seek),
                "fd_write" => Function::new_native(&store, fd_write),
                "environ_sizes_get" => Function::new_native(&store, environ_sizes_get),
                "environ_get" => Function::new_native(&store, environ_get),
            },
        };

        (Instance::new(&module, &custom_imports).unwrap(), memory)
    }

    fn logstr(env: &Env, ptr: i32) {
        let mut ptr_end = 0;
        let byte_view = env.memory.uint8view();

        for (i, cell) in byte_view[ptr as usize..].iter().enumerate() {
            if cell != &Cell::new(0) {
                ptr_end = i;
            } else {
                break;
            }
        }

        let str_vec: Vec<_> = byte_view[ptr as usize..=(ptr + ptr_end as i32) as usize]
            .iter()
            .cloned()
            .map(|chr| chr.get())
            .collect();

        // Convert the subslice to a `&str`.
        let string = std::str::from_utf8(&str_vec).unwrap();

        // Print it!
        println!("{string}");
    }

    // Based on https://github.com/wasmerio/wasmer/blob/2.3.0/lib/wasi/src/syscalls/mod.rs#L2537
    fn random_get(env: &Env, buf: i32, buf_len: i32) -> i32 {
        let mut u8_buffer = vec![0; buf_len as usize];
        let res = getrandom::getrandom(&mut u8_buffer);
        match res {
            Ok(()) => {
                unsafe {
                    env.memory
                        .uint8view()
                        .subarray(buf as u32, buf as u32 + buf_len as u32)
                        .copy_from(&u8_buffer);
                }
                0_i32 // __WASI_ESUCCESS
            }
            Err(_) => 29_i32, // __WASI_EIO
        }
    }

    fn proc_exit(_: i32) {
        unimplemented!("proc_exit is not implemented")
    }

    fn fd_write(_: i32, _: i32, _: i32, _: i32) -> i32 {
        unimplemented!("fd_write is not implemented")
    }

    fn fd_seek(_: i32, _: i64, _: i32, _: i32) -> i32 {
        unimplemented!("fd_seek is not implemented")
    }

    fn fd_read(_: i32, _: i32, _: i32, _: i32) -> i32 {
        unimplemented!("fd_read is not implemented")
    }

    fn fd_fdstat_get(_: i32, _: i32) -> i32 {
        unimplemented!("fd_fdstat_get is not implemented")
    }

    fn fd_close(_: i32) -> i32 {
        unimplemented!("fd_close is not implemented")
    }

    fn environ_sizes_get(_: i32, _: i32) -> i32 {
        unimplemented!("environ_sizes_get is not implemented")
    }

    fn environ_get(_: i32, _: i32) -> i32 {
        unimplemented!("environ_get is not implemented")
    }

    fn set_data(_: i32, _: i32, _: i32) {
        unimplemented!("set_data is not implemented")
    }

    fn get_data(_: i32, _: i32) -> i32 {
        unimplemented!("get_data is not implemented")
    }

    fn env_load_verifier_crs() -> i32 {
        unimplemented!("env_load_verifier_crs is not implemented")
    }

    fn env_load_prover_crs(_: i32) -> i32 {
        unimplemented!("env_load_prover_crs is not implemented")
    }
}
