#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

// `acvm-backend-barretenberg` can either interact with the Barretenberg backend through a static library
// or through an embedded wasm binary. It does not make sense to include both of these backends at the same time.
// We then throw a compilation error if both flags are set.
// TODO: handle JS target.
#[cfg(all(feature = "native", feature = "wasm"))]
compile_error!("feature \"native\" and feature \"wasm\" cannot be enabled at the same time");

mod acvm_interop;
mod barretenberg_structures;
mod composer;
#[cfg(any(feature = "native", feature = "wasm"))]
mod crs;
#[cfg(test)]
mod merkle;
mod pedersen;
mod pippenger;
mod scalar_mul;
mod schnorr;

use acvm::acir::BlackBoxFunc;
use thiserror::Error;

#[cfg(feature = "native")]
#[derive(Debug, Error)]
enum FeatureError {
    #[error("Could not slice field element")]
    FieldElementSlice {
        source: std::array::TryFromSliceError,
    },
    #[error("Expected a Vec of length {0} but it was {1}")]
    FieldToArray(usize, usize),
}

#[cfg(not(feature = "native"))]
#[derive(Debug, Error)]
enum FeatureError {
    #[error("Trying to call {name} resulted in an error")]
    FunctionCallFailed {
        name: String,
        source: wasmer::RuntimeError,
    },
    #[error("Could not find function export named {name}")]
    InvalidExport {
        name: String,
        source: wasmer::ExportError,
    },
    #[error("No value available when value was expected")]
    NoValue,
    #[error("Value expected to be i32")]
    InvalidI32,
    #[error("Could not convert value {value} from i32 to u32")]
    InvalidU32 {
        value: i32,
        source: std::num::TryFromIntError,
    },
    #[error("Could not convert value {value} from i32 to usize")]
    InvalidUsize {
        value: i32,
        source: std::num::TryFromIntError,
    },
    #[error("Value expected to be 0 or 1 representing a boolean")]
    InvalidBool,
}

#[derive(Debug, Error)]
enum Error {
    #[error("The value {0} overflows in the pow2ceil function")]
    Pow2CeilOverflow(u32),

    #[error("Malformed Black Box Function: {0} - {1}")]
    MalformedBlackBoxFunc(BlackBoxFunc, String),

    #[error("Unsupported Black Box Function: {0}")]
    UnsupportedBlackBoxFunc(BlackBoxFunc),

    #[error(transparent)]
    FromFeature(#[from] FeatureError),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct BackendError(#[from] Error);

impl From<FeatureError> for BackendError {
    fn from(value: FeatureError) -> Self {
        value.into()
    }
}

/// The number of bytes necessary to store a `FieldElement`.
const FIELD_BYTES: usize = 32;

#[derive(Debug)]
pub struct Barretenberg {
    #[cfg(feature = "wasm")]
    store: std::cell::RefCell<wasmer::Store>,
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
fn smoke() -> Result<(), Error> {
    use crate::pedersen::Pedersen;

    let b = Barretenberg::new();
    let (x, y) = b.encrypt(vec![acvm::FieldElement::zero(), acvm::FieldElement::one()])?;
    dbg!(x.to_hex(), y.to_hex());
    Ok(())
}

#[cfg(feature = "native")]
mod native {
    use super::{Barretenberg, Error, FeatureError};

    impl Barretenberg {
        pub(crate) fn new() -> Barretenberg {
            Barretenberg {}
        }
    }

    pub(super) fn field_to_array(f: &acvm::FieldElement) -> Result<[u8; 32], Error> {
        let v = f.to_be_bytes();
        let result: [u8; 32] = v
            .try_into()
            .map_err(|v: Vec<u8>| FeatureError::FieldToArray(32, v.len()))?;
        Ok(result)
    }
}

#[cfg(not(feature = "native"))]
mod wasm {
    use std::cell::RefCell;
    use wasmer::{
        Function, FunctionEnv, FunctionEnvMut, Instance, Memory, MemoryType, Module,
        Store, Value, WasmPtr,
    };
    use wasmer_wasix::WasiEnv;

    use super::{Barretenberg, Error, FeatureError};

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
            env_logger::init();
            let (instance, memory, store) = instance_load();
            Barretenberg {
                memory,
                instance,
                store: RefCell::new(store),
            }
        }
    }

    #[derive(Clone)]
    struct Env {
        memory: Memory,
    }

    /// A wrapper around the arguments or return value from a WASM call.
    /// Notice, `Option<Value>` is used because not every call returns a value,
    /// some calls are simply made to free a pointer or manipulate the heap.
    #[derive(Debug, Clone)]
    pub(super) struct WASMValue(Option<Value>);

    impl From<usize> for WASMValue {
        fn from(value: usize) -> Self {
            WASMValue(Some(Value::I32(value as i32)))
        }
    }

    impl From<i32> for WASMValue {
        fn from(value: i32) -> Self {
            WASMValue(Some(Value::I32(value)))
        }
    }

    impl From<Value> for WASMValue {
        fn from(value: Value) -> Self {
            WASMValue(Some(value))
        }
    }

    impl TryFrom<WASMValue> for bool {
        type Error = FeatureError;

        fn try_from(value: WASMValue) -> Result<Self, Self::Error> {
            match value.try_into()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(FeatureError::InvalidBool),
            }
        }
    }

    impl TryFrom<WASMValue> for usize {
        type Error = FeatureError;

        fn try_from(value: WASMValue) -> Result<Self, Self::Error> {
            let value: i32 = value.try_into()?;
            value
                .try_into()
                .map_err(|source| FeatureError::InvalidUsize { value, source })
        }
    }

    impl TryFrom<WASMValue> for u32 {
        type Error = FeatureError;

        fn try_from(value: WASMValue) -> Result<Self, Self::Error> {
            let value = value.try_into()?;
            u32::try_from(value).map_err(|source| FeatureError::InvalidU32 { value, source })
        }
    }

    impl TryFrom<WASMValue> for i32 {
        type Error = FeatureError;

        fn try_from(value: WASMValue) -> Result<Self, Self::Error> {
            value.0.map_or(Err(FeatureError::NoValue), |val| {
                val.i32().ok_or(FeatureError::InvalidI32)
            })
        }
    }

    impl TryFrom<WASMValue> for Value {
        type Error = FeatureError;

        fn try_from(value: WASMValue) -> Result<Self, Self::Error> {
            value.0.ok_or(FeatureError::NoValue)
        }
    }

    impl Barretenberg {
        /// Transfer bytes to WASM heap
        pub(super) fn transfer_to_heap(
            &self,
            data: &[u8],
            offset: usize,
        ) {
            let memory = &self.memory;
            let store = self.store.borrow();
            let memory_view = memory.view(&store);

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
                match memory_view.write(offset as u64, data) {
                    Ok(_) => {},
                    Err(_) => print!("Could not write to Wasm Memory"),
                };
            }
        }

        // TODO: Consider making this Result-returning
        pub(super) fn read_memory<const SIZE: usize>(&self, start: usize) -> [u8; SIZE] {
            // println!("read memory call");
            self.read_memory_variable_length(start, SIZE)
                .try_into()
                .expect("Read memory should be of the specified length")
        }

        pub(super) fn read_memory_variable_length(&self, offset: usize, length: usize) -> Vec<u8> {
            // println!("read_memory_variable_length call...");
            let memory = &self.memory;
            let store = &self.store.borrow();
            let memory_view = memory.view(&store);

            // let end = start + length;
            let mut buf = vec![0; length]; //Vec::with_capacity(length).as_mut_slice();

            #[cfg(feature = "js")]
            return memory.uint8view().to_vec()[start..end].to_vec();

            #[cfg(not(feature = "js"))]
            memory_view.read(offset as u64, &mut buf).unwrap();
            buf.to_vec()
            // return memory.view()[start..end]
            //     .iter()
            //     .map(|cell: &Cell<u8>| cell.get())
            //     .collect();
        }

        pub(super) fn get_pointer(&self, ptr_ptr: usize) -> usize {
            let ptr: [u8; POINTER_BYTES] = self.read_memory(ptr_ptr);
            u32::from_le_bytes(ptr) as usize
        }

        pub(super) fn call(&self, name: &str, param: &WASMValue) -> Result<WASMValue, Error> {
            self.call_multiple(name, vec![param])
        }

        pub(super) fn call_multiple(
            &self,
            name: &str,
            params: Vec<&WASMValue>,
        ) -> Result<WASMValue, Error> {
            // println!("\ncall_multiple (\n{}\n{:?})\n", name, params);
            // We take in a reference to values, since they do not implement Copy.
            // We then clone them inside of this function, so that the API does not have a bunch of Clones everywhere

            let mut args: Vec<Value> = vec![];
            for param in params.into_iter().cloned() {
                args.push(param.try_into()?)
            }
            let func = self.instance.exports.get_function(name).map_err(|source| {
                FeatureError::InvalidExport {
                    name: name.to_string(),
                    source,
                }
            })?;
            let boxed_value = func
                .call(&mut self.store.borrow_mut(), &args)
                .map_err(|source| FeatureError::FunctionCallFailed {
                    name: name.to_string(),
                    source,
                })?;
            let option_value = boxed_value.first().cloned();

            Ok(WASMValue(option_value))
        }

        /// Creates a pointer and allocates the bytes that the pointer references to, to the heap
        pub(super) fn allocate(&self, bytes: &[u8]) -> Result<WASMValue, Error> {
            // println!("allocate called...");
            let ptr: i32 = self.call("bbmalloc", &bytes.len().into())?.try_into()?;

            let i32_bytes = ptr.to_be_bytes();
            let u32_bytes = u32::from_be_bytes(i32_bytes);

            self.transfer_to_heap(bytes, u32_bytes as usize);
            Ok(ptr.into())
        }

        /// Frees a pointer.
        /// Notice we consume the Value, if you clone the value before passing it to free
        /// It most likely is a bug
        pub(super) fn free(&self, pointer: WASMValue) -> Result<(), Error> {
            self.call("bbfree", &pointer)?;
            Ok(())
        }
    }

    fn load_module() -> (Module, Store) {
        let store = Store::default();

        let embedded_barretenberg_wasm = Wasm::get("barretenberg.wasm").unwrap();
        let module = Module::new(&store, embedded_barretenberg_wasm.data).unwrap();
        (module, store)
    }

    fn instance_load() -> (Instance, Memory, Store) {
        let (module, mut store) = load_module();

        let mem_type = MemoryType::new(130, Some(65536), false);
        let memory = Memory::new(&mut store, mem_type).unwrap();

        let log_str_env = &FunctionEnv::new(
            &mut store,
            Env {
                memory: memory.clone(),
            },
        );

        // let random_get_env = &FunctionEnv::new(
        //     &mut store,
        //     Env {
        //         memory: memory.clone(),
        //     },
        // );

        // let custom_imports = imports! {
        //     "env" => {
        //         "logstr" => Function::new_typed_with_env(
        //             &mut store,
        //             log_str_env,
        //             // Env {
        //             //     memory: memory.clone(),
        //             // },
        //             logstr,
        //         ),
        //         "set_data" => Function::new_typed(&mut store, set_data),
        //         "get_data" => Function::new_typed(&mut store, get_data),
        //         "env_load_verifier_crs" => Function::new_typed(&mut store, env_load_verifier_crs),
        //         "env_load_prover_crs" => Function::new_typed(&mut store, env_load_prover_crs),
        //         "memory" => memory.clone(),
        //         "env_hardware_concurrency" => Function::new_typed(&mut store, env_hardware_concurrency),
        //     },
        //     "wasi_snapshot_preview1" => {
        //         "fd_read" => Function::new_typed(&mut store, fd_read),
        //         "fd_close" => Function::new_typed(&mut store, fd_close),
        //         "proc_exit" =>  Function::new_typed(&mut store, proc_exit),
        //         "fd_fdstat_get" => Function::new_typed(&mut store, fd_fdstat_get),
        //         "random_get" => Function::new_typed_with_env(
        //             &mut store,
        //             random_get_env,
        //             // Env {
        //             //     memory: memory.clone(),
        //             // },
        //             random_get
        //         ),
        //         "fd_seek" => Function::new_typed(&mut store, fd_seek),
        //         "fd_write" => Function::new_typed(&mut store, fd_write),
        //         "environ_sizes_get" => Function::new_typed(&mut store, environ_sizes_get),
        //         "environ_get" => Function::new_typed(&mut store, environ_get),
        //         "clock_time_get" => Function::new_typed(&mut store, clock_time_get),
        //     },
        //     "wasi" => {
        //         "thread-spawn" => Function::new_typed(&mut store, thread_spawn),
        //     },
        // };

        let mut wasi_env = WasiEnv::builder("barretenberg").finalize(&mut store).unwrap();

        let mut import_object = wasi_env.import_object_for_all_wasi_versions(&mut store, &module).unwrap();

        import_object.define("env", "memory", memory.clone());
        // import_object.define("wasi", "memory", memory.clone());
        // import_object.define("wasi_snapshot_preview1", "memory", memory.clone());
        import_object.define("env", "logstr", Function::new_typed_with_env(
            &mut store,
            log_str_env,
            logstr,
        ));

        import_object.define("env", "set_data", Function::new_typed(&mut store, set_data));
        import_object.define("env", "get_data", Function::new_typed(&mut store, get_data));
        import_object.define("env", "env_load_verifier_crs", Function::new_typed(&mut store, env_load_verifier_crs));
        import_object.define("env", "env_load_prover_crs", Function::new_typed(&mut store, env_load_prover_crs));
        import_object.define("env", "env_hardware_concurrency", Function::new_typed(&mut store, env_hardware_concurrency));

        
        // TODO: investigate  why wasmer detects `wasi_snapshot_preview1` namespace when wasm binary expects `wasi` namespace  
        // let _thread_spawn_extern = import_object.get_export("wasi_snapshot_preview1", "thread-spawn").unwrap();
        // import_object.define("wasi", "thread-spawn", _thread_spawn_extern);


        // println!("\n\n <<DEBUG: Provided ImportObject's: ");
        // for ns in import_object.into_iter() {
        //     println!("{:?}", ns);
        // }
        // println!("DEBUG End>>\n");

        let instance =
            Instance::new(&mut store, &module, &import_object).unwrap();
        
        wasi_env.initialize_with_memory(&mut store, instance.clone(), Some(memory.clone())).unwrap();
        // {
        //     Ok(_) => (),
        //     Err(err) => panic!("Could not initialize WASI Environmnet: {}", err),
        // };

        // let start = instance.exports.get_function("_initialize").unwrap();
        // match start.call(&mut store, &[]) {
        //     Ok(_) => (),
        //     Err(err) => println!("Could not start WASM instance: {}", err),
        // };

        (   
            instance, 
            memory,
            store,
        )
    }

    fn logstr(mut _env: FunctionEnvMut<Env>, ptr: i32) {
        // print!("logstr call...");
        // let mut ptr_end = 0;
        let (env, store) = _env.data_and_store_mut();
        let memory_view = env.memory.view(&store);

        // let byte_view = _env.memory.uint8view();

        // for (i, cell) in byte_view[ptr as usize..].iter().enumerate() {
        //     if cell != &Cell::new(0) {
        //         ptr_end = i;
        //     } else {
        //         break;
        //     }
        // }

        // let str_vec: Vec<_> = byte_view[ptr as usize..=(ptr + ptr_end as i32) as usize]
        //     .iter()
        //     .cloned()
        //     .map(|chr| chr.get())
        //     .collect();
        let log_str_wasm_ptr: WasmPtr<u8, wasmer::Memory32> = WasmPtr::new(ptr as u32);

        match log_str_wasm_ptr.read_utf8_string_with_nul(&memory_view) {
            Ok(log_string) => println!("logstr: {log_string}"),
            Err(err) => println!("Error while reading log string from memory {}", err),
        };

        // memory_view.
        // Convert the subslice to a `&str`.
        // let string = std::str::from_utf8(&str_vec).unwrap();

        // Print it!
    }

    // Based on https://github.com/wasmerio/wasmer/blob/2.3.0/lib/wasi/src/syscalls/mod.rs#L2537
    // fn random_get(mut _env: FunctionEnvMut<Env>, buf_ptr: i32, buf_len: i32) -> i32 {
    //     let mut u8_buffer = vec![0; buf_len as usize];
    //     let res = getrandom::getrandom(&mut u8_buffer);
    //     match res {
    //         Ok(()) => {
    //             let (env, store) = _env.data_and_store_mut();
    //             let memory_view = env.memory.view(&store);
    //             match memory_view.write(buf_ptr as u64, u8_buffer.as_mut_slice()) {
    //                 Ok(_) => {
    //                     println!("RandomNumber successfully written to Wasm Memory");
    //                     0_i32 // __WASI_ESUCCESS
    //                 }
    //                 Err(err) => {
    //                     println!("RandomNumber write to Wasm Memory failed: {}", err);
    //                     29_i32 // __WASI_EIO
    //                 }
    //             };
    //             // unsafe {
    //             //     env.memory
    //             //         .uint8view()
    //             //         .subarray(buf as u32, buf as u32 + buf_len as u32)
    //             //         .copy_from(&u8_buffer);
    //             // }
    //             0_i32 // __WASI_ESUCCESS
    //         }
    //         Err(err) => {
    //             println!("Failed to get RandomNumber: {}", err);
    //             29_i32 // __WASI_EIO
    //         }
    //     }
    // }

    fn env_hardware_concurrency() -> i32 {
        return 4;
    }

    // fn clock_time_get(_:i32, _:i64, _:i32) -> i32 {
    //     unimplemented!("proc_exit: clock_time_get is not implemented")
    // }

    // fn thread_spawn(_:i32) -> i32 {
    //     unimplemented!("proc_exit: thread_spawn is not implemented")
    // }

    // fn proc_exit(_: i32) {
    //     unimplemented!("proc_exit is not implemented")
    // }

    // fn fd_write(_: i32, _: i32, _: i32, _: i32) -> i32 {
    //     unimplemented!("fd_write is not implemented")
    // }

    // fn fd_seek(_: i32, _: i64, _: i32, _: i32) -> i32 {
    //     unimplemented!("fd_seek is not implemented")
    // }

    // fn fd_read(_: i32, _: i32, _: i32, _: i32) -> i32 {
    //     unimplemented!("fd_read is not implemented")
    // }

    // fn fd_fdstat_get(_: i32, _: i32) -> i32 {
    //     unimplemented!("fd_fdstat_get is not implemented")
    // }

    // fn fd_close(_: i32) -> i32 {
    //     unimplemented!("fd_close is not implemented")
    // }

    // fn environ_sizes_get(_: i32, _: i32) -> i32 {
    //     unimplemented!("environ_sizes_get is not implemented")
    // }

    // fn environ_get(_: i32, _: i32) -> i32 {
    //     unimplemented!("environ_get is not implemented")
    // }

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


// running 23 tests
// test acvm_interop::pwg::merkle::tests::simple_shield ... ok
// test acvm_interop::pwg::merkle::tests::test_check_membership ... ok
// test acvm_interop::smart_contract::test_smart_contract ... FAILED
// test barretenberg_structures::tests::serialize_expression ... ok
// test composer::test::test_a_single_constraint_no_pub_inputs ... FAILED
// test composer::test::test_a_single_constraint_with_pub_inputs ... FAILED
// test composer::test::test_compute_merkle_root_constraint ... FAILED
// test composer::test::test_keccak256_constraint ... FAILED
// test composer::test::test_logic_constraints ... FAILED
// test composer::test::test_memory_constraints ... FAILED
// test composer::test::test_multiple_constraints ... FAILED
// test composer::test::test_no_constraints_no_pub_inputs ... FAILED
// test composer::test::test_ped_constraints ... FAILED
// test composer::test::test_schnorr_constraints ... FAILED
// test crs::downloading ... ignored
// test merkle::basic_interop_hashpath ... ok
// test merkle::basic_interop_initial_root ... ok
// test merkle::basic_interop_update ... ok
// test pedersen::basic_interop ... ok
// test pedersen::pedersen_hash_to_point ... ok
// test scalar_mul::test::smoke_test ... FAILED
// test schnorr::basic_interop ... FAILED
// test smoke ... ok