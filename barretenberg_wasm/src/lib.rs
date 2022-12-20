///  Import the Barretenberg WASM file
pub static WASM: &[u8] = include_bytes!("barretenberg.wasm");

pub mod acvm_interop;
pub use acvm_interop::Plonk;
pub use common::acvm::{Backend, PartialWitnessGenerator, ProofSystemCompiler};
pub mod blake2s;
pub mod composer;
pub mod pedersen;
pub mod pippenger;
pub mod scalar_mul;
pub mod schnorr;

pub use common::crs;
use std::cell::Cell;
use wasmer::{
    imports, Function, FunctionType, Instance, Memory, MemoryType, Module, Store, Type, Value,
};

/// Barretenberg is the low level struct which calls the WASM file
/// This is the bridge between Rust and the WASM which itself is a bridge to the C++ codebase.
pub struct Barretenberg {
    memory: Memory,
    instance: Instance,
}

/// A wrapper around the return value from a WASM call
/// Notice, Option<> is used because not every call returns a value
/// Some calls are simply made to free a pointer for example
/// Or manipulate the heap
#[derive(Debug)]
pub struct WASMValue(Option<Value>);

impl WASMValue {
    pub fn value(self) -> Value {
        self.0.unwrap()
    }
    pub fn into_i32(self) -> i32 {
        i32::try_from(self.0.unwrap()).expect("expected an i32 value")
    }
}

impl Barretenberg {
    /// Transfer bytes to WASM heap
    pub fn transfer_to_heap(&mut self, arr: &[u8], offset: usize) {
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
    pub fn slice_memory(&self, start: usize, end: usize) -> Vec<u8> {
        let memory = &self.memory;

        #[cfg(feature = "js")]
        return memory.uint8view().to_vec()[start as usize..end].to_vec();

        #[cfg(not(feature = "js"))]
        return memory.view()[start..end]
            .iter()
            .map(|cell: &Cell<u8>| cell.get())
            .collect();
    }

    pub fn call(&self, name: &str, param: &Value) -> WASMValue {
        self.call_multiple(name, vec![param])
    }
    pub fn call_multiple(&self, name: &str, params: Vec<&Value>) -> WASMValue {
        // We take in a reference to values, since they do not implement Copy.
        // We then clone them inside of this function, so that the API does not have a bunch of Clones everywhere

        let params: Vec<_> = params.into_iter().cloned().collect();
        let func = self.instance.exports.get_function(name).unwrap();
        let option_value = func.call(&params).unwrap().first().cloned();

        WASMValue(option_value)
    }

    /// Creates a pointer and allocates the bytes that the pointer references to, to the heap
    pub fn allocate(&mut self, bytes: &[u8]) -> Value {
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
    pub fn free(&mut self, pointer: Value) {
        self.call("bbfree", &pointer);
    }
}

impl Default for Barretenberg {
    fn default() -> Self {
        Self::new()
    }
}

fn load_module() -> (Module, Store) {
    let store = Store::default();

    let module = Module::new(&store, WASM).unwrap();
    (module, store)
}

fn instance_load() -> (Instance, Memory) {
    let (module, store) = load_module();

    let log_env = Function::new_native(&store, logstr);
    // Add all of the wasi host functions.
    // We don't use any of them, so they have dummy implementations.
    let signature = FunctionType::new(vec![Type::I32, Type::I64, Type::I32], vec![Type::I32]);
    let clock_time_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(
        vec![Type::I32, Type::I32, Type::I32, Type::I32],
        vec![Type::I32],
    );
    let fd_read = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32], vec![Type::I32]);
    let fd_close = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32], vec![]);
    let proc_exit = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let fd_fdstat_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let random_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(
        vec![Type::I32, Type::I64, Type::I32, Type::I32],
        vec![Type::I32],
    );
    let fd_seek = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(
        vec![Type::I32, Type::I32, Type::I32, Type::I32],
        vec![Type::I32],
    );
    let fd_write = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let environ_sizes_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let environ_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(
        vec![
            Type::I32,
            Type::I32,
            Type::I32,
            Type::I32,
            Type::I32,
            Type::I64,
            Type::I64,
            Type::I32,
            Type::I32,
        ],
        vec![Type::I32],
    );
    let path_open = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(
        vec![Type::I32, Type::I32, Type::I32, Type::I32, Type::I32],
        vec![Type::I32],
    );
    let path_filestat_get = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let fd_fdstat_set_flags = Function::new(&store, &signature, |_| Ok(vec![Value::I32(0)]));

    let mem_type = MemoryType::new(130, None, false);
    let memory = Memory::new(&store, mem_type).unwrap();

    let custom_imports = imports! {
        "env" => {
            "logstr" => log_env,
            "memory" => memory.clone(),
        },
        "wasi_snapshot_preview1" => {
            "clock_time_get" => clock_time_get,
            "fd_read" => fd_read,
            "fd_close" => fd_close,
            "proc_exit" => proc_exit,
            "fd_fdstat_get" => fd_fdstat_get,
            "path_filestat_get" => path_filestat_get,
            "fd_fdstat_set_flags" => fd_fdstat_set_flags,
            "random_get" => random_get,
            "fd_seek" => fd_seek,
            "path_open" => path_open,
            "fd_write" => fd_write,
            "environ_sizes_get" => environ_sizes_get,
            "environ_get" => environ_get,
        },
    };

    // let res_import = import_object.chain_back(custom_imports);
    let res_import = custom_imports;
    (Instance::new(&module, &res_import).unwrap(), memory)
}

impl Barretenberg {
    pub fn new() -> Barretenberg {
        let (instance, memory) = instance_load();
        Barretenberg { memory, instance }
    }
}
#[allow(unused_variables)]
fn logstr(ptr: i32) {
    // println!("[No logs]")
    // let memory = my_env.memory.get_ref().unwrap();

    // let mut ptr_end = 0;
    // let byte_view = memory.uint8view();

    // for (i, cell) in byte_view[ptr as usize..].iter().enumerate() {
    //     if cell != 0 {
    //         ptr_end = i;
    //     } else {
    //         break;
    //     }
    // }

    // let str_vec: Vec<_> = byte_view[ptr as usize..=(ptr + ptr_end as i32) as usize]
    //     .into_iter()
    //     .cloned()
    //     .collect();

    // // Convert the subslice to a `&str`.
    // let string = std::str::from_utf8(&str_vec).unwrap();

    // // Print it!
    // println!("[WASM LOG] {}", string);
}

#[test]
fn smoke() {
    let mut b = Barretenberg::new();
    let (x, y) = b.encrypt(vec![
        common::acvm::FieldElement::zero(),
        common::acvm::FieldElement::one(),
    ]);
    dbg!(x.to_hex(), y.to_hex());
}
