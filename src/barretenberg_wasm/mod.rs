///  Import the Barretenberg WASM file
pub static WASM: &[u8] = include_bytes!("barretenberg.wasm");

pub mod instance;
pub mod pedersen;
pub mod scalar_mul;
pub mod schnorr;

use once_cell::sync::Lazy;
use std::sync::Mutex;
use wasmer::{imports, Function, FunctionType, Instance, Module, Store, Type, Value};

/// Barretenberg is the low level struct which calls the WASM file
/// This is the bridge between Rust and the WASM which itself is a bridge to the C++ codebase.
pub struct Barretenberg {
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

pub static BARRETENBERG: Lazy<Mutex<Barretenberg>> = Lazy::new(|| Mutex::new(Barretenberg::new()));

impl Barretenberg {
    /// Transfer bytes to WASM heap
    pub fn transfer_to_heap(&mut self, arr: &[u8], offset: usize) {
        let memory = self.instance.exports.get_memory("memory").unwrap();
        for (byte_id, cell) in memory.view::<u8>()[offset..(offset + arr.len())]
            .iter()
            .enumerate()
        {
            cell.set(arr[byte_id]);
        }
    }
    // XXX: change to read_mem
    pub fn slice_memory(&self, start: usize, end: usize) -> Vec<u8> {
        let memory = self.instance.exports.get_memory("memory").unwrap();

        let mut result = Vec::new();

        for cell in memory.view()[start as usize..end].iter() {
            result.push(cell.get());
        }

        result
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
    #[cfg(all(not(feature = "wasm"), feature = "sys"))]
    let store = Store::default();
    #[cfg(feature = "wasm")]
    let store = Store::new();

    let module = Module::new(&store, &WASM).unwrap();
    (module, store)
}

fn instance_load() -> Instance {
    let (module, store) = load_module();

    let log_env = Function::new_native_with_env(
        &store,
        Env {
            memory: wasmer::LazyInit::new(),
        },
        logstr,
    );
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

    let custom_imports = imports! {
        "env" => {
            "logstr" => log_env,
        },
        "wasi_snapshot_preview1" => {
            "clock_time_get" => clock_time_get,
            "fd_read" => fd_read,
            "fd_close" => fd_close,
            "proc_exit" => proc_exit,
            "fd_fdstat_get" => fd_fdstat_get,
            "random_get" => random_get,
            "fd_seek" => fd_seek,
            "fd_write" => fd_write,
            "environ_sizes_get" => environ_sizes_get,
            "environ_get" => environ_get,
        }
    };

    // let res_import = import_object.chain_back(custom_imports);
    let res_import = custom_imports;
    Instance::new(&module, &res_import).unwrap()
}

impl Barretenberg {
    pub fn new() -> Barretenberg {
        Barretenberg {
            instance: instance_load(),
        }
    }
}

fn logstr(my_env: &Env, ptr: i32) {
    use std::cell::Cell;
    let memory = my_env.memory.get_ref().unwrap();

    let mut ptr_end = 0;
    for (i, cell) in memory.view::<u8>()[ptr as usize..].iter().enumerate() {
        if cell.get() != 0 {
            ptr_end = i;
        } else {
            break;
        }
    }

    let str_vec: Vec<_> = memory.view()[ptr as usize..=(ptr + ptr_end as i32) as usize]
        .iter()
        .map(|cell: &Cell<u8>| cell.get())
        .collect();

    // Convert the subslice to a `&str`.
    let string = std::str::from_utf8(&str_vec).unwrap();

    // Print it!
    println!("[WASM LOG] {}", string);
}

#[derive(Clone)]
pub struct Env {
    memory: wasmer::LazyInit<wasmer::Memory>,
}

impl wasmer::WasmerEnv for Env {
    fn init_with_instance(&mut self, instance: &Instance) -> Result<(), wasmer::HostEnvInitError> {
        let memory = instance.exports.get_memory("memory").unwrap();
        self.memory.initialize(memory.clone());
        Ok(())
    }
}

#[test]
fn foo() {
    let mut b = Barretenberg::new();
    let (x, y) = b.encrypt(vec![acvm::FieldElement::zero(), acvm::FieldElement::one()]);
    dbg!(x.to_hex(), y.to_hex());
}