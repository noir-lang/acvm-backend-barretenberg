let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;
const { TextEncoder, TextDecoder } = require(`util`);

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachedFloat64Memory0 = new Float64Array();

function getFloat64Memory0() {
    if (cachedFloat64Memory0.byteLength === 0) {
        cachedFloat64Memory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachedFloat64Memory0;
}

let cachedInt32Memory0 = new Int32Array();

function getInt32Memory0() {
    if (cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

let WASM_VECTOR_LEN = 0;

let cachedUint8Memory0 = new Uint8Array();

function getUint8Memory0() {
    if (cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {
        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            if (--state.cnt === 0) {
                wasm.__wbindgen_export_2.get(state.dtor)(a, state.b);

            } else {
                state.a = a;
            }
        }
    };
    real.original = state;

    return real;
}

let stack_pointer = 32;

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
}
function __wbg_adapter_26(arg0, arg1, arg2) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm._dyn_core__ops__function__FnMut___A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h05c93453828e8688(retptr, arg0, arg1, addBorrowedObject(arg2));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

function __wbg_adapter_29(arg0, arg1, arg2) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm._dyn_core__ops__function__FnMut___A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hca967ff60b9a40de(retptr, arg0, arg1, addBorrowedObject(arg2));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        if (r1) {
            throw takeObject(r0);
        }
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

let cachedUint32Memory0 = new Uint32Array();

function getUint32Memory0() {
    if (cachedUint32Memory0.byteLength === 0) {
        cachedUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32Memory0;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4);
    const mem = getUint32Memory0();
    for (let i = 0; i < array.length; i++) {
        mem[ptr / 4 + i] = addHeapObject(array[i]);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
* @param {any} circuit
* @param {(string)[]} initial_js_witness
* @returns {Uint8Array}
*/
module.exports.compute_witnesses = function(circuit, initial_js_witness) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArrayJsValueToWasm0(initial_js_witness, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.compute_witnesses(retptr, addHeapObject(circuit), ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
};

/**
* @param {any} acir
* @returns {Uint8Array}
*/
module.exports.serialise_acir_to_barrtenberg_circuit = function(acir) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.serialise_acir_to_barrtenberg_circuit(retptr, addHeapObject(acir));
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
};

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* @param {any} acir
* @param {Uint8Array} witness_arr
* @returns {Uint8Array}
*/
module.exports.packed_witness_to_witness = function(acir, witness_arr) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(witness_arr, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.packed_witness_to_witness(retptr, addHeapObject(acir), ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
};

/**
* @param {string} vk_method
* @returns {string}
*/
module.exports.eth_contract_from_cs = function(vk_method) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(vk_method, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.eth_contract_from_cs(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
};

/**
* @param {(string)[]} pub_inputs_js_string
* @returns {Uint8Array}
*/
module.exports.serialise_public_inputs = function(pub_inputs_js_string) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArrayJsValueToWasm0(pub_inputs_js_string, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.serialise_public_inputs(retptr, ptr0, len0);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
};

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}
/**
* A struct representing an aborted instruction execution, with a message
* indicating the cause.
*/
class WasmerRuntimeError {

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmerruntimeerror_free(ptr);
    }
}
module.exports.WasmerRuntimeError = WasmerRuntimeError;

module.exports.__wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

module.exports.__wbindgen_object_clone_ref = function(arg0) {
    const ret = getObject(arg0);
    return addHeapObject(ret);
};

module.exports.__wbindgen_number_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getFloat64Memory0()[arg0 / 8 + 1] = isLikeNone(ret) ? 0 : ret;
    getInt32Memory0()[arg0 / 4 + 0] = !isLikeNone(ret);
};

module.exports.__wbindgen_number_new = function(arg0) {
    const ret = arg0;
    return addHeapObject(ret);
};

module.exports.__wbindgen_json_serialize = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = JSON.stringify(obj === undefined ? null : obj);
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbg_new_693216e109162396 = function() {
    const ret = new Error();
    return addHeapObject(ret);
};

module.exports.__wbg_stack_0ddaca5d1abfb52f = function(arg0, arg1) {
    const ret = getObject(arg1).stack;
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbg_error_09919627ac0992f5 = function(arg0, arg1) {
    try {
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(arg0, arg1);
    }
};

module.exports.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

module.exports.__wbindgen_string_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbindgen_is_undefined = function(arg0) {
    const ret = getObject(arg0) === undefined;
    return ret;
};

module.exports.__wbg_instanceof_Global_71ffa48bd62833fb = function(arg0) {
    const ret = getObject(arg0) instanceof WebAssembly.Global;
    return ret;
};

module.exports.__wbg_get_ad41fee29b7e0f53 = function(arg0, arg1) {
    const ret = getObject(arg0)[arg1 >>> 0];
    return addHeapObject(ret);
};

module.exports.__wbg_length_a73bfd4c96dd97ef = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbg_new_ee1a3da85465d621 = function() {
    const ret = new Array();
    return addHeapObject(ret);
};

module.exports.__wbg_get_72332cd2bc57924c = function() { return handleError(function (arg0, arg1) {
    const ret = Reflect.get(getObject(arg0), getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_new_e6a9fecc2bf26696 = function() {
    const ret = new Object();
    return addHeapObject(ret);
};

module.exports.__wbg_newwithlength_df0e16f0b90b6295 = function(arg0) {
    const ret = new Array(arg0 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_set_64cc39858b2ec3f1 = function(arg0, arg1, arg2) {
    getObject(arg0)[arg1 >>> 0] = takeObject(arg2);
};

module.exports.__wbg_push_0bc7fce4a139a883 = function(arg0, arg1) {
    const ret = getObject(arg0).push(getObject(arg1));
    return ret;
};

module.exports.__wbg_instanceof_Function_209355dc9c61e243 = function(arg0) {
    const ret = getObject(arg0) instanceof Function;
    return ret;
};

module.exports.__wbg_newwithargs_97d68be691eaac2d = function(arg0, arg1, arg2, arg3) {
    const ret = new Function(getStringFromWasm0(arg0, arg1), getStringFromWasm0(arg2, arg3));
    return addHeapObject(ret);
};

module.exports.__wbg_bind_1f440a7fa661cc6e = function(arg0, arg1, arg2) {
    const ret = getObject(arg0).bind(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
};

module.exports.__wbg_name_ef3d2d249cf2458b = function(arg0) {
    const ret = getObject(arg0).name;
    return addHeapObject(ret);
};

module.exports.__wbg_constructor_49b344c0ab64de09 = function(arg0) {
    const ret = getObject(arg0).constructor;
    return addHeapObject(ret);
};

module.exports.__wbg_getPrototypeOf_d6d1f0000eddc427 = function(arg0) {
    const ret = Object.getPrototypeOf(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_buffer_34f5ec9f8a838ba0 = function(arg0) {
    const ret = getObject(arg0).buffer;
    return addHeapObject(ret);
};

module.exports.__wbg_newwithbyteoffsetandlength_88fdad741db1b182 = function(arg0, arg1, arg2) {
    const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
};

module.exports.__wbg_new_cda198d9dbc6d7ea = function(arg0) {
    const ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_set_1a930cfcda1a8067 = function(arg0, arg1, arg2) {
    getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

module.exports.__wbg_length_51f19f73d6d9eff3 = function(arg0) {
    const ret = getObject(arg0).length;
    return ret;
};

module.exports.__wbg_setindex_4756adbb17b8d274 = function(arg0, arg1, arg2) {
    getObject(arg0)[arg1 >>> 0] = arg2;
};

module.exports.__wbg_new_444e3ec65846d469 = function() { return handleError(function (arg0, arg1) {
    const ret = new WebAssembly.Instance(getObject(arg0), getObject(arg1));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_exports_e80fe8dbc3c6be2b = function(arg0) {
    const ret = getObject(arg0).exports;
    return addHeapObject(ret);
};

module.exports.__wbg_new_7ae57ee5fea65b3e = function() { return handleError(function (arg0) {
    const ret = new WebAssembly.Module(getObject(arg0));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_exports_f7e41889b96910fe = function(arg0) {
    const ret = WebAssembly.Module.exports(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_imports_bd88674ca332e5c3 = function(arg0) {
    const ret = WebAssembly.Module.imports(getObject(arg0));
    return addHeapObject(ret);
};

module.exports.__wbg_instanceof_Table_eb0b31569696af5c = function(arg0) {
    const ret = getObject(arg0) instanceof WebAssembly.Table;
    return ret;
};

module.exports.__wbg_get_4987f87cbcb53a7b = function() { return handleError(function (arg0, arg1) {
    const ret = getObject(arg0).get(arg1 >>> 0);
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_instanceof_Memory_c84c3bb5e7edc84f = function(arg0) {
    const ret = getObject(arg0) instanceof WebAssembly.Memory;
    return ret;
};

module.exports.__wbg_new_c72422ed33ac6448 = function() { return handleError(function (arg0) {
    const ret = new WebAssembly.Memory(getObject(arg0));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_apply_bd59f70527113b67 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = Reflect.apply(getObject(arg0), getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
}, arguments) };

module.exports.__wbg_set_2762e698c2f5b7e0 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = Reflect.set(getObject(arg0), getObject(arg1), getObject(arg2));
    return ret;
}, arguments) };

module.exports.__wbindgen_debug_string = function(arg0, arg1) {
    const ret = debugString(getObject(arg1));
    const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

module.exports.__wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

module.exports.__wbindgen_memory = function() {
    const ret = wasm.memory;
    return addHeapObject(ret);
};

module.exports.__wbindgen_function_table = function() {
    const ret = wasm.__wbindgen_export_2;
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper174 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 33, __wbg_adapter_26);
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper176 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 33, __wbg_adapter_29);
    return addHeapObject(ret);
};

module.exports.__wbindgen_closure_wrapper178 = function(arg0, arg1, arg2) {
    const ret = makeMutClosure(arg0, arg1, 33, __wbg_adapter_26);
    return addHeapObject(ret);
};

const path = require('path').join(__dirname, 'aztec_backend_bg.wasm');
const bytes = require('fs').readFileSync(path);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
wasm = wasmInstance.exports;
module.exports.__wasm = wasm;

