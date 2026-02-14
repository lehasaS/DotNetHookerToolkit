'use strict';

function r16(p) {
  return p.isNull() ? null : p.readUtf16String();
}

const pMessageBoxW = Process.getModuleByName('user32.dll').getExportByName('MessageBoxW');

Interceptor.attach(pMessageBoxW, {
  onEnter(args) {
    const text = r16(args[1]);
    const caption = r16(args[2]);
    const uType = args[3].toUInt32();
    const tid = Process.getCurrentThreadId();

    console.log(
      `[MessageBoxW][TID ${tid}] ` +
      `"${caption}" -> "${text}" (type=0x${uType.toString(16)})`
    );
  },

  onLeave(retval) {
    console.log(`[MessageBoxW] -> retval=${retval.toInt32()}`);
  }
});
