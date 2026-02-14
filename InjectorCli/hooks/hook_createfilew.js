'use strict';

function r16(p) {
  return p.isNull() ? null : p.readUtf16String();
}

const pCreateFileW = Process.getModuleByName('kernel32.dll').getExportByName('CreateFileW');

Interceptor.attach(pCreateFileW, {
  onEnter(args) {
    this.name = r16(args[0]);
    this.desiredAccess = args[1].toUInt32();
    this.shareMode = args[2].toUInt32();
    this.creationDisposition = args[4].toUInt32();
    this.flagsAndAttributes = args[5].toUInt32();

    console.log(
      `[CreateFileW] name="${this.name}" ` +
      `access=0x${this.desiredAccess.toString(16)} ` +
      `share=0x${this.shareMode.toString(16)} ` +
      `disp=0x${this.creationDisposition.toString(16)} ` +
      `flags=0x${this.flagsAndAttributes.toString(16)}`
    );
  },

  onLeave(retval) {
    console.log(`[CreateFileW] -> handle=${retval}`);
  }
});
