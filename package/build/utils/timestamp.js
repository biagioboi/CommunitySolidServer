"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nowInSeconds = void 0;
// Question: Spec isn't clear about the endianness. Assumes big-endian here
// since ACA-Py uses big-endian.
function timestamp() {
    let time = Date.now();
    const bytes = [];
    for (let i = 0; i < 8; i++) {
        const byte = time & 0xff;
        bytes.push(byte);
        time = (time - byte) / 256; // Javascript right shift (>>>) only works on 32 bit integers
    }
    return Uint8Array.from(bytes).reverse();
}
exports.default = timestamp;
/**
 * Returns the current time in seconds
 */
function nowInSeconds() {
    return Math.floor(new Date().getTime() / 1000);
}
exports.nowInSeconds = nowInSeconds;
//# sourceMappingURL=timestamp.js.map