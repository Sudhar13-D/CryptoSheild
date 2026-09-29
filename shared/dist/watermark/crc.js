/**
 * CRC16-CCITT implementation (polynomial 0x1021, init 0xFFFF).
 */
export function crc16(data) {
    let crc = 0xffff;
    for (let i = 0; i < data.length; i++) {
        crc ^= data[i] << 8;
        for (let j = 0; j < 8; j++) {
            if ((crc & 0x8000) !== 0) {
                crc = ((crc << 1) ^ 0x1021) & 0xffff;
            }
            else {
                crc = (crc << 1) & 0xffff;
            }
        }
    }
    return crc;
}
export function appendCrc16(payload) {
    const crc = crc16(payload);
    const result = new Uint8Array(payload.length + 2);
    result.set(payload, 0);
    result[payload.length] = (crc >> 8) & 0xff;
    result[payload.length + 1] = crc & 0xff;
    return result;
}
export function verifyAndStripCrc16(dataWithCrc) {
    if (dataWithCrc.length < 3) {
        return { valid: false, payload: new Uint8Array(0) };
    }
    const payload = dataWithCrc.slice(0, dataWithCrc.length - 2);
    const expectedCrc = (dataWithCrc[dataWithCrc.length - 2] << 8) | dataWithCrc[dataWithCrc.length - 1];
    const actualCrc = crc16(payload);
    return {
        valid: actualCrc === expectedCrc,
        payload,
    };
}
