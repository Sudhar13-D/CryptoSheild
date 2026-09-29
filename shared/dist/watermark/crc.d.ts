/**
 * CRC16-CCITT implementation (polynomial 0x1021, init 0xFFFF).
 */
export declare function crc16(data: Uint8Array): number;
export declare function appendCrc16(payload: Uint8Array): Uint8Array;
export declare function verifyAndStripCrc16(dataWithCrc: Uint8Array): {
    valid: boolean;
    payload: Uint8Array;
};
