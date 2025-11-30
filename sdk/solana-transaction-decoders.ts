// Solana transaction decoder functions
// These can be used in both browser and server environments

// Helper functions for browser-compatible binary data handling
function hexToUint8Array(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/, '');
  const bytes =
    cleanHex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || [];
  return new Uint8Array(bytes);
}

function readUInt8(buffer: Uint8Array, offset: number): number {
  return buffer[offset];
}

function readUInt32LE(buffer: Uint8Array, offset: number): number {
  return (
    (buffer[offset] |
      (buffer[offset + 1] << 8) |
      (buffer[offset + 2] << 16) |
      (buffer[offset + 3] << 24)) >>>
    0
  ); // Unsigned right shift to ensure positive
}

function readUInt16LE(buffer: Uint8Array, offset: number): number {
  return buffer[offset] | (buffer[offset + 1] << 8);
}

function uint8ArrayToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function uint8ArrayToUtf8(buffer: Uint8Array): string {
  return new TextDecoder().decode(buffer);
}

// Base58 encoding alphabet (Bitcoin/Solana alphabet)
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function uint8ArrayToBase58(buffer: Uint8Array): string {
  // Handle empty input
  if (buffer.length === 0) return '';

  // Count leading zeros
  let leadingZeros = 0;
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    leadingZeros++;
  }

  // Convert to base58
  const digits = [0];
  for (let i = leadingZeros; i < buffer.length; i++) {
    let carry = buffer[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  // Convert to base58 string
  let result = '';
  for (let i = 0; i < leadingZeros; i++) {
    result += BASE58_ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}

// Instruction decoder functions
export function decodeCreateTargetPoolInstruction(hex: string): {
  instruction: 0;
  pool_id: string;
  target_hashes: string[];
} {
  try {
    const buffer = hexToUint8Array(hex);
    let offset = 0;
    const instruction = readUInt8(buffer, offset) as 0;
    offset += 1;
    // Pool ID (Rust string: 4-byte length prefix, then utf8 bytes)
    const poolIdLen = readUInt32LE(buffer, offset);
    offset += 4;
    const pool_id = uint8ArrayToUtf8(
      buffer.subarray(offset, offset + poolIdLen),
    );
    offset += poolIdLen;
    // Number of hashes (Rust u32)
    const numHashes = readUInt32LE(buffer, offset);
    offset += 4;
    const target_hashes: string[] = [];
    for (let i = 0; i < numHashes; i++) {
      target_hashes.push(uint8ArrayToHex(buffer.subarray(offset, offset + 32)));
      offset += 32;
    }
    return { instruction, pool_id, target_hashes };
  } catch (err: unknown) {
    if (err instanceof Error) {
      throw new Error('Failed to decode CreateTargetPool: ' + err.message);
    }
    throw new Error('Failed to decode CreateTargetPool: Unknown error');
  }
}

export function decodeSubmitSessionInstruction(hex: string): {
  instruction: 1;
  session_id: string;
  pool_id: string;
  session_media_hash: string;
  target_selector_program: string;
  completed_target_indices: number[];
} {
  try {
    const buffer = hexToUint8Array(hex);
    let offset = 0;
    const instruction = readUInt8(buffer, offset) as 1;
    offset += 1;
    // Session ID (Rust string: 4-byte length prefix, then utf8 bytes)
    const sessionIdLen = readUInt32LE(buffer, offset);
    offset += 4;
    const session_id = uint8ArrayToUtf8(
      buffer.subarray(offset, offset + sessionIdLen),
    );
    offset += sessionIdLen;
    // Pool ID (Rust string: 4-byte length prefix, then utf8 bytes)
    const poolIdLen = readUInt32LE(buffer, offset);
    offset += 4;
    const pool_id = uint8ArrayToUtf8(
      buffer.subarray(offset, offset + poolIdLen),
    );
    offset += poolIdLen;
    // Session media hash (32 bytes)
    const session_media_hash = uint8ArrayToHex(
      buffer.subarray(offset, offset + 32),
    );
    offset += 32;
    // Target selector program (32 bytes)
    const target_selector_program = uint8ArrayToHex(
      buffer.subarray(offset, offset + 32),
    );
    offset += 32;
    // Completed target indices (Vec<u16>: 4-byte length prefix, then u16 elements)
    const completedIndicesLen = readUInt32LE(buffer, offset);
    offset += 4;
    const completed_target_indices: number[] = [];
    for (let i = 0; i < completedIndicesLen; i++) {
      completed_target_indices.push(readUInt16LE(buffer, offset));
      offset += 2;
    }
    return {
      instruction,
      session_id,
      pool_id,
      session_media_hash,
      target_selector_program,
      completed_target_indices,
    };
  } catch (err: unknown) {
    if (err instanceof Error) {
      throw new Error('Failed to decode SubmitSession: ' + err.message);
    }
    throw new Error('Failed to decode SubmitSession: Unknown error');
  }
}

export function decodeFinalizeSessionInstruction(hex: string): {
  instruction: 2;
  session_id: string;
  submission_blockhash: string;
  completed_target_indices: number[];
} {
  try {
    const buffer = hexToUint8Array(hex);
    let offset = 0;
    const instruction = readUInt8(buffer, offset) as 2;
    offset += 1;
    // Session ID (Rust string: 4-byte length prefix, then utf8 bytes)
    const sessionIdLen = readUInt32LE(buffer, offset);
    offset += 4;
    const session_id = uint8ArrayToUtf8(
      buffer.subarray(offset, offset + sessionIdLen),
    );
    offset += sessionIdLen;
    // Submission blockhash (now a base58 string: 4-byte length prefix, then utf8 bytes)
    const blockhashLen = readUInt32LE(buffer, offset);
    offset += 4;
    const submission_blockhash = uint8ArrayToUtf8(
      buffer.subarray(offset, offset + blockhashLen),
    );
    offset += blockhashLen;
    // Completed target indices (Vec<u16>: 4-byte length prefix, then u16 elements)
    const completedIndicesLen = readUInt32LE(buffer, offset);
    offset += 4;
    const completed_target_indices: number[] = [];
    for (let i = 0; i < completedIndicesLen; i++) {
      completed_target_indices.push(readUInt16LE(buffer, offset));
      offset += 2;
    }
    return {
      instruction,
      session_id,
      submission_blockhash,
      completed_target_indices,
    };
  } catch (err: unknown) {
    if (err instanceof Error) {
      throw new Error('Failed to decode FinalizeSession: ' + err.message);
    }
    throw new Error('Failed to decode FinalizeSession: Unknown error');
  }
}

// Pool account decoder function
export function decodePoolAccount(base64Data: string): {
  type: 'poolAccount';
  pool_id: string;
  creator: string;
  target_count: number;
  targets: string[];
  created_at: number;
  finalized: boolean;
} {
  try {
    // Decode base64 to buffer (browser-compatible)
    const binaryString = atob(base64Data);
    const data = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      data[i] = binaryString.charCodeAt(i);
    }
    let offset = 0;

    // Read pool_id (string: 4-byte length + utf8 bytes)
    const poolIdLen = readUInt32LE(data, offset);
    offset += 4;
    const pool_id = uint8ArrayToUtf8(data.subarray(offset, offset + poolIdLen));
    offset += poolIdLen;

    // Read creator (32 bytes)
    const creator = data.subarray(offset, offset + 32);
    offset += 32;

    // Read target_count (u16 - 2 bytes)
    const target_count = readUInt16LE(data, offset);
    offset += 2;

    // Read targets (Vec<[u8; 32]>: 4-byte length + target_count * 32 bytes)
    const targetsLen = readUInt32LE(data, offset);
    offset += 4;
    const targets: string[] = [];
    for (let i = 0; i < targetsLen; i++) {
      const target = data.subarray(offset, offset + 32);
      targets.push(uint8ArrayToHex(target));
      offset += 32;
    }

    // Read created_at (i64 - 8 bytes)
    // Note: JavaScript doesn't have native i64, so we'll read as two 32-bit values
    const createdAtLow = readUInt32LE(data, offset);
    const createdAtHigh = readUInt32LE(data, offset + 4);
    const created_at = createdAtLow + createdAtHigh * 0x100000000;
    offset += 8;

    // Read finalized (bool - 1 byte)
    const finalized = data[offset] !== 0;

    return {
      type: 'poolAccount' as const,
      pool_id,
      creator: uint8ArrayToHex(creator),
      target_count,
      targets,
      created_at,
      finalized,
    };
  } catch (error) {
    throw new Error(`Failed to decode pool account: ${error}`);
  }
}

// Session account decoder function
export function decodeSessionAccount(base64Data: string): {
  type: 'sessionAccount';
  session_id: string;
  pool_id: string;
  session_media_hash: string;
  submission_slot: number;
  submission_blockhash: string;
  assigned_target_index: number;
  target_selector_program: string;
  submitter: string;
  submitted_at: number;
  finalized: boolean;
  finalized_at: number;
  completed_target_indices: number[];
} {
  try {
    // Decode base64 to buffer (browser-compatible)
    const binaryString = atob(base64Data);
    const data = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      data[i] = binaryString.charCodeAt(i);
    }
    let offset = 0;

    // Read session_id (string: 4-byte length + utf8 bytes)
    const sessionIdLen = readUInt32LE(data, offset);
    offset += 4;
    const session_id = uint8ArrayToUtf8(
      data.subarray(offset, offset + sessionIdLen),
    );
    offset += sessionIdLen;

    // Read pool_id (string: 4-byte length + utf8 bytes)
    const poolIdLen = readUInt32LE(data, offset);
    offset += 4;
    const pool_id = uint8ArrayToUtf8(data.subarray(offset, offset + poolIdLen));
    offset += poolIdLen;

    // Read session_media_hash (32 bytes)
    const session_media_hash = uint8ArrayToHex(
      data.subarray(offset, offset + 32),
    );
    offset += 32;

    // Read submission_slot (u64 - 8 bytes)
    const submissionSlotLow = readUInt32LE(data, offset);
    const submissionSlotHigh = readUInt32LE(data, offset + 4);
    const submission_slot =
      submissionSlotLow + submissionSlotHigh * 0x100000000;
    offset += 8;

    // Read submission_blockhash (32 bytes) - convert to base58 format
    const submission_blockhash = uint8ArrayToBase58(
      data.subarray(offset, offset + 32),
    );
    offset += 32;

    // Read assigned_target_index (u16 - 2 bytes)
    const assigned_target_index = readUInt16LE(data, offset);
    offset += 2;

    // Read target_selector_program (32 bytes)
    const target_selector_program = uint8ArrayToHex(
      data.subarray(offset, offset + 32),
    );
    offset += 32;

    // Read submitter (32 bytes)
    const submitter = uint8ArrayToHex(data.subarray(offset, offset + 32));
    offset += 32;

    // Read submitted_at (i64 - 8 bytes)
    const submittedAtLow = readUInt32LE(data, offset);
    const submittedAtHigh = readUInt32LE(data, offset + 4);
    const submitted_at = submittedAtLow + submittedAtHigh * 0x100000000;
    offset += 8;

    // Read finalized (bool - 1 byte)
    const finalized = data[offset] !== 0;
    offset += 1;

    // Read finalized_at (i64 - 8 bytes)
    const finalizedAtLow = readUInt32LE(data, offset);
    const finalizedAtHigh = readUInt32LE(data, offset + 4);
    const finalized_at = finalizedAtLow + finalizedAtHigh * 0x100000000;
    offset += 8;

    // Read completed_target_indices (Vec<u16>: 4-byte length + u16 elements)
    const completedIndicesLen = readUInt32LE(data, offset);
    offset += 4;
    const completed_target_indices: number[] = [];
    for (let i = 0; i < completedIndicesLen; i++) {
      completed_target_indices.push(readUInt16LE(data, offset));
      offset += 2;
    }

    return {
      type: 'sessionAccount' as const,
      session_id,
      pool_id,
      session_media_hash,
      submission_slot,
      submission_blockhash,
      assigned_target_index,
      target_selector_program,
      submitter,
      submitted_at,
      finalized,
      finalized_at,
      completed_target_indices,
    };
  } catch (error) {
    throw new Error(`Failed to decode session account: ${error}`);
  }
}

// Helper function to detect if string is likely base64
function isLikelyBase64(str: string): boolean {
  // Base64 regex pattern
  const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
  return base64Pattern.test(str) && str.length > 50; // Pool account data should be fairly long
}

// Auto-detect data type and decode (hex instruction or base64 pool account)
export function decodeInstruction(input: string):
  | { instruction: 0; pool_id: string; target_hashes: string[] }
  | {
      instruction: 1;
      session_id: string;
      pool_id: string;
      session_media_hash: string;
      target_selector_program: string;
      completed_target_indices: number[];
    }
  | {
      instruction: 2;
      session_id: string;
      submission_blockhash: string;
      completed_target_indices: number[];
    }
  | {
      type: 'poolAccount';
      pool_id: string;
      creator: string;
      target_count: number;
      targets: string[];
      created_at: number;
      finalized: boolean;
    } {
  // First, try to detect if this looks like base64 pool account data
  if (isLikelyBase64(input)) {
    try {
      return decodePoolAccount(input);
    } catch {
      // If base64 decode fails, fall through to hex instruction decode
    }
  }

  // Try to decode as hex instruction
  try {
    const buffer = hexToUint8Array(input);
    const instructionByte = readUInt8(buffer, 0);

    if (instructionByte === 0) {
      return decodeCreateTargetPoolInstruction(input);
    } else if (instructionByte === 1) {
      return decodeSubmitSessionInstruction(input);
    } else if (instructionByte === 2) {
      return decodeFinalizeSessionInstruction(input);
    } else {
      throw new Error(`Unknown instruction type: ${instructionByte}`);
    }
  } catch (hexError) {
    // If both base64 and hex failed, provide a helpful error
    if (isLikelyBase64(input)) {
      throw new Error(
        'Failed to decode as both pool account data and hex instruction. Data may be corrupted.',
      );
    } else {
      throw new Error(
        `Failed to decode hex instruction: ${hexError instanceof Error ? hexError.message : 'Unknown error'}`,
      );
    }
  }
}
