import {
  BlindingResultBytes,
  BrsaKeyPair,
  BrsaPublicKey,
  BrsaSecretKey,
  PbrsaKeyPair,
  PbrsaPublicKey,
  PbrsaSecretKey,
} from "../pkg/blind_rsa_signatures_wasm.js";

export {
  BlindingResultBytes as BlindingResult,
  BrsaKeyPair,
  BrsaPublicKey,
  BrsaSecretKey,
  PbrsaKeyPair,
  PbrsaPublicKey,
  PbrsaSecretKey,
};

export interface GenerateKeyPairOptions {
  modulusBits?: number;
}

const DEFAULT_MODULUS_BITS = 2048;

export const brsa = Object.freeze({
  KeyPair: BrsaKeyPair,
  PublicKey: BrsaPublicKey,
  SecretKey: BrsaSecretKey,
  generateKeyPair: generateBrsaKeyPair,
});

export const pbrsa = Object.freeze({
  KeyPair: PbrsaKeyPair,
  PublicKey: PbrsaPublicKey,
  SecretKey: PbrsaSecretKey,
  generateKeyPair: generatePbrsaKeyPair,
});

export default Object.freeze({ brsa, pbrsa });

function generateBrsaKeyPair(options: GenerateKeyPairOptions = {}): BrsaKeyPair {
  return BrsaKeyPair.generate(modulusBits(options));
}

function generatePbrsaKeyPair(options: GenerateKeyPairOptions = {}): PbrsaKeyPair {
  return PbrsaKeyPair.generate(modulusBits(options));
}

function modulusBits(options: GenerateKeyPairOptions): number {
  return options.modulusBits ?? DEFAULT_MODULUS_BITS;
}
