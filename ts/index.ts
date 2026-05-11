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

export const brsa = Object.freeze({
  KeyPair: BrsaKeyPair,
  PublicKey: BrsaPublicKey,
  SecretKey: BrsaSecretKey,
});

export const pbrsa = Object.freeze({
  KeyPair: PbrsaKeyPair,
  PublicKey: PbrsaPublicKey,
  SecretKey: PbrsaSecretKey,
});

export default Object.freeze({ brsa, pbrsa });
