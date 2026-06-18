import wasmBytes from './pkg/rustcrypto_wasm_bg.wasm';
import __init, { initSync as __initSync } from './pkg/rustcrypto_wasm.js';

export {
    xchacha20poly1305_encrypt,
    xchacha20poly1305_decrypt,
    shake256,
    argon2id,
    ml_dsa87_keygen,
    ml_dsa87_sign,
    ml_dsa87_verify,
    ml_dsa87_verifying_key_from_seed,
} from './pkg/rustcrypto_wasm.js';

export const init     = () => __init({ module_or_path: wasmBytes });
export const initSync = () => __initSync({ module: wasmBytes });
