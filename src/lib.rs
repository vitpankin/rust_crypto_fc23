extern crate wasm_bindgen;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rsa::{RsaPrivateKey, RsaPublicKey};
use wasm_bindgen::prelude::*;
use pkcs1;
use wasm_bindgen_futures::future_to_promise;
use js_sys;


#[wasm_bindgen]
pub fn encrypt(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, data).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, data).unwrap()
}

#[wasm_bindgen]
pub fn generate_ssh_keypair(bits: usize) -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let keys = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n\n-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        &*pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, pkcs1::LineEnding::default()).unwrap(),
        &*pkcs1::EncodeRsaPublicKey::to_pkcs1_pem(&public_key, pkcs1::LineEnding::default()).unwrap()
    );

    Ok(JsValue::from_str(&keys))
}


