extern crate cryptoxide;
extern crate base64;

use std::fs::File;
use std::env;
use cryptoxide::{chacha20poly1305::ChaCha20Poly1305, hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha512};
use std::{
    io::Read,
    iter::repeat,
};
use base64::decode;

const PASSWORD_DERIVATION_ITERATIONS: u32 = 10_000;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

pub type Password = [u8];
type Key = [u8; KEY_SIZE];
type Salt = [u8; SALT_SIZE];
type Nonce = [u8; NONCE_SIZE];

fn main() {
    let args: Vec<String> = env::args().collect();
    let password = &args[1];
    println!("Jolt key path: {}.", args[2]);
    let mut file = File::open(args[2].clone()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    decrypt(password.to_string(), contents);
}

fn password_to_key(password: &Password, salt: Salt, key: &mut Key) {
    let mut mac = Hmac::new(Sha512::new(), password);
    pbkdf2(&mut mac, &salt[..], PASSWORD_DERIVATION_ITERATIONS, key);
}

fn decrypt( password: String, digest : String) {
    let mut digest = &decode(&digest).unwrap()[..];
    let mut salt: Salt = [0; SALT_SIZE];
    let mut nonce: Nonce = [0; NONCE_SIZE];
    let mut key: Key = [0; KEY_SIZE];
    let len = digest.len() - TAG_SIZE - SALT_SIZE - NONCE_SIZE;
    let mut cleartext: Vec<u8> = repeat(0).take(len).collect();

    digest.read_exact(&mut salt[..]).unwrap();
    digest.read_exact(&mut nonce[..]).unwrap();
    password_to_key(password.as_bytes(), salt, &mut key);

    let mut decipher = ChaCha20Poly1305::new(&key[..], &nonce[..], &[]);
    if decipher.decrypt(&digest[0..len], &mut cleartext[..], &digest[len..]) {
        let cleartext_string = String::from_utf8(cleartext).unwrap();
        let (sk, rest) = cleartext_string.split_at(cleartext_string.len() / 2);
        let (_, pk) = rest.split_at(1);
        println!("secretkey: {}\npublickey: {}",sk ,pk);
    } else {
        println!("Couldn't decrypt");
    }
}
