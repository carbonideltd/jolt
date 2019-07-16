extern crate cryptoxide;
extern crate base64;
extern crate chain_addr;
extern crate chain_crypto;

use std::fs::File;
use std::env;
use cryptoxide::{chacha20poly1305::ChaCha20Poly1305, hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha512};
use std::{
    fmt,
    io::{Read},
    iter::repeat,
};
use base64::decode;
use rpassword::prompt_password_stdout;
use chain_crypto::{
    bech32::Bech32,
    Ed25519, PublicKey
};

const PASSWORD_DERIVATION_ITERATIONS: u32 = 10_000;
const SK_SIZE: usize = 69;
const PK_SIZE: usize = 69;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const DISCRIMINATION: chain_addr::Discrimination = chain_addr::Discrimination::Production;
const ADDRESS_PREFIX: &str = "ceo";

pub type Password = [u8];
type Key = [u8; KEY_SIZE];
type Salt = [u8; SALT_SIZE];
type Nonce = [u8; NONCE_SIZE];
type SK = [u8; SK_SIZE];
type PK = [u8; PK_SIZE];

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    println!("jolt key decrypter");
    println!("key path:  {}", args[1]);
    let password = prompt_password_stdout("enter your jolt password: ").unwrap();
    // let password = read_password().unwrap();
    let mut file = File::open(args[1].clone()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    decrypt(password.to_string(), contents)?;
    Ok(())
}

fn password_to_key(password: &Password, salt: Salt, key: &mut Key) {
    let mut mac = Hmac::new(Sha512::new(), password);
    pbkdf2(&mut mac, &salt[..], PASSWORD_DERIVATION_ITERATIONS, key);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address(chain_addr::Address);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        chain_addr::AddressReadable::from_address(ADDRESS_PREFIX, &self.0).fmt(f)
    }
}

fn decrypt( password: String, digest : String) -> std::io::Result<()>{
    let digest = decode(&digest).unwrap();
    let mut digest = &digest[..];
    let mut salt: Salt = [0; SALT_SIZE];
    let mut nonce: Nonce = [0; NONCE_SIZE];
    let mut key: Key = [0; KEY_SIZE];
    let mut sk: SK = [0; SK_SIZE];
    let mut pk: PK = [0; PK_SIZE];
    let len = digest.len() - TAG_SIZE - SALT_SIZE - NONCE_SIZE;
    let mut cleartext: Vec<u8> = repeat(0).take(len).collect();
    digest.read_exact(&mut salt[..]).unwrap();
    digest.read_exact(&mut nonce[..]).unwrap();
    password_to_key(password.as_bytes(), salt, &mut key);
    let mut decipher = ChaCha20Poly1305::new(&key[..], &nonce[..], &[]);
    if decipher.decrypt(&digest[0..len], &mut cleartext[..], &digest[len..]) {
        let mut cleartext = &cleartext[..];
        cleartext.read_exact(&mut sk[..]).unwrap();
        cleartext.read_exact(&mut pk[..]).unwrap();
        let pk = String::from_utf8(pk.to_vec()).unwrap();
        println!("secret key: < not displayed for security reasons >\npublic key: {}"
        , pk);
        let pk = PublicKey::<Ed25519>::try_from_bech32_str(&pk).unwrap();
        let addr = Address(chain_addr::Address(DISCRIMINATION, chain_addr::Kind::Single(pk)));
        println!("address:    {}", addr);
    } else {
        println!("password incorrect");
    }
    Ok(())
}
