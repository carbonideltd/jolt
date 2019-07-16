#![recursion_limit = "512"]

extern crate chain_crypto;
extern crate chain_addr;
extern crate rand_chacha;
extern crate getrandom;
extern crate cryptoxide;
#[macro_use]
extern crate stdweb;
extern crate base64;

mod address;

use yew::{html, Component, ComponentLink, Html, Renderable, ShouldRender};
use yew::services::ConsoleService;
use chain_crypto::{Ed25519, PublicKey, SecretKey};
use chain_crypto::bech32::Bech32;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;
use getrandom::getrandom;
use std::{
    io::Read,
    iter::repeat,
};

use cryptoxide::{chacha20poly1305::ChaCha20Poly1305, hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha512};

use base64::{encode, decode};

pub struct Model {
    console: ConsoleService,
    password: String,
    sk: String,
    pk: String,
    address: String,
    encrypted: String,
    decrypted: String,
    download_href: String,
}

pub enum Msg {
    GotPassword(String),
    Generate,
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        Model {
            console: ConsoleService::new(),
            password: "".into(),
            sk: "".into(),
            pk: "".into(),
            address: "".into(),
            encrypted: "".into(),
            decrypted: "".into(),
            download_href: "data:text/plain;charset=utf-8,".into(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::GotPassword(new_value) => {
                self.password = new_value;
            }
            Msg::Generate => {
                self.generate_keys();
            }
        }
        true
    }
}

impl Renderable<Model> for Model {
    fn view(&self) -> Html<Self> {
        html! {
            <div>
                <h1>{ "Generate Identity" }</h1>
                <input
                    type="password"
                    value=&self.password
                    oninput=|e| Msg::GotPassword(e.value)
                    placeholder="Password">
                </input>
                <nav class="menu">
                    <button onclick=|_| Msg::Generate>{ "Generate" }</button>
                </nav>
                <p>{ &self.sk }</p>
                <p>{ &self.pk }</p>
                <p>{ &self.address }</p>
                <p>{ &self.encrypted }</p>
                <p>{ &self.decrypted }</p>
                <p>{ &self.download_href }</p>
                <a download="filename.txt" href=self.download_href.clone()>{"text file"}</a>
            </div>
        }
    }
}

impl Model {
    fn generate_keys(&mut self) {
        let mut buf = [0u8; 32];
        match getrandom(&mut buf) {
            Err(why) => panic!("{:?}", why),
            Ok(buf) => buf,
        };
        let mut rng = ChaChaRng::from_seed(buf);
        const DISCRIMINATION: chain_addr::Discrimination = chain_addr::Discrimination::Production;
        let sk: SecretKey<Ed25519> = SecretKey::generate(&mut rng);
        self.sk = sk.to_bech32_str();
        let pk: PublicKey<Ed25519> = sk.to_public();
        self.pk = pk.clone().to_bech32_str();
        let address = chain_addr::Address(DISCRIMINATION, chain_addr::Kind::Single(pk.clone()));
        self.address = address::Address::from(address).to_string();
        self.console.log("generate");
        let crypto_material = format!("{}\n{}",sk.to_bech32_str(), pk.clone().to_bech32_str() );
        let digest = encrypt(self.password.clone(), &crypto_material);
        self.encrypted = digest.clone();
        let cleartext = decrypt(self.password.clone(), digest.clone());
        match cleartext {
            Some(ct) => {
                assert_eq!(&crypto_material[..], &ct[..]);
                self.decrypted = ct;
                self.download_href.push_str(&digest.clone().as_str());
            },
            None => {
                panic!("Couldn't decrypt")
            },
        };
    }
}

const PASSWORD_DERIVATION_ITERATIONS: u32 = 10_000;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const CLEARTEXT_SIZE: usize = 139;
const CIPHERTEXT_SIZE: usize = CLEARTEXT_SIZE;
const DIGEST_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE + CIPHERTEXT_SIZE;

pub type Password = [u8];
type Key = [u8; KEY_SIZE];
type Salt = [u8; SALT_SIZE];
type Nonce = [u8; NONCE_SIZE];
type Tag = [u8; TAG_SIZE];


fn generate_nonce() -> Nonce {
    let mut buf: Nonce = [0u8; NONCE_SIZE];
    match getrandom(&mut buf) {
        Err(why) => panic!("{:?}", why),
        Ok(buf) => buf,
    };
    buf
}

fn generate_salt() -> Salt {
    let mut buf: Salt = [0u8; SALT_SIZE];
    match getrandom(&mut buf) {
        Err(why) => panic!("{:?}", why),
        Ok(buf) => buf,
    };
    buf
}

fn password_to_key(password: &Password, salt: Salt, key: &mut Key) {
    let mut mac = Hmac::new(Sha512::new(), password);
    pbkdf2(&mut mac, &salt[..], PASSWORD_DERIVATION_ITERATIONS, key);
}

fn encrypt(password: String, cleartext: &String) -> String {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let mut key: Key = [0; KEY_SIZE];
    password_to_key(password.as_bytes(), salt, &mut key);
    let mut tag: Tag = [0; TAG_SIZE];
    let cleartext: Vec<u8> = cleartext.as_bytes().to_vec();
    let mut ciphertext: Vec<u8> = vec!(0u8; CIPHERTEXT_SIZE);

    let mut cipher = ChaCha20Poly1305::new(&key, &nonce, &[]);
    cipher.encrypt(&cleartext, &mut ciphertext, &mut tag[..]);
    let mut digest: Vec<u8> = Vec::with_capacity(DIGEST_SIZE);
    digest.extend_from_slice(&salt);
    digest.extend_from_slice(&nonce);
    digest.append(&mut ciphertext);
    digest.extend_from_slice(&tag);
    js! { console.log( @{ format!("encrypted: {:?}", digest) })};
    encode(&digest)
}

fn decrypt( password: String, digest : String) -> Option<String> {
    let mut digest = &decode(&digest).unwrap()[..];
    let mut salt = [0; SALT_SIZE];
    let mut nonce = [0; NONCE_SIZE];
    let mut key = [0; KEY_SIZE];
    let len = digest.len() - TAG_SIZE - SALT_SIZE - NONCE_SIZE;
    let mut cleartext: Vec<u8> = repeat(0).take(len).collect();

    digest.read_exact(&mut salt[..]).unwrap();
    digest.read_exact(&mut nonce[..]).unwrap();
    password_to_key(password.as_bytes(), salt, &mut key);

    let mut decipher = ChaCha20Poly1305::new(&key[..], &nonce[..], &[]);
    if decipher.decrypt(&digest[0..len], &mut cleartext[..], &digest[len..]) {
        js! { console.log( @{ format!("decrypted: {:?}", cleartext) })};
        Some(String::from_utf8(cleartext).unwrap())
    } else {
        None
    }
}


// fn test_vector2() {
//     struct TestVector2 {
//         key: [u8; 32],
//         nonce: Vec<u8>,
//         tag: [u8;16],
//         plain_text: Vec<u8>,
//         cipher_text: Vec<u8>,
//         aad: Vec<u8>,
//     };
//     let v = TestVector2 {
//         key: [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f],
//         nonce: vec!(0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47),
//         tag: [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91],
//         plain_text: vec!(0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e),
//         cipher_text: vec!(0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16),
//         aad: vec!(0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7),
//     };
//     let mut tag = [0u8; 16];
//     let mut ciphertext = vec!(0u8; v.cipher_text.len());
//     let mut cipher = ChaCha20Poly1305::new(&v.key, &v.nonce, &v.aad);
//     let mut decipher = cipher.clone();
//     cipher.encrypt(&v.plain_text, &mut ciphertext, &mut tag[..]);
//     assert_eq!(&ciphertext[..], &v.cipher_text[..]);
//     assert_eq!(&tag[..], &v.tag[..]);
//     let mut cipher_tag: Vec<u8> = Vec::with_capacity(ciphertext.len() + tag.len());
//     js! { console.log( @{ format!("length of tag: {:?}", tag.len()) })};
//     js! { console.log( @{ format!("length of plain_text: {:?}", v.plain_text.len()) })};
//     js! { console.log( @{ format!("length of ciphertext: {:?}", ciphertext.len()) })};
//     js! { console.log( @{ format!("length of cipher_tag: {:?}", cipher_tag.len()) })};
//     cipher_tag.extend_from_slice(&tag);
//     js! { console.log( @{ format!("length of cipher_tag1: {:?}", cipher_tag.len()) })};
//     cipher_tag.append(&mut ciphertext);
//     js! { console.log( @{ format!("cipher_tag: {:?}", cipher_tag) })};
//     js! { console.log( @{ format!("length of cipher_tag2: {:?}", cipher_tag.len()) })};
//     js! { console.log( @{ format!("calculated tag: {:?}", tag) })};
//     js! { console.log( @{ format!("derived    tag: {:?}", v.tag) })};
//     let (tag1, ciphertext1) = cipher_tag.split_at(16);
//     js! { console.log( @{ format!("split tag:      {:?}", tag1) })};
//     assert_eq!(&ciphertext1[..], &v.cipher_text[..]);
//     assert_eq!(&tag1[..], &v.tag[..]);
//     let mut output = vec!(0u8; v.plain_text.len());
//     assert!(decipher.decrypt(&ciphertext1, &mut output, &tag1[..]), true);
//     assert_eq!(&output[..], &v.plain_text[..]);
// }
