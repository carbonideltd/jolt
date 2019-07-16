#![recursion_limit = "512"]

extern crate chain_crypto;
extern crate chain_addr;
extern crate rand_chacha;
extern crate getrandom;
extern crate cryptoxide;
extern crate stdweb;
extern crate base64;

mod address;

use yew::{html, Component, ComponentLink, Html, Renderable, ShouldRender};
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
    password: String,
    sk: String,
    pk: String,
    address: String,
    encrypted: String,
    decrypted: String,
    download_href: String,
    completed: bool,
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
            password: "".into(),
            sk: "".into(),
            pk: "".into(),
            address: "".into(),
            encrypted: "".into(),
            decrypted: "".into(),
            download_href: "data:text/plain;charset=utf-8,".into(),
            completed: false,
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
                    placeholder="Select a strong password">
                </input>
                <button onclick=|_| Msg::Generate>{ "Generate" }</button>
                {
                    if self.completed == true {
                        html! {
                            <div>
                                <p></p>
                                <p>{ "Your key pair is now generated, please download the encrypted file to a secure location." }</p>
                                <p> { "Back up the file somewhere safe and ensure you do not lose the password." }</p>
                                <a download="jolt.key" href=self.download_href.clone()>{"download your jolt keys"}</a>
                            </div>
                        }
                    } else {
                        html! { <a type="hidden" />  }
                    }
                }
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
        let crypto_material = format!("{}{}",sk.to_bech32_str(), pk.clone().to_bech32_str());
        let digest = encrypt(self.password.clone(), &crypto_material);
        self.encrypted = digest.clone();
        let cleartext = decrypt(self.password.clone(), digest.clone());
        match cleartext {
            Some(ct) => {
                assert_eq!(&crypto_material[..], &ct[..]);
                self.decrypted = ct;
                self.download_href.push_str(&digest.clone().as_str());
                self.completed = true;
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
const CLEARTEXT_SIZE: usize = 138;
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
        Some(String::from_utf8(cleartext).unwrap())
    } else {
        None
    }
}
