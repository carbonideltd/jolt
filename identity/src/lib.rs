#![recursion_limit = "512"]

extern crate chain_addr;
extern crate rand_chacha;
extern crate stdweb;
extern crate jolt_crypto;

use yew::{html, Component, ComponentLink, Html, Renderable, ShouldRender};
use chain_crypto::{Ed25519, PublicKey, SecretKey};
use chain_crypto::bech32::Bech32;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;
use getrandom::getrandom;
use std::fmt;

const DISCRIMINATION: chain_addr::Discrimination = chain_addr::Discrimination::Production;
const ADDRESS_PREFIX: &str = "ceo";
const HREF: &str = "data:text/plain;charset=utf-8,";

pub struct Model {
    password: String,
    address: String,
    href: String,
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
            address: "".into(),
            href: HREF.into(),
            completed: false,

        }
    }
    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::GotPassword(new_value) => {
                self.password = new_value;
            }
            Msg::Generate => {
                if self.password.len() != 0 {
                    self.href = HREF.into();
                    self.completed = false;
                    self.generate_keys();
                    self.password = "".into();
                }
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
                    placeholder="A strong passphrase">
                </input>
                <button onclick=|_| Msg::Generate>{ "Generate" }</button>
                <p> { "This application's "}<a href="https://github.com/carbonideltd/jolt/tree/master/identity">{ "source code" }</a>{ " can be audited and/or run locally." }</p>
                {
                    if self.completed == true {
                        html! {
                            <div>
                                <p></p>
                                <p><b>{"Your Luceo production address is: "}</b>{format!("{}", self.address) }</p>
                                <p><b>{"Encrypted keypair:    "}</b><a download="jolt.key" href=self.href.clone()>{"Jolt keypair download"}</a></p>
                                <p>{ "Your Jolt key pair is now generated and is associated with the address, you must download the encrypted keypair file to a secure location." }</p>
                                <p> { "Back up the file somewhere safe and ensure you do not lose the passphrase." }</p>
                                <p> { "You may run the "} <a href="https://github.com/carbonideltd/jolt/tree/master/identity_cli">{ "decryptor program" }</a> {" locally to ensure the file wasn't corrupted when it downloaded." }</p>
                                <p> { "The decryptor program will also print the address if needed later." }</p>
                            </div>
                        }
                    } else {
                        html! { <a type="hidden" />  }
                    }
                }
                <p></p>
                <p>{"How to select a secure passphrase:"}</p>
                <a href="https://xkcd.com/936/"><img src="https://imgs.xkcd.com/comics/password_strength.png"/></a>
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
        let sk: SecretKey<Ed25519> = SecretKey::generate(&mut rng);
        let pk: PublicKey<Ed25519> = sk.to_public();
        let crypto_material = format!("{}{}",sk.to_bech32_str(), pk.clone().to_bech32_str());
        let digest = jolt_crypto::encrypt(self.password.clone(), &crypto_material);
        let cleartext = jolt_crypto::decrypt(self.password.clone(), digest.clone());
        match cleartext {
            Some((_sk, pk)) => {
                let pk = PublicKey::<Ed25519>::try_from_bech32_str(&pk).unwrap();
                let addr = Address(chain_addr::Address(DISCRIMINATION, chain_addr::Kind::Single(pk)));
                self.href.push_str(&digest.clone().as_str());
                self.completed = true;
                self.address = addr.to_string();
            },
            None => {
                panic!("Couldn't decrypt")
            },
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address(chain_addr::Address);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        chain_addr::AddressReadable::from_address(ADDRESS_PREFIX, &self.0).fmt(f)
    }
}
