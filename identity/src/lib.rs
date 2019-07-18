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

const HREF: &str = "data:text/plain;charset=utf-8,";

pub struct Model {
    password: String,
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
                    placeholder="Select a strong password">
                </input>
                <button onclick=|_| Msg::Generate>{ "Generate" }</button>
                <p> { "This application's "}<a href="https://github.com/carbonideltd/jolt">{ "source code" }</a>{ " can be audited and/or run locally." }</p>
                <p> { "To obtain your address you'll need to run a decryptor on your machine, obtained by the above link."} </p>

                {
                    if self.completed == true {
                        html! {
                            <div>
                                <p></p>
                                <p>{ "Your key pair is now generated, please download the encrypted file to a secure location." }</p>
                                <p> { "Back up the file somewhere safe and ensure you do not lose the password." }</p>
                                <a download="jolt.key" href=self.href.clone()>{"download your jolt keys"}</a>
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
        let sk: SecretKey<Ed25519> = SecretKey::generate(&mut rng);
        let pk: PublicKey<Ed25519> = sk.to_public();
        let crypto_material = format!("{}{}",sk.to_bech32_str(), pk.clone().to_bech32_str());
        let digest = jolt_crypto::encrypt(self.password.clone(), &crypto_material);
        let cleartext = jolt_crypto::decrypt(self.password.clone(), digest.clone());
        match cleartext {
            Some(_) => {
                self.href.push_str(&digest.clone().as_str());
                self.completed = true;
            },
            None => {
                panic!("Couldn't decrypt")
            },
        };
    }
}
