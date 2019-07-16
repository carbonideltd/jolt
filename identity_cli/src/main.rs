extern crate chain_addr;
extern crate jolt_crypto;

use std::fs::File;
use std::env;
use std::{
    fmt,
    io::{Read},
};
use rpassword::prompt_password_stdout;
use chain_crypto::{
    bech32::Bech32,
    Ed25519, PublicKey
};

const DISCRIMINATION: chain_addr::Discrimination = chain_addr::Discrimination::Production;
const ADDRESS_PREFIX: &str = "ceo";

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("jolt key decrypter");
    println!("key path:  {}", args[1]);
    let password = prompt_password_stdout("enter your jolt password: ").unwrap();
    let mut file = File::open(args[1].clone()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let pk = jolt_crypto::decrypt(password.to_string(), contents);
    match pk {
        Some(pk) => {
            println!("secret key: <not displayed for security reasons>\npublic key: {}", pk);
            let pk = PublicKey::<Ed25519>::try_from_bech32_str(&pk).unwrap();
            let addr = Address(chain_addr::Address(DISCRIMINATION, chain_addr::Kind::Single(pk)));
            println!("address:    {}", addr);
        },
        None => {
            panic!("Couldn't decrypt")
        },
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address(chain_addr::Address);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        chain_addr::AddressReadable::from_address(ADDRESS_PREFIX, &self.0).fmt(f)
    }
}
