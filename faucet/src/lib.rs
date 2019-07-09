#![recursion_limit = "256"]

use yew::{html, Component, ComponentLink, Html, Renderable, ShouldRender};

pub struct Model {
    host: String,
    address: String,
    amount: i64,
}

pub enum Msg {
    GotHost(String),
    GotAddress(String),
    GotAmount(i64),
    Clicked,
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        Model {
            host: "".into(),
            address: "".into(),
            amount: 0,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::GotHost(new_value) => {
                self.host = new_value;
            }
            Msg::GotAddress(new_value) => {
                self.address = new_value;
            }
            Msg::GotAmount(new_value) => {
                self.amount = new_value;
            }
            Msg::Clicked => {
                self.host = "a host".to_string();
                self.address = "an address".to_string();
                self.amount = 1337;
            }
        }
        true
    }
}

impl Renderable<Model> for Model {
    fn view(&self) -> Html<Self> {
        html! {
            <div>
                <h1>{ "Jormungandr Testnet Faucet" }</h1>
                <div>
                    <label>{ "Host: " }</label>
                    <input value=&self.host
                        oninput=|e| Msg::GotHost(e.value)
                        placeholder="your testnet host">
                    </input>
                </div>
                <div>
                    <label>{ "Address: " }</label>
                    <input value=&self.address
                        oninput=|e| Msg::GotAddress(e.value)
                        placeholder="your testnet address">
                    </input>
                </div>
                <div>
                    <label>{ "Amount: " }</label>
                    <input value=&self.amount
                        oninput=|e| Msg::GotAmount(e.value.parse::<i64>().unwrap())
                        placeholder=0>
                    </input>
                </div>
                <button onclick=|_| Msg::Clicked>{ "Submit" }</button>
                <div>
                    {&self.host}
                </div>
                <div>
                    {&self.address}
                </div>
                <div>
                    {&self.amount}
                </div>

            </div>
        }
    }
}
