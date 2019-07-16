#![recursion_limit="128"]

use log::trace;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};
use yew::{html, App, Component, ComponentLink, Html, Renderable, ShouldRender};
use yew::components::Select;
use faucet::Model as Faucet;
use jolt::Model as Jolt;
use identity::Model as Identity;


#[derive(Clone, Debug, Display, EnumString, EnumIter, PartialEq)]
enum Scene {
    Faucet,
    Jolt,
    Identity,
}

struct Model {
    scene: Option<Scene>,
}

enum Msg {
    SwitchTo(Scene),
}

impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, _: ComponentLink<Self>) -> Self {
        Self {
            scene: Some(Scene::Identity)
            // scene: None
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::SwitchTo(scene) => {
                self.scene = Some(scene);
                true
            }
        }
    }
}

impl Renderable<Model> for Model {
    fn view(&self) -> Html<Self> {
        html! {
            <div id="fullscreen">
                <div id="left_pane">
                    <Select<Scene>
                        selected=self.scene.clone()
                        options=Scene::iter().collect::<Vec<_>>()
                        onchange=Msg::SwitchTo />
                </div>
                <div id="right_pane">
                    { self.view_scene() }
                </div>
            </div>
        }
    }
}

impl Model {
    fn view_scene(&self) -> Html<Self> {
        if let Some(scene) = self.scene.as_ref() {
            match scene {
                Scene::Faucet => html! { <Faucet /> },
                Scene::Jolt => html! { <Jolt /> },
                Scene::Identity => html! { <Identity /> },
            }
        } else {
            html! {
                <p>{ "Select application in dropdown list." }</p>
            }
        }
    }
}

fn main() {
    web_logger::init();
    trace!("Initializing yew...");
    yew::initialize();
    trace!("Creating an application instance...");
    let app: App<Model> = App::new();
    trace!("Mount the App to the body of the page...");
    app.mount_to_body();
    trace!("Run");
    yew::run_loop();
}
