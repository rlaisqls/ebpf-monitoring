use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use prometheus_client::registry;
use regex::Regex;

type ParsedName = Vec<String>;

trait ModuleController {
    fn new_module(&self, id: &str, export: ExportFunc) -> Result<Box<dyn Module>, String>;
}

trait Module {
    fn load_config(&mut self, config: &[u8], args: HashMap<String, Box<dyn Any>>) -> Result<(), String>;
    fn run(&mut self, context: Arc<()>) -> Result<(), String>;
}

type ExportFunc = fn(exports: &mut HashMap<String, Box<dyn Any>>);

pub struct Options {
    module_controller: Box<dyn ModuleController>,
    id: String,
    data_path: String, // A path to a directory with this component may use for storage.
    on_state_change: fn(exports: Exports), // OnStateChange may be invoked at any time by a component whose Export value changes.
    registerer: Arc<dyn registry>,
    tracer: Arc<()>,
    get_service_data: fn(name: &str) -> Result<Box<dyn Any>, String>,
}

type Arguments = Box<dyn Any>;
pub type Exports = Box<dyn Any>;

trait Component {
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}

pub struct Registration {
    name: String,
    args: Arguments,
    exports: Exports,
    build: fn(opts: Options, args: Arguments) -> Result<Box<dyn Component>, String>,
}

fn register(r: Registration, registered: &mut HashMap<String, Registration>, parsed_names: &mut HashMap<String, ParsedName>) {
    if registered.contains_key(&r.name) {
        panic!("Component name {} already registered", r.name);
    }

    let parsed = parse_component_name(&r.name).expect("invalid component name");

    registered.insert(r.name.clone(), r);
    parsed_names.insert(r.name.clone(), parsed);
}

fn parse_component_name(name: &str) -> Result<ParsedName, String> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.is_empty() {
        return Err("missing name".to_string());
    }

    let identifier_regex = Regex::new(r"^[A-Za-z][0-9A-Za-z_]*$").unwrap();
    for part in &parts {
        if part.is_empty() {
            return Err("found empty identifier".to_string());
        }
        if !identifier_regex.is_match(part) {
            return Err(format!("identifier {} is not valid", part));
        }
    }
    Ok(parts.iter().map(|s| s.to_string().collect()))
}

fn get<'a>(name: &'a str, registered: &'a HashMap<String, Registration>) -> Option<&'a Registration> {
    registered.get(name)
}

fn all_names(registered: &HashMap<String, Registration>) -> Vec<String> {
    let mut keys: Vec<String> = registered.keys().cloned().collect();
    keys.sort();
    keys
}