use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use common::error::Result;
use regex::Regex;
use common::ebpf::metrics::registry::Registerer;
use common::error::Error::OSError;

type ParsedName = Vec<String>;

type ExportFunc = fn(exports: &mut HashMap<String, Box<dyn Any>>);

#[derive(Clone)]
pub struct Options {
    pub id: String,
    pub data_path: String, // A path to a directory with this component may use for storage.
    pub registerer: Arc<dyn Registerer>,
    pub get_service_data: fn(name: &str) -> Result<Box<dyn Any>, String>
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
        panic!("Component name {} already registered", r.name.clone());
    }

    let parsed = parse_component_name(&r.name).expect("invalid component name");

    parsed_names.insert(r.name.clone(), parsed);
    registered.insert(r.name.clone(), r);
}

fn parse_component_name(name: &str) -> Result<ParsedName> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.is_empty() {
        return Err(OSError("missing name".to_string()));
    }

    let identifier_regex = Regex::new(r"^[A-Za-z][0-9A-Za-z_]*$").unwrap();
    for part in &parts {
        if part.is_empty() {
            return Err(OSError("found empty identifier".to_string()));
        }
        if !identifier_regex.is_match(part) {
            return Err(OSError(format!("identifier {} is not valid", part.to_string())));
        }
    }
    Ok(parts.iter().map(|s| s.to_string()).collect())
}

fn get<'a>(name: &'a str, registered: &'a HashMap<String, Registration>) -> Option<&'a Registration> {
    registered.get(name)
}

fn all_names(registered: &HashMap<String, Registration>) -> Vec<String> {
    let mut keys: Vec<String> = registered.keys().cloned().collect();
    keys.sort();
    keys
}