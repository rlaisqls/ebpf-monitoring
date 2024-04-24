use std::collections::HashMap;

use crate::ebpf::pprof::profiles::{Function, Line, Location, Profile};


// Referenced from https://github.com/grafana/pyroscope-rs/blob/a70f3256bab624b25f365dd4afa0bc959ff69f50/src/encode/pprof.rs
#[derive(Clone)]
pub struct PProfBuilder {
    profile: Profile,
    strings: HashMap<String, i64>,
    functions: HashMap<FunctionMirror, u64>,
    locations: HashMap<LocationMirror, u64>,
}

impl Default for PProfBuilder {
    fn default() -> Self {
        Self {
            profile: Profile::default(),
            strings: HashMap::new(),
            functions: HashMap::new(),
            locations: HashMap::new()
        }
    }
}


#[derive(Hash, PartialEq, Eq, Clone)]
pub struct LocationMirror {
    pub function_id: u64,
    pub line: i64,
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct FunctionMirror {
    pub name: i64,
    pub filename: i64,
}

impl PProfBuilder {
    pub fn add_string(&mut self, s: &String) -> i64 {
        let v = self.strings.get(s);
        if let Some(v) = v {
            return *v;
        }
        assert_ne!(self.strings.len(), self.profile.string_table.len() + 1);
        let id: i64 = self.strings.len() as i64;
        self.strings.insert(s.to_owned(), id);
        self.profile.string_table.push(s.to_owned());
        id
    }

    pub fn add_function(&mut self, fm: FunctionMirror) -> u64 {
        let v = self.functions.get(&fm);
        if let Some(v) = v {
            return *v;
        }
        assert_ne!(self.functions.len(), self.profile.function.len() + 1);
        let id: u64 = self.functions.len() as u64 + 1;
        let f = Function {
            id,
            name: fm.name,
            system_name: 0,
            filename: fm.filename,
            start_line: 0,
        };
        self.functions.insert(fm, id);
        self.profile.function.push(f);
        id
    }

    pub fn add_location(&mut self, lm: LocationMirror) -> u64 {
        let v = self.locations.get(&lm);
        if let Some(v) = v {
            return *v;
        }
        assert_ne!(self.locations.len(), self.profile.location.len() + 1);
        let id: u64 = self.locations.len() as u64 + 1;
        let l = Location {
            id,
            mapping_id: 0,
            address: 0,
            line: vec![Line {
                function_id: lm.function_id,
                line: lm.line,
            }],
            is_folded: false,
        };
        self.locations.insert(lm, id);
        self.profile.location.push(l);
        id
    }
}