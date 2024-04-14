use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// Define the Label struct
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label {
    pub name: String,
    pub value: String,
}

impl Label {
    pub fn new(name: String, value: String) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=\"{}\"", self.name, self.value)
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.value.hash(state);
    }
}

#[derive(Debug, Clone)]
pub struct Labels(pub Vec<Label>);

impl Labels {
    pub fn new(labels: Vec<Label>) -> Self { Self(labels) }
    pub fn from_map(hashmap: HashMap<String, String>) -> Labels {
        Labels(
            hashmap
                .into_iter()
                .map(|(name, value)| Label::new(name, value))
                .collect()
        )
    }
    pub fn get(&self, name: &str) -> Option<String> {
        let mut map = HashMap::new();
        for label in &self.0 {
            map.insert(label.name.clone(), label.value.clone());
        }
        Some(map[name].clone())
    }
    pub fn set(&mut self, name: &str, value: &str) {
        if self.get(name).is_some() {
            self.0.retain(|l| l.name == name);
        }
        self.0.push(Label { name: name.to_string(), value: value.to_string() })
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn hash(&self) -> u64 {
        let mut hasher = xxhash_rust::xxh64::Xxh64::new(0);
        let mut buffer = Vec::with_capacity(1024);
        let sep: u8 = 0xff;

        for label in &self.0 {
            buffer.clear();
            buffer.extend(label.name.as_bytes());
            buffer.push(sep);
            buffer.extend(label.value.as_bytes());
            buffer.push(sep);
            hasher.write(&buffer);
        }
        hasher.finish()
    }
}

impl fmt::Display for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (i, label) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", label)?;
        }
        write!(f, "}}")
    }
}

impl FromStr for Labels {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut labels = vec![];
        let pairs: Vec<&str> = s.trim_matches(|p| p == '{' || p == '}').split(',').collect();
        for pair in pairs {
            let parts: Vec<&str> = pair.split('=').collect();
            let name = parts[0].trim();
            let value = parts[1].trim_matches('"');
            labels.push(Label::new(name.to_string(), value.to_string()));
        }
        Ok(Labels::new(labels))
    }
}

#[derive(Debug, Clone)]
struct LabelsMap(BTreeMap<String, String>);

impl LabelsMap {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn insert(&mut self, name: &str, value: &str) {
        self.0.insert(name.to_string(), value.to_string());
    }

    fn get(&self, name: &str) -> Option<&String> {
        self.0.get(name)
    }

    fn remove(&mut self, name: &str) -> Option<String> {
        self.0.remove(name)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
