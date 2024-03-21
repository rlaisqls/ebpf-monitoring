use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// Define the Label struct
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label {
    name: String,
    value: String,
}

impl Label {
    fn new(name: &str, value: &str) -> Self {
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

// Define the Labels struct
#[derive(Debug, Clone)]
pub struct Labels(Vec<Label>);

impl Labels {
    fn new(labels: Vec<Label>) -> Self {
        Self(labels)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Implement the fmt::Display trait for Labels
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

// Implement the FromStr trait for Labels
impl FromStr for Labels {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut labels = vec![];
        let pairs: Vec<&str> = s.trim_matches(|p| p == '{' || p == '}').split(',').collect();
        for pair in pairs {
            let parts: Vec<&str> = pair.split('=').collect();
            if parts.len() != 2 {
                return Err(());
            }
            let name = parts[0].trim();
            let value = parts[1].trim_matches('"');
            labels.push(Label::new(name, value));
        }
        Ok(Labels::new(labels))
    }
}

// Define the LabelsMap struct
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
