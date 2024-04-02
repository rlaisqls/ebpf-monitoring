use std::collections::HashMap;
use common::common::labels::Label;

pub mod target;
pub mod scrape;
pub mod scrape_loop;
pub mod manager;

pub type Profile = Vec<u8>;
pub type LabelSet = HashMap<String, String>;

pub struct Group {
    targets: Vec<LabelSet>,
    labels: LabelSet,
    source: String,
}