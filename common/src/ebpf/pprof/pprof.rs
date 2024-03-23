use std::collections::HashMap;
use std::hash::Hasher;
use std::io::{self, Write};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use xxhash_rust::xxh3::xxh3_64;

use byteorder::{ByteOrder, LittleEndian};
use flate2::write::GzEncoder;
use flate2::Compression;
use pprof::protos::{Location, Profile, Mapping, ValueType, Sample, Function, Line};

struct ProfileBuilders {
    builders: HashMap<u64, ProfileBuilder>,
    sample_rate: i64,
}

impl ProfileBuilders {
    fn new(sample_rate: i64) -> Self {
        Self {
            builders: HashMap::new(),
            sample_rate,
        }
    }

    fn builder_for_target(&mut self, hash: u64, labels: Labels) -> &mut ProfileBuilder {
        self.builders
            .entry(hash)
            .or_insert_with(|| ProfileBuilder::new(labels, self.sample_rate))
    }
}

struct ProfileBuilder {
    locations: HashMap<String, Location>,
    functions: HashMap<String, Function>,
    sample_hash_to_sample: HashMap<u64, Sample>,
    profile: Profile,
    labels: Labels,

    tmp_locations: Vec<Location>,
    tmp_location_ids: Vec<u8>,
}

impl ProfileBuilder {
    fn new(labels: Labels, sample_rate: i64) -> Self {
        Self {
            locations: HashMap::new(),
            functions: HashMap::new(),
            sample_hash_to_sample: HashMap::new(),
            profile: Profile {
                mapping: vec![Mapping { id: 1 }],
                sample_type: vec![ValueType {
                    ty: *strings.get("cpu").unwrap() as i64,
                    unit: *strings.get("nanoseconds").unwrap() as i64,
                    ..Default::default()
                }],
                period: 1_000_000_000 / sample_rate,
                period_type: ValueType {
                    type_: "cpu".to_string(),
                    unit: "nanoseconds".to_string(),
                },
                time_nanos: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                ..Default::default()
            },
            labels,
            tmp_locations: Vec::with_capacity(128),
            tmp_location_ids: Vec::with_capacity(128),
        }
    }

    fn create_sample(&mut self, stacktrace: Vec<String>, value: u64) {
        let scaled_value = (value as i64) * self.profile.period;
        let mut sample = Sample {
            value: vec![scaled_value],
            ..Default::default()
        };

        for s in stacktrace {
            let loc = self.add_location(&s);
            sample.location.push(loc.clone());
        }

        self.profile.sample.push(sample);
    }

    fn create_sample_or_add_value(&mut self, stacktrace: Vec<&str>, value: u64) {
        let scaled_value = value as i64 * self.profile.period;
        self.tmp_locations.clear();
        self.tmp_location_ids.clear();

        for s in stacktrace {
            let loc = self.add_location(s);
            self.tmp_locations.push(loc.clone());
            self.tmp_location_ids.push(loc.id as u8);
        }

        let h = xxh3_64(&self.tmp_location_ids);

        if let Some(sample) = self.sample_hash_to_sample.get_mut(&h) {
            sample.value[0] += scaled_value;
            return;
        }

        let mut sample_location = vec![&Location::default(); self.tmp_locations.len()];
        sample_location.clone_from_slice(&self.tmp_locations);

        let sample = Sample {
            location_id: vec![],
            location: sample_location,
            value: vec![scaled_value],
            label: Default::default(),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        };

        self.sample_hash_to_sample.insert(h, sample.clone());
        self.profile.sample.push(sample);
    }

    fn add_location(&mut self, function: &str) -> Location {
        if let Some(loc) = self.locations.get(function) {
            return loc.clone();
        }

        let id = (self.profile.location.len() + 1) as u64;
        let loc = Location {
            id,
            mapping: self.profile.mapping[0].clone(),
            line: vec![Line {
                function: self.add_function(function),
            }],
            ..Default::default()
        };

        self.locations.insert(function.to_string(), loc.clone());
        self.profile.location.push(loc.clone());

        loc
    }

    fn add_function(&mut self, function: &str) -> Function {
        if let Some(func) = self.functions.get(function) {
            return func.clone();
        }

        let id = (self.profile.function.len() + 1) as u64;
        let func = Function {
            id,
            name: function.to_string(),
        };

        self.functions.insert(function.to_string(), func.clone());
        self.profile.function.push(func.clone());

        func
    }

    fn write(&self, dst: &mut dyn Write) -> io::Result<()> {
        let mut gz_encoder = GzEncoder::new(dst, Compression::default());
        self.profile
            .encode(&mut gz_encoder)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ebpf profile encode {}", e)))
    }
}

struct Labels {
    // Define label structure here
}

impl Default for Labels {
    fn default() -> Self {
        // Define default label values here
        Self {}
    }
}