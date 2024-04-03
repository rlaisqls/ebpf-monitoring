use std::collections::HashMap;
use std::hash::Hasher;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use pprof::protos::{Function, Line, Location, Profile, Sample};

use crate::common::labels::Labels;
use crate::ebpf::sd::target::Target;
use crate::error::Error::{InvalidData};
use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SampleType {
    Cpu = 0,
    Mem = 1,
}

const SAMPLE_TYPE_CPU: SampleType = SampleType::Cpu;
const SAMPLE_TYPE_MEM: SampleType = SampleType::Mem;

trait SamplesCollector {
    fn collect_profiles(&self, callback: CollectProfilesCallback) -> Result<(), String>;
}

struct ProfileSample<'a> {
    target: &'a Target,
    pid: u32,
    sample_type: SampleType,
    aggregation: bool,
    stack: Vec<String>,
    value: u64,
    value2: u64,
}

type CollectProfilesCallback = fn(ProfileSample);

pub fn collect(builders: &ProfileBuilders, collector: &dyn SamplesCollector) -> Result<(), String> {
    collector.collect_profiles(|sample| {
        builders.add_sample(sample);
    })
}

pub struct ProfileBuilders {
    pub builders: HashMap<u64, ProfileBuilder>,
    sample_rate: i64,
}

impl ProfileBuilders {
    pub fn new(sample_rate: i64) -> Self {
        Self {
            builders: HashMap::new(),
            sample_rate,
        }
    }
    pub fn builder_for_target(&mut self, hash: u64, labels: Labels) -> &mut ProfileBuilder {
        self.builders
            .entry(hash)
            .or_insert_with(|| ProfileBuilder::new(labels, self.sample_rate))
    }
    fn add_sample(&mut self, sample: &ProfileSample) {
        let bb = self.builder_for_sample(sample);
        bb.create_sample(sample);
    }
    fn builder_for_sample(&mut self, sample: &ProfileSample) -> &mut ProfileBuilder {
        let (labels_hash, labels) = sample.target.labels();

        let mut k = BuilderHashKey {
            labels_hash,
            sample_type: sample.sample_type,
        };
        if self.opt.per_pid_profile {
            k.pid = sample.pid;
        }

        let res = self.builders.entry(k).or_insert_with(|| {
            let (sample_type, period_type, period) = if sample.sample_type == SampleTypeCpu {
                (
                    vec![profile::ValueType {
                        r#type: "cpu".to_string(),
                        unit: "nanoseconds".to_string(),
                    }],
                    profile::ValueType {
                        r#type: "cpu".to_string(),
                        unit: "nanoseconds".to_string(),
                    },
                    std::time::Duration::from_secs(1).as_nanos() / self.opt.sample_rate,
                )
            } else {
                (
                    vec![
                        profile::ValueType {
                            r#type: "alloc_objects".to_string(),
                            unit: "count".to_string(),
                        },
                        profile::ValueType {
                            r#type: "alloc_space".to_string(),
                            unit: "bytes".to_string(),
                        },
                    ],
                    profile::ValueType {
                        r#type: "space".to_string(),
                        unit: "bytes".to_string(),
                    },
                    512 * 1024, // todo
                )
            };

            let mut builder = ProfileBuilder {
                locations: HashMap::new(),
                functions: HashMap::new(),
                sample_hash_to_sample: HashMap::new(),
                labels: labels.clone(),
                profile: profile::Profile {
                    mapping: vec![profile::Mapping { id: 1 }],
                    sample_type,
                    period,
                    period_type,
                    time_nanos: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_nanos(),
                },
                tmp_location_ids: Vec::with_capacity(128),
                tmp_locations: Vec::with_capacity(128),
            };
            builder
        });

        res
    }
}

struct ProfileBuilder {
    locations: HashMap<String, Location>,
    functions: HashMap<String, Function>,
    sample_hash_to_sample: HashMap<u64, Sample>,
    pub profile: Profile,
    pub labels: Labels,

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
        let sample = Sample {
            value: vec![scaled_value],
            ..Default::default()
        };
        for (i, s) in sample.stack.iter().enumerate() {
            sample.location[i] = self.add_location(s);
        }
        self.profile.sample.push(sample);
    }

    fn add_location(&mut self, function: &str) -> Location {
        if let Some(loc) = self.locations.get(function) {
            return loc.clone();
        }

        let id = (self.profile.location.len() + 1) as u64;
        let loc = Location {
            id,
            mapping_id: self.profile.mapping[0].clone().id,
            line: vec![Line {
                function_id: self.add_function(function).id,
                ..Default::default()
            }].into(),
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
            name: function.to_string().parse().unwrap(),
            system_name: 0,
            filename: 0,
            start_line: 0,
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        };

        self.functions.insert(function.to_string(), func.clone());
        self.profile.function.push(func.clone());

        func
    }

    pub fn write(&self, dst: &mut dyn Write) -> Result<()> {
        let mut gz_encoder = GzEncoder::new(dst, Compression::default());
        self.profile
            .encode(&mut gz_encoder)
            .map_err(|e| Err(InvalidData(format!("ebpf profile encode {}", e))));
    }
}