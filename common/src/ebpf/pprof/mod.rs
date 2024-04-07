use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use prost::Message;

use crate::common::labels::Labels;
use crate::ebpf::pprof::pprof::PProfBuilder;
use crate::ebpf::pprof::profiles::{Function, Line, Location, Profile, Sample, ValueType};
use crate::ebpf::sd::target::Target;
use crate::error::Result;

mod profiles;
mod pprof;

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

pub fn collect(builders: &mut ProfileBuilders, collector: &dyn SamplesCollector) -> Result<(), String> {
    collector.collect_profiles(|sample| {
        builders.add_sample(sample);
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BuildersOptions {
    pub sample_rate: i64,
    pub per_pid_profile: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BuilderHashKey {
    pub labels_hash: u64,
    pub pid: u32,
    pub sample_type: SampleType,
}

pub struct ProfileBuilders {
    pub builders: HashMap<BuilderHashKey, ProfileBuilder>,
    pub opt: BuildersOptions
}

impl ProfileBuilders {
    pub fn new(options: BuildersOptions) -> Self {
        Self {
            builders: HashMap::new(),
            opt: options,
        }
    }

    fn add_sample(&mut self, sample: ProfileSample) {
        let bb = self.builder_for_sample(&sample);
        bb.create_sample(sample);
    }

    fn builder_for_sample(&mut self, sample: &ProfileSample) -> &mut ProfileBuilder {
        let (labels_hash, labels) = sample.target.clone().labels();

        let mut k = BuilderHashKey {
            labels_hash,
            sample_type: sample.sample_type,
            pid: 0,
        };
        if self.opt.per_pid_profile {
            k.pid = sample.pid;
        }

        let mut b = PProfBuilder::default();
        let from_b = |s: &str| { b.add_string(&s.to_string()) };
        self.builders.entry(k).or_insert_with(|| {
            let (sample_type, period_type, period) = if sample.sample_type == SAMPLE_TYPE_CPU {
                (
                    vec![ValueType { r#type: from_b("cpu"), unit: from_b("nanoseconds"), }],
                    ValueType { r#type: from_b("cpu"), unit: from_b("nanoseconds") },
                    (Duration::from_secs(1).as_nanos() as i64) / self.opt.sample_rate,
                )
            } else {
                (
                    vec![
                        ValueType { r#type: from_b("alloc_objects"), unit: from_b("count") },
                        ValueType { r#type: from_b("alloc_space"), unit: from_b("bytes"), },
                    ],
                    ValueType { r#type: b.add_string(&"space".to_string()), unit: from_b("bytes") },
                    512 * 1024,
                )
            };
            ProfileBuilder {
                labels: labels.clone(),
                profile: Profile {
                    sample_type,
                    time_nanos: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_nanos() as i64,
                    duration_nanos: period as i64,
                    period_type: Some(period_type),
                    ..Default::default()
                },
                tmp_location_ids: Vec::with_capacity(128),
                tmp_locations: Vec::with_capacity(128),
                pprof_builder: b,
                ..Default::default()
            }
        })
    }
}

struct ProfileBuilder {
    pub locations: HashMap<String, Location>,
    pub functions: HashMap<String, Function>,
    pub sample_hash_to_sample: HashMap<u64, Sample>,
    pub profile: Profile,
    pub labels: Labels,

    pub tmp_locations: Vec<Location>,
    pub tmp_location_ids: Vec<u64>,

    pub pprof_builder: PProfBuilder
}

impl Default for ProfileBuilder {
    fn default() -> Self {
        Self {
            locations: HashMap::new(),
            functions: HashMap::new(),
            sample_hash_to_sample: HashMap::new(),
            profile: Profile {
                sample_type: vec![],
                sample: vec![],
                mapping: vec![],
                location: vec![],
                function: vec![],
                string_table: vec![],
                drop_frames: 0,
                keep_frames: 0,
                time_nanos: 0,
                duration_nanos: 0,
                period_type: None,
                period: 0,
                comment: vec![],
                default_sample_type: 0,
            },
            labels: Labels(vec![]),
            tmp_locations: vec![],
            tmp_location_ids: vec![],
            pprof_builder: Default::default(),
        }
    }
}

impl ProfileBuilder {

    fn create_sample(&mut self, input_sample: ProfileSample) {
        let mut sample = Sample {
            value: if input_sample.sample_type == SampleType::Cpu { vec![0] } else { vec![0, 0] },
            location_id: Vec::new(),
            label: vec![],
        };
        for s in input_sample.stack {
            sample.location_id.push(self.add_location(s.as_str()).id);
        }
        self.profile.sample.push(sample);
    }

    fn create_sample_or_add_value(&mut self, input_sample: &ProfileSample) {
        self.tmp_locations.clear();
        self.tmp_location_ids.clear();

        for s in &input_sample.stack {
            let loc = self.add_location(s);
            self.tmp_locations.push(loc.clone());
            self.tmp_location_ids.push(loc.id);
        }

        let mut hasher = DefaultHasher::new();
        self.tmp_location_ids.hash(&mut hasher);
        let h = hasher.finish();

        if let Some(sample) = self.sample_hash_to_sample.get_mut(&h) {
            self.add_value(input_sample, sample);
            return;
        }

        let mut sample = self.new_sample(input_sample);
        self.add_value(input_sample, &mut sample);
        sample.location_id.copy_from_slice(&self.tmp_location_ids);
        self.sample_hash_to_sample.insert(h, sample.clone());
        self.profile.sample.push(sample);
    }

    fn new_sample(&self, input_sample: &ProfileSample) -> Sample {
        let mut sample = Sample::default();
        if input_sample.sample_type == SampleType::Cpu {
            sample.value = vec![0];
        } else {
            sample.value = vec![0, 0];
        }
        sample.location_id = vec![0; input_sample.stack.len()];
        sample
    }

    fn add_value(&self, input_sample: &ProfileSample, sample: &mut Sample) {
        if input_sample.sample_type == SampleType::Cpu {
            sample.value[0] += input_sample.value * self.profile.period;
        } else {
            sample.value[0] += input_sample.value;
            sample.value[1] += input_sample.value2;
        }
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
            start_line: 0
        };

        self.functions.insert(function.to_string(), func.clone());
        self.profile.function.push(func.clone());

        func
    }

    pub fn write(&self, dst: &mut dyn Write) {
        let mut gzip_writer = GzEncoder::new(
            dst, Compression::default()
        );
        let mut content = Vec::new();
        self.profile.encode(&mut content).unwrap();
        gzip_writer.write(content.as_slice()).unwrap();
        gzip_writer.finish().unwrap();
    }
}