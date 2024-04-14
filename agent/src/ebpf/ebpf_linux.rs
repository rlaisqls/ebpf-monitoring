use std::{
    sync::Arc,
    time::Duration,
};

use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;
use std::borrow::Borrow;

use log::error;
use tokio::time::interval;
use common::common::collector;
use common::ebpf::metrics::ebpf_metrics::EbpfMetrics;
use common::ebpf::metrics::metrics::ProfileMetrics;

use common::ebpf::pprof;
use common::ebpf::pprof::BuildersOptions;
use common::ebpf::sd::target::{LABEL_SERVICE_NAME, TargetFinder, TargetsOptions};
use common::ebpf::session::{Session, SessionDebugInfo, SessionOptions};
use common::ebpf::symtab::elf_module::SymbolOptions;
use common::ebpf::symtab::gcache::{GCacheOptions};
use common::ebpf::symtab::symbols::CacheOptions;
use common::error::Error::OSError;

use common::error::Result;

use crate::appender::{Appendable, Appender, Fanout};
use crate::common::component::Component;
use crate::common::registry::Options;
use crate::write::write::FanOutClient;
pub mod push_api {
    include!("../api/push/push.v1.rs");
}

type Target = HashMap<String, String>;

#[derive(Clone)]
pub struct Arguments {
    pub forward_to: Arc<Vec<Box<FanOutClient>>>,
    pub targets: Vec<Target>,
    pub collect_interval: Duration,
    pub sample_rate: i32,
    pub pid_cache_size: i32,
    pub build_id_cache_size: i32,
    pub same_file_cache_size: i32,
    pub container_id_cache_size: i32,
    pub cache_rounds: i32,
    pub collect_user_profile: bool,
    pub collect_kernel_profile: bool,
    pub python_enabled: bool,
}

pub struct EbpfLinuxComponent<'a> {
    options: Options,
    args: Arguments,
    session: Session<'a>,

    appendable: Box<Fanout>,
    debug_info: DebugInfo,
    metrics: Arc<EbpfMetrics>
}

struct DebugInfo {
    targets: Vec<String>,
    session: SessionDebugInfo
}

impl Default for DebugInfo {
    fn default() -> Self {
        Self {
            targets: vec![],
            session: SessionDebugInfo::default(),
        }
    }
}


impl Component for EbpfLinuxComponent<'_> {
    fn run(&mut self) -> Result<()> {
        let mut interval = interval(self.args.collect_interval);
        loop {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                tokio::select! {
                _ = interval.tick() => {
                    let result = self.collect_profiles();
                    if let Err(err) = result {
                        dbg!(format!("ebpf profiling session failed: {}", err));
                    }
                    self.update_debug_info();
                }
            } });
        }
        Ok(())
    }
}

impl EbpfLinuxComponent<'_> {

    async fn update(&mut self, _args: Arguments) -> Result<()> {
        Ok(())
    }

    pub async fn new(opts: Options, args: Arguments) -> Result<Self> {
        let target_finder = Arc::new(Mutex::new(TargetFinder::new(
            1024,
            File::open("/").unwrap()
        )));
        let ms = Arc::new(EbpfMetrics::new(opts.registerer.borrow()));
        let sesstion_opts = convert_session_options(&args.clone(), ms.clone().profile_metrics.clone());
        let session = Session::new(target_finder, sesstion_opts).unwrap();

        Ok(Self {
            options: opts.clone(),
            args: args.clone(),
            session,
            appendable: Box::new(Fanout::new(args.clone().forward_to, opts.id, opts.registerer.clone())),
            debug_info: DebugInfo { targets: vec![], session: SessionDebugInfo::default() },
            metrics: ms.clone()
        })
    }

    fn collect_profiles(&mut self) -> Result<()> {
        let builders = Arc::new(Mutex::new(pprof::ProfileBuilders::new(
            BuildersOptions { sample_rate: 1000, per_pid_profile: false }
        )));
        collector::collect(builders.clone(), &mut self.session).unwrap();

        let bb = builders.clone();
        let b = bb.lock().unwrap();
        for (_, builder) in &b.builders {
            let sn = builder.labels.get(LABEL_SERVICE_NAME);
            let a = sn.unwrap();
            let service_name = a.trim();
            self.metrics.pprofs_total
                .with_label_values(&[service_name]).inc();
            self.metrics.pprof_samples_total
                .with_label_values(&[service_name])
                .inc_by(builder.profile.sample.len() as f64);

            let mut buf = vec![];
            builder.write(&mut buf);

            let raw_profile: Vec<u8> = buf.into();
            self.metrics.pprof_bytes_total
                .with_label_values(&[service_name])
                .inc_by(raw_profile.len() as f64);

            let samples = vec![push_api::RawSample { raw_profile, id: "".to_string() }];
            let appender = self.appendable.appender();
            if let Err(err) = appender.append(
                builder.labels.clone(),
                samples
            ) {
                error!("ebpf pprof write err {}", err);
                return Err(OSError(format!("{}", err)));
            }
        }
        Ok(())
    }

    fn update_debug_info(&mut self) {
        let targets = {
            let mut target_finder = self.session.target_finder.lock().unwrap() ;
            target_finder.debug_info().clone()
        };
        let debug_info = DebugInfo {
            targets,
            session: self.session.debug_info().unwrap(),
        };
        self.debug_info = debug_info;
    }
}

fn convert_session_options(_args: &Arguments, ms: Arc<ProfileMetrics>) -> SessionOptions {
    let keep_rounds = 3;//args.cache_rounds.unwrap_or(3);
    SessionOptions {
        collect_user: true, // args.collect_user_profile.unwrap_or(true),
        collect_kernel: true, //args.collect_kernel_profile.unwrap_or(true),
        unknown_symbol_module_offset: false,
        sample_rate: 97, //args.sample_rate.unwrap_or(97) as u32,
        python_enabled: true, //args.python_enabled.unwrap_or(true),
        cache_options: CacheOptions {
            pid_cache_options: GCacheOptions {
                size: 32, //args.pid_cache_size.unwrap_or(32) as usize,
                keep_rounds
            },
            build_id_cache_options: GCacheOptions {
                size: 64, //args.build_id_cache_size.unwrap_or(64) as usize,
                keep_rounds
            },
            same_file_cache_options: GCacheOptions {
                size: 8, //args.same_file_cache_size.unwrap_or(8) as usize,
                keep_rounds
            },
            symbol_options: SymbolOptions::default()
        },
        unknown_symbol_address: false,
        metrics: ms,
    }
}

fn targets_option_from_args(args: &Arguments) -> TargetsOptions {
    TargetsOptions {
        targets: args.clone().targets,
        targets_only: true,
        container_cache_size: args.container_id_cache_size as usize,
    }
}