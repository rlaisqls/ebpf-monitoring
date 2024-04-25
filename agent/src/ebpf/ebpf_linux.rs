#[allow(unused_imports)]
use std::{
    sync::Arc,
    time::Duration,
};

use std::fs::File;
use std::sync::Mutex;
use std::borrow::Borrow;
use std::ops::Deref;
use std::thread;

use log::{error, info};
use tokio::time::interval;
use iwm::common::collector;
use iwm::ebpf::metrics::ebpf_metrics::EbpfMetrics;
use iwm::ebpf::metrics::metrics::ProfileMetrics;

use iwm::ebpf::{pprof};
use iwm::ebpf::pprof::BuildersOptions;
use iwm::ebpf::ring::reader::Reader;
use iwm::ebpf::sd::target::{LABEL_SERVICE_NAME, TargetFinder, TargetsOptions};
use iwm::ebpf::session::{Session, SessionDebugInfo, SessionOptions};
use iwm::ebpf::symtab::elf_module::SymbolOptions;
use iwm::ebpf::symtab::gcache::{GCacheOptions};
use iwm::ebpf::symtab::symbols::CacheOptions;
use iwm::ebpf::sync::PidOp;
use iwm::error::Error::OSError;

use iwm::error::Result;

use crate::appender::{Appendable, Fanout};
use crate::common::component::Component;
use crate::common::registry::Options;
use crate::discover::discover::Target;
use crate::write::write::FanOutClient;
pub mod push_api {
    include!("../api/push/push.v1.rs");
}

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
    pub python_enabled: bool
}

pub struct EbpfLinuxComponent<'a> {
    options: Options,
    args: Arguments,
    pub session: Arc<Mutex<Session<'a>>>,

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
    async fn run(&mut self) {
        let opts = TargetsOptions {
            targets: self.args.targets.clone(),
            targets_only: true,
            container_cache_size: 1024,
        };
        {
            let mut s = self.session.lock().unwrap();
            s.update_targets(&opts);
        }

        let mut interval = interval(self.args.collect_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let result = self.collect_profiles();
                    if let Err(err) = result {
                        dbg!(format!("ebpf profiling session failed: {}", err));
                    }
                    self.update_debug_info();
                }
            }
        }
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
            session: Arc::new(Mutex::new(session)),
            appendable: Box::new(Fanout::new(args.clone().forward_to, opts.id, opts.registerer.clone())),
            debug_info: DebugInfo { targets: vec![], session: SessionDebugInfo::default() },
            metrics: ms.clone()
        })
    }

    fn collect_profiles(&mut self) -> Result<()> {
        let builders = Arc::new(Mutex::new(pprof::ProfileBuilders::new(
            BuildersOptions { sample_rate: 1000, per_pid_profile: false }
        )));
        {
            let mut s = self.session.lock().unwrap();
            collector::collect(builders.clone(), &mut s).unwrap();
        }

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
        let mut s = self.session.lock().unwrap();
        let targets = {
            let mut target_finder = s.target_finder.lock().unwrap() ;
            target_finder.debug_info().clone()
        };
        let debug_info = DebugInfo {
            targets,
            session: s.debug_info().unwrap(),
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
