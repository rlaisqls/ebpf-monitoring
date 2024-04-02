use std::{
    sync::Arc,
    time::Duration,
};
use std::collections::HashMap;
use std::fs::File;
use log::error;
use tokio::time::interval;
use common::ebpf::pprof;
use common::ebpf::sd::target::{TargetFinder, TargetsOptions};
use common::ebpf::session::{Session, SessionDebugInfo, SessionOptions};
use common::ebpf::symtab::elf_module::SymbolOptions;
use common::ebpf::symtab::gcache::GCacheOptions;
use common::ebpf::symtab::symbols::CacheOptions;
use common::error::Error::{NotFound, OSError};
use common::error::Result;

use crate::appender::{Appendable, Fanout, RawSample};
use crate::common::component::Component;
use crate::common::registry::Options;
use crate::ebpf::metrics::metrics;
use crate::scrape::target::SERVICE_NAME_LABEL;

type Target = HashMap<String, String>;
#[derive(Debug, Copy, Clone)]
pub struct Arguments {
    pub forward_to: Arc<Vec<dyn Appendable>>,
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

// Define the component structure
#[derive(Debug)]
pub struct EbpfLinuxComponent<'a> {
    options: Options,
    args: Arguments,
    target_finder: TargetFinder,
    session: Session<'a>,

    appendable: Fanout,
    debug_info: DebugInfo,
    metrics: metrics
}

struct DebugInfo {
    targets: Vec<String>,
    session: SessionDebugInfo
}

impl Component for EbpfLinuxComponent {
    async fn run(mut self) -> Result<()> {
        let mut interval = interval(self.args.collect_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let result = self.collect_profiles().await;
                    if let Err(err) = result {
                        dbg!(format!("ebpf profiling session failed: {}", err));
                    }
                    self.update_debug_info();
                }
                _ = self.session.changed() => {
                    let debug_info = DebugInfo {
                        targets: self.target_finder.debug_info(),
                        session: self.session.debug_info(),
                    };
                    self.debug_info = debug_info;
                }
            }
        }
    }

    fn update(&mut self, args: Arguments) {
        self.args = args;
        self.session.update_targets(targets_option_from_args(&self.args));
        self.appendable.update_children(&self.args.forward_to);
    }
}

impl EbpfLinuxComponent {
    pub async fn new(opts: Options, args: Arguments) -> Result<Self> {
        let target_finder = TargetFinder::new(
            1024,
            File::open("/").unwrap()
        );
        let ms = metrics::new(opts.registerer.borrow());
        let session = Session::new(&target_finder, convert_session_options(&args)).unwrap();

        Ok(Self {
            options: opts.clone(),
            args,
            target_finder,
            session,
            appendable: Fanout::new(args.forward_to, opts.id, opts.registerer),
            debug_info: DebugInfo { targets: vec![], session: Default::default() },
            metrics: ms
        })
    }

    async fn collect_profiles(&self) -> Result<()> {
        let mut builders = pprof::ProfileBuilders::new(1000);
        pprof::collect(&mut builders, &self.session).await?;
        for (_, builder) in builders.builders {
            let service_name = builder.labels.get(SERVICE_NAME_LABEL).unwrap().trim();
            self.metrics.pprofs_total
                .with_label_values(&[service_name]).inc();
            self.metrics.pprof_samples_total
                .with_label_values(&[service_name])
                .inc_by(builder.profile.sample.len() as f64);

            let mut buf = vec![];
            builder.write(&mut buf)?;

            let raw_profile = buf.into();
            let samples = vec![RawSample { raw_profile }];
            self.metrics.pprof_bytes_total
                .with_label_values(&[service_name])
                .add(raw_profile.len() as f64);

            let appender = self.appendable.appender();
            if let Err(err) = appender.append(
                builder.labels().clone(),
                samples,
            ) {
                error!("ebpf pprof write", "err" => format!("{}", err));
                return Err(OSError(format!("{}", err)));
            }
        }
        Ok(())
    }

    fn update_debug_info(&mut self) {
        let debug_info = DebugInfo {
            targets: self.target_finder.debug_info(),
            session: self.session.debug_info(),
        };
        self.debug_info = debug_info;
    }
}

fn convert_session_options(args: &Arguments) -> SessionOptions {
    let keep_rounds = args.cache_rounds.unwrap_or(3);
    SessionOptions {
        collect_user: args.collect_user_profile.unwrap_or(true),
        collect_kernel: args.collect_kernel_profile.unwrap_or(true),
        sample_rate: args.sample_rate.unwrap_or(97) as u32,
        python_enabled: args.python_enabled.unwrap_or(true),
        cache_options: CacheOptions {
            pid_cache_options: GCacheOptions {
                size: args.pid_cache_size.unwrap_or(32) as usize,
                keep_rounds
            },
            build_id_cache_options: GCacheOptions {
                size: args.build_id_cache_size.unwrap_or(64) as usize,
                keep_rounds
            },
            same_file_cache_options: GCacheOptions {
                size: args.same_file_cache_size.unwrap_or(8) as usize,
                keep_rounds
            },
            symbol_options: SymbolOptions::default()
        },
        ..Default::default()
    }
}

fn targets_option_from_args(args: &Arguments) -> TargetsOptions {
    TargetsOptions {
        targets: args.clone().targets.unwrap_or_default(),
        targets_only: true,
        container_cache_size: args.container_id_cache_size.unwrap_or_default() as usize,
        ..Default::default()
    }
}