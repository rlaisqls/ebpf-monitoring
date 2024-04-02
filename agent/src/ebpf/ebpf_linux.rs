use std::{
    fs::DirEntry,
    sync::{Arc, Mutex},
    time::Duration,
};
use std::collections::HashMap;
use std::fs::File;
use tokio::time::interval;
use futures::future::join_all;
use common::ebpf::pprof;
use common::ebpf::sd::target::{TargetFinder, TargetsOptions};
use common::ebpf::session::{DiscoveryTarget, Session, SessionDebugInfo, SessionOptions};
use common::ebpf::symtab::elf_module::SymbolOptions;
use common::ebpf::symtab::gcache::GCacheOptions;
use common::ebpf::symtab::symbols::CacheOptions;

use crate::appender::{Appendable, Fanout, RawSample};
use crate::common::component::Component;
use crate::common::registry::Options;

type Target = HashMap<String, String>;
#[derive(Debug, Copy, Clone)]
pub struct Arguments {
    pub forward_to: Arc<Vec<dyn Appendable>>,
    pub targets: Option<Vec<Target>>,
    pub collect_interval: Option<Duration>,
    pub sample_rate: Option<i32>,
    pub pid_cache_size: Option<i32>,
    pub build_id_cache_size: Option<i32>,
    pub same_file_cache_size: Option<i32>,
    pub container_id_cache_size: Option<i32>,
    pub cache_rounds: Option<i32>,
    pub collect_user_profile: Option<bool>,
    pub collect_kernel_profile: Option<bool>,
    pub python_enabled: Option<bool>,
}

// Define the component structure
#[derive(Debug)]
pub struct EbpfLinuxComponent<'a> {
    options: Options,
    args: Arguments,
    target_finder: TargetFinder,
    session: Session<'a>,
    appendable: Fanout,
    debug_info: DebugInfo
}

struct DebugInfo {
    targets: Vec<String>,
    session: SessionDebugInfo
}

impl Component for EbpfLinuxComponent {

    async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut interval = interval(self.args.collect_interval.unwrap_or_else(|| Duration::from_secs(15)));

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

    // Update the component's arguments
    fn update(&mut self, args: Arguments) {
        self.args = args;
        self.session.update_targets(targets_option_from_args(&self.args));
        self.appendable.update_children(&self.args.forward_to);
    }
}

// Implement methods for the component
impl EbpfLinuxComponent {
    // Create a new instance of the component
    pub async fn new(opts: Options, args: Arguments) -> Result<Self, Box<dyn std::error::Error>> {
        let target_finder = TargetFinder::new(
            1024,
            File::open("/").unwrap()
        );
        let session = Session::new(&target_finder, convert_session_options(&args)).unwrap();

        Ok(Self {
            options: opts.clone(),
            args,
            target_finder,
            session,
            appendable: Fanout::new(args.forward_to, opts.id, opts.registerer),
            debug_info: DebugInfo { targets: vec![], session: Default::default() },
        })
    }

    // CollectProfiles
    async fn collect_profiles(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut builders = pprof::ProfileBuilders::new(1000);
        pprof::collect(&mut builders, &self.session).await?;

        for (_, builder) in builders.builders {
            let service_name = builder.labels.get();
        }

        Ok(())
    }

    // Update debug information
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