use std::{
    fs::DirEntry,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::interval;
use futures::future::join_all;
use common::ebpf::sd::target::{Target, TargetFinder};

use crate::appender::{Appendable, Fanout};
use crate::common::registry::Options;

// Define the component's arguments structure
#[derive(Debug)]
pub struct Arguments {
    pub forward_to: Vec<dyn Appendable>,
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
    pub demangle: Option<String>,
    pub python_enabled: Option<bool>,
}

// Define the component structure
#[derive(Debug)]
pub struct Component {
    options: Options,
    args: Arguments,
    target_finder: TargetFinder,
    session: Session,
    appendable: Fanout,
}

// Implement methods for the component
impl Component {
    // Create a new instance of the component
    pub async fn new(opts: Options, args: Arguments) -> Result<Self, Box<dyn std::error::Error>> {
        let target_finder = TargetFinder::new("/");
        let session = Session::new(&target_finder, convert_session_options(&args));

        let debug_info = DebugInfo {
            targets: target_finder.debug_info(),
            session: session.debug_info(),
        };

        Ok(Self {
            options: opts,
            args,
            target_finder,
            session,
            appendable: Fanout::new(args.forward_to, opts.id, opts.registerer),
            debug_info,
        })
    }

    // Start the component's main loop
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
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
    pub fn update(&mut self, args: Arguments) {
        self.args = args;
        self.session.update_targets(&targets_option_from_args(&self.args));
        self.appendable.update_children(&self.args.forward_to);
    }

    // Collect profiles
    async fn collect_profiles(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut builders = Vec::new();
        pprof::collect(&mut builders, &self.session).await?;
        let mut tasks = Vec::new();

        for builder in builders {
            let appender = self.appendable.appender();
            let args = self.args.clone();
            tasks.push(tokio::spawn(async move {
                let profile_data = builder.write()?;
                let service_name = builder.labels().get("service_name").unwrap_or_default();
                let samples = vec![Arc::new(RawSample::new(profile_data))];
                appender.append(samples, service_name, args.id).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }));
        }

        join_all(tasks).await.into_iter().collect::<Result<(), Box<dyn std::error::Error>>>()?;
        Ok(())
    }

    // Update debug information
    fn update_debug_info(&mut self) {
        let debug_info = EbpfDebugInfo {
            targets: self.target_finder.debug_info(),
            session: self.session.debug_info(),
        };
        self.debug_info = debug_info;
    }
}

// Convert session options
fn convert_session_options(args: &Arguments) -> ebpf::SessionOptions {
    let mut session_options = ebpf::SessionOptions::default();
    session_options.collect_user = args.collect_user_profile.unwrap_or(true);
    session_options.collect_kernel = args.collect_kernel_profile.unwrap_or(true);
    session_options.sample_rate = args.sample_rate.unwrap_or(97);
    session_options.python_enabled = args.python_enabled.unwrap_or(true);

    let symbol_options = symtab::SymbolOptions {
        go_table_fallback: false,
        demangle_options: demangle2::convert_demangle_options(args.demangle.as_ref().map(|s| s.as_str())),
    };

    session_options.symbol_options = symbol_options;

    let cache_options = symtab::CacheOptions {
        pid_cache_options: symtab::GCacheOptions {
            size: args.pid_cache_size.unwrap_or(32),
            keep_rounds: args.cache_rounds.unwrap_or(3),
        },
        build_id_cache_options: symtab::GCacheOptions {
            size: args.build_id_cache_size.unwrap_or(64),
            keep_rounds: args.cache_rounds.unwrap_or(3),
        },
        same_file_cache_options: symtab::GCacheOptions {
            size: args.same_file_cache_size.unwrap_or(8),
            keep_rounds: args.cache_rounds.unwrap_or(3),
        },
    };

    session_options.cache_options = cache_options;

    session_options
}

// Convert targets options from arguments
fn targets_option_from_args(args: &Arguments) -> discovery::TargetsOptions {
    let targets = args.targets.as_ref().map(|t| {
        t.iter().map(|target| {
            let entry = DirEntry::new();
