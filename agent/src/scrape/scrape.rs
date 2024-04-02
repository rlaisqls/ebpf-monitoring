use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, mpsc, RwLock};
use std::thread;
use std::time::Duration;
use log::{debug, error, info};
use tokio::select;
use common::common::labels::Labels;
use common::ebpf::sd::target::Target;
use common::error::Result;
use crate::appender::{Appendable, Appender, Fanout};
use crate::common::registry::Options;
use crate::scrape::{Group, LabelSet};
use crate::scrape::manager::Manager;

pub struct ProfilingTarget {
    pub enabled: bool,
    pub path: String,
    pub delta: bool,
}

struct CustomProfilingTarget {
    pub enabled: bool,
    pub path: String,
    pub delta: bool,
    pub name: String,
}

pub struct ProfilingConfig {
    pub memory: ProfilingTarget,
    pub block: ProfilingTarget,
    pub goroutine: ProfilingTarget,
    pub mutex: ProfilingTarget,
    pub process_cpu: ProfilingTarget,
    pub fgprof: ProfilingTarget,
    pub go_delta_prof_memory: ProfilingTarget,
    pub go_delta_prof_mutex: ProfilingTarget,
    pub go_delta_prof_block: ProfilingTarget,
    pub custom: Vec<CustomProfilingTarget>,
    pub pprof_prefix: String,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            memory: ProfilingTarget { enabled: true, path: "/debug/pprof/allocs".to_string(), delta: false },
            // Initialize other fields similarly
            pprof_prefix: String::new(),
            ..Default::default()
        }
    }
}

impl ProfilingConfig {
    pub(crate) fn all_targets(&self) -> HashMap<String, ProfilingTarget> {
        let mut targets = HashMap::new();
        targets.insert("memory".to_string(), self.memory.clone());
        // Insert other targets similarly
        targets
    }
}

pub struct Arguments {
    pub targets: Vec<Target>,
    pub forward_to: Vec<dyn Appendable>,
    pub job_name: Option<String>,
    pub params: HashMap<String, String>, // Assuming you need to store query parameters as key-value pairs
    pub scrape_interval: Duration,
    pub scrape_timeout: Duration,
    pub scheme: String,
    pub profiling_config: ProfilingConfig
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            forward_to: Vec::new(),
            job_name: None,
            params: HashMap::new(),
            scrape_interval: Duration::from_secs(15),
            scrape_timeout: Duration::from_secs(10),
            scheme: "http".to_string(),
            profiling_config: ProfilingConfig::default(),
        }
    }
}

pub struct ScrapeComponent {
    opts: Options,
    reload_targets: tokio::sync::mpsc::Sender<()>,
    args: RwLock<Arguments>,
    scraper: Arc<Manager>,
    appendable: Fanout,
}

impl ScrapeComponent {
    pub async fn new(opts: Options, args: Arguments) -> Result<Self> {
        let a = args.borrow();
        let flow_appendable = Fanout::new(Arc::new(args.forward_to), opts.id(), opts.registerer());
        let scraper = Manager::new(flow_appendable.clone());
        let c = Self {
            opts,
            reload_targets: tokio::sync::mpsc::channel(1).0,
            args: Arguments::default(),
            scraper: Arc::new(scraper),
            appendable: flow_appendable,
        };
        c.update(&a.clone()).await.expect("");
        Ok(c)
    }

    pub async fn run(&self) -> Result<(), String> {
        let scraper = Arc::clone(&self.scraper);
        let opts = self.opts.clone();
        let args = self.args.clone();
        let reload_targets = self.reload_targets.clone();

        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            scraper.deref().run(receiver);
            info!("scrape manager stopped");
        });

        loop {
            select! {
                _ = return Ok(()),
                _ = reload_targets.recv() => {
                    let tgs;
                    let job_name;
                    let clustering;

                    // Read lock to get the current state of args
                    {
                        let mut_lock = mut_lock.read().unwrap();
                        tgs = args.targets.clone();
                        job_name = args.id.clone();
                        clustering = args.clustering.enabled;
                    }

                    if !args.job_name.is_empty() {
                        job_name = args.job_name.clone();
                    }

                    // First approach, manually building the 'clustered' targets implementation every time.
                    let ct = discovery::new_distributed_targets(clustering, cluster.clone(), tgs);
                    let prom_targets = component_targets_to_prom(job_name.clone(), ct.get());

                    match target_sets_chan.send(prom_targets) {
                        Ok(_) => debug!(opts.logger, "passed new targets to scrape manager"),
                        Err(_) => return Ok(()), // This could be improved based on actual requirement
                    }
                }
            }
        }
    }

    async fn update(&self, args: Arguments) -> Result<(), String> {
        let a = args.borrow();
        self.appendable.update_children(args.forward_to);
        if let Err(err) = self.scraper.apply_config(a) {
            return Err(format!("error applying scrape configs: {}", err).into());
        }
        debug!("scrape config was updated");

        if let Err(_) = self.reload_targets.send(()) {
            error!("failed to send reload signal");
        }

        Ok(())
    }

    fn notify_cluster_change(&self) {
        // Implement the cluster change notification logic
    }

    fn component_targets_to_prom(&self, job_name: &str, tgs: &[Target]) -> HashMap<String, Vec<Group>> {
        let mut prom_group = Group { source: job_name.to_string(), targets: vec![], labels: HashMap::new() };

        for tg in tgs {
            let label_set = convert_label_set(tg); // Assuming convert_label_set converts discovery::Target to some label set
            prom_group.targets.push(label_set);
        }

        let mut result = HashMap::new();
        result.insert(job_name.to_string(), vec![prom_group]);

        result
    }
}

fn convert_label_set(tg: &Target) -> LabelSet {
    let mut label_set = Labels(Vec::new());
    for (k, v) in tg.iter() {
        label_set.insert(k.to_string(), v.to_string());
    }
    label_set
}