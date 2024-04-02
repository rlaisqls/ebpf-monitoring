use std::collections::HashMap;
use std::hash::Hash;
use std::io::{copy, Cursor, Write};
use std::sync::{Arc, Mutex, Once};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::task::Context;
use std::thread;
use std::time::{Duration, Instant};
use log::{error, info};
use tonic::codegen::tokio_stream::StreamExt;
use common::common::labels::{Label, Labels};
use common::ebpf::sd::target::METRIC_NAME;
use common::ebpf::wait_group::WaitGroup;
use common::error::{Error, Result};
use crate::appender::{Appender, RawSample};
use crate::scrape::{Group};
use crate::scrape::scrape::{Arguments, ProfilingTarget};
use crate::scrape::target::{ADDRESS_LABEL, labels_by_profiles, PARAM_LABEL_PREFIX, populate_labels, PROFILE_NAME, PROFILE_PATH, SCHEME_LABEL, Target, TargetHealth};


pub struct ScrapePool {
    config: Arguments,
    appendable: Arc<dyn Appender>,
    mtx: Mutex<()>,
    active_targets: HashMap<u64, ScrapeLoop>,
    dropped_targets: Vec<Target>,
}

impl ScrapePool {
    fn new(cfg: Arguments, appendable: Arc<dyn Appender>) -> Result<Self, Error> {
        Ok(ScrapePool {
            config: cfg,
            appendable,
            mtx: Mutex::new(()),
            active_targets: HashMap::new(),
            dropped_targets: Vec::new(),
        })
    }

    pub(crate) async fn sync(&mut self, groups: Vec<Group>) {
        let _mtx = self.mtx.lock().unwrap();
        info!(self.logger, "syncing target groups"; "job" => self.config.job_name.clone());

        let all_targets = self.config.profiling_config.all_targets();
        let mut actives = Vec::new();

        for group in groups {
            let (targets, dropped) = targets_from_group(&group, &self.config, &all_targets).unwrap();
            for t in &targets {
                if !t.labels().is_empty() {
                    actives.push(Arc::new(t.clone()));
                }
            }
            self.dropped_targets.extend(dropped);
        }

        for t in actives {
            let hash = t.hash;
            if !self.active_targets.contains_key(&hash) {
                let mut loop_ = ScrapeLoop::new(
                    t,
                    self.appendable.clone(),
                    self.config.scrape_interval,
                    self.config.scrape_timeout
                );
                self.active_targets.insert(hash, loop_);
                loop_.start().await;
            } else {
                if let Some(loop_) = self.active_targets.get_mut(&hash) {
                    loop_.set_discovered_labels(t.discovered_labels());
                }
            }
        }

        // Removes inactive targets.
        let mut to_remove = Vec::new();
        for (h, loop_) in &mut self.active_targets {
            if !actives.iter().any(|t| t.hash() == *h) {
                loop_.stop(false).await;
                to_remove.push(*h);
            }
        }
        for h in to_remove {
            self.active_targets.remove(&h);
        }
    }

    async fn reload(&mut self, cfg: Arguments) -> Result<(), Error> {
        if self.config.scrape_interval == cfg.scrape_interval && self.config.scrape_timeout == cfg.scrape_timeout  {
            self.config = cfg;
            return Ok(());
        }
        self.config = cfg;

        for (hash, t) in &mut self.active_targets {
            t.stop(false).await;
            let mut loop_ = ScrapeLoop::new(
                t.target.clone(),
                self.appendable.clone(),
                self.config.scrape_interval,
                self.config.scrape_timeout
            );
            self.active_targets.insert(*hash, loop_);
            loop_.start().await;
        }
        Ok(())
    }

    async fn stop(&mut self) {
        let _mtx = self.mtx.lock().unwrap();
        let mut threads = vec![];
        for (_, t) in &mut self.active_targets {
            let handle = thread::spawn(async move || {
                t.stop(true);
            });
            threads.push(handle);
        }
        for handle in threads {
            handle.join().unwrap();
        }
    }

    fn targets_active(&self) -> HashMap<String, Vec<Target>> {
        let mut targets = HashMap::new();
        let mut handles = vec![];

        {
            for (tset, sp) in &self.active_targets {
                let tset = tset.clone();
                let sp = Arc::clone(sp);
                let handle = thread::spawn(move || {
                    let active_targets = sp.lock().unwrap().active_targets();
                    (tset, active_targets)
                });
                handles.push(handle);
            }
        }

        for handle in handles {
            let (tset, active_targets) = handle.join().unwrap();
            targets.insert(tset, active_targets);
        }
        targets
    }

    fn targets_dropped(&self) -> Vec<Target> {
        self.dropped_targets.clone()
    }
}

impl Drop for ScrapePool {
    fn drop(&mut self) {
        let _ = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(self.stop());
    }
}

fn targets_from_group(group: &Group, cfg: &Arguments, target_types: &HashMap<String, ProfilingTarget>) -> Result<(Vec<Target>, Vec<Target>)> {
    let mut targets = Vec::new();
    let mut dropped_targets = Vec::new();

    for (i, tlset) in group.targets.iter().enumerate() {
        let mut lbls = Vec::with_capacity(tlset.len() + group.labels.len());

        for (ln, lv) in tlset.iter() {
            lbls.push(Label::new(ln.clone(), lv.clone()));
        }
        for (ln, lv) in group.labels.iter() {
            if !tlset.contains_key(ln) {
                lbls.push(Label::new(ln.clone(), lv.clone()));
            }
        }

        let lset = Labels(lbls);
        let lsets = labels_by_profiles(&lset, &cfg.profiling_config);

        for lset in lsets {
            let mut prof_type = String::new();
            for label in &lset {
                if label.name() == PROFILE_NAME {
                    prof_type = label.value().to_string();
                }
            }
            let (lbls, orig_labels) = populate_labels(&lset, cfg.clone()).unwrap();
            if lbls.is_empty() || orig_labels.is_some() {
                let mut params = cfg.params.clone().unwrap_or_default();
                params.insert(ADDRESS_LABEL, lset.get(ADDRESS_LABEL).to_string());
                params.insert(SCHEME_LABEL, cfg.scheme.clone());
                params.insert(PROFILE_PATH, lset.get(PROFILE_PATH).to_string());
                for (k, v) in cfg.params.iter() {
                    if let Some(val) = v.first() {
                        params.insert(format!("{}{}", PARAM_LABEL_PREFIX, k), val.to_string());
                    }
                }
                dropped_targets.push(Target::new(lbls, orig_labels, params));
                continue;
            }
            if !lbls.is_empty() || orig_labels.is_some() {
                let mut params = cfg.params.clone().unwrap_or_default();
                if let Some(pcfg) = target_types.get(&prof_type) {
                    if pcfg.delta {
                        params.insert("seconds".to_string(), ((cfg.scrape_interval.as_secs() as i64) - 1).to_string());
                    }
                }
                targets.push(Target::new(lbls, orig_labels, params));
            }
        }
    }

    Ok((targets, dropped_targets))
}

struct ScrapeLoop {
    target: Arc<Target>,

    last_scrape_size: usize,

    scrape_client: reqwest::Client,
    appender: Arc<Mutex<dyn Appender>>,

    interval: Duration,
    timeout: Duration
}

impl ScrapeLoop {
    fn new(
        target: Arc<Target>,
        appender: Arc<Mutex<dyn Appender>>,
        interval: Duration,
        timeout: Duration
    ) -> Self {
        let scrape_client = reqwest::Client::new();
        ScrapeLoop {
            target,
            last_scrape_size: 0,
            scrape_client,
            appender,
            interval,
            timeout
        }
    }

    fn start(&mut self) {
        let target = Arc::clone(&self.target);
        let appender = Arc::clone(&self.appender);
        let interval = self.interval;
        let timeout = self.timeout;

        thread::spawn(move || {
            let mut last_scrape_time = Instant::now();

            loop {
                let elapsed = last_scrape_time.elapsed();
                if elapsed < interval {
                    thread::sleep(interval - elapsed);
                }

                last_scrape_time = Instant::now();

                if let Err(err) = Self::scrape_profile(&target, &appender, timeout) {
                    eprintln!("Error scraping profile: {:?}", err);
                }
            }
        });
    }

    fn scrape(&mut self) {
        let start = Instant::now();
        let b = vec![0u8; self.last_scrape_size];
        let mut buf = Cursor::new(b);
        let mut profile_type = String::new();

        for l in &self.target.all_labels {
            if l.name == METRIC_NAME {
                profile_type = l.value.clone();
                break;
            }
        }

        if let Err(err) = self.fetch_profile(&profile_type, &mut buf) {
            log::error!("fetch profile failed: {}", err);
            self.update_target_status(start, Some(err));
            return;
        }

        let b = buf.into_inner();
        if !b.is_empty() {
            self.last_scrape_size = b.len();
        }

        if let Err(err) = self.appender.append(Context::background(), &self.target.all_labels, vec![RawSample {
            raw_profile: b,
            ..Default::default()
        }]) {
            log::error!("push failed: {}", err);
            self.update_target_status(start, Some(err));
            return;
        }

        self.update_target_status(start, None);
    }

    fn update_target_status(&self, start: Instant, err: Option<common::error::Error>) {
        if let Some(err) = err {
            self.target.health = TargetHealth::Bad;
            self.target.last_error = Some(err);
        } else {
            self.target.health = TargetHealth::Good;
            self.target.last_error = None;
        }
        self.target.last_scrape = start;
        self.target.last_scrape_duration = Instant::now().duration_since(start);
    }

    fn fetch_profile(&self, profile_type: &str, buf: &mut dyn Write) -> Result<(), common::error::Error> {
        let url = self.url();
        log::debug!("scraping {} profile: url: {}", profile_type, url);

        let resp = self.scrape_client.get(url).send()?;
        let mut resp = resp.error_for_status()?;
        let mut body = Vec::new();
        copy(&mut resp, &mut body)?;
        buf.write_all(&body)?;

        Ok(())
    }

    fn stop(&self, wait: bool) {}
}