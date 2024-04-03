use std::any::Any;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use crate::common::component::Component;

use async_trait::async_trait;
use futures::future;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use log::{debug, info};
use prometheus::{CounterVec, Opts, register_counter_vec};
use prost::Message;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tonic::transport::Channel;
use common::error::Result;
use crate::common::registry::{Exports, Options};

use push_api::pusher_service_client::PusherServiceClient;
use push_api::{PushRequest, PushResponse};
use crate::appender::Fanout;
use crate::write::metrics::Metrics;

pub mod push_api {
    include!("../api/push/push.v1.rs");
}


#[derive(Debug, Clone)]
pub struct EndpointOptions {
    pub name: String,
    pub url: String,
    pub remote_timeout: Duration,
    pub headers: HashMap<String, String>,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub max_backoff_retries: usize,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            remote_timeout: Duration::from_secs(10),
            headers: HashMap::new(),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(300),
            max_backoff_retries: 10,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Arguments {
    pub external_labels: HashMap<String, String>,
    pub endpoints: Vec<EndpointOptions>,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            external_labels: HashMap::new(),
            endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct WriteComponent {
    opts: Options,
    cfg: Arguments,
    metrics: Arc<Metrics>
}

impl WriteComponent {
    pub async fn new(o: Options, c: Arguments) -> Result<(dyn Component, FanOutClient)> {
        let metrics = Metrics::new(&o.registerer);
        let receiver = FanOutClient::new(o, c, Arc::new(metrics)).await.unwrap();
        Ok((Component {
            opts: o.borrow(),
            cfg: c.borrow(),
            metrics,
        }, receiver))
    }
}

impl Component for WriteComponent {

    async fn run(self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    async fn update(&mut self, new_cfg: Arguments) -> Result<()> {
        self.cfg = new_cfg.clone();
        // Assuming level.Debug and Log are part of a logging library
        info!("updating iwm.write config: {:?}", self.cfg);

        let receiver = FanOutClient::new(
            self.opts,
            new_cfg,
            self.borrow().metrics
        ).await.unwrap();
        self.opts.on_state_change(Box::new(receiver));
        Ok(())
    }
}


#[derive(Debug)]
struct FanOutClient {
    clients: Vec<PusherServiceClient<Channel>>,
    config: Arguments,
    opts: Options,
    metrics: Arc<Metrics>,
}

impl FanOutClient {
    async fn new(opts: Options, config: Arguments, metrics: Arc<Metrics>) -> Result<Self> {
        let mut clients = Vec::with_capacity(config.endpoints.len());
        for endpoint in &config.endpoints {
            let client = PusherServiceClient::connect(&endpoint).await?;
            clients.push(client);
        }
        Ok(Self {
            clients, config, opts, metrics,
        })
    }

    async fn push(&self, req: PushRequest) -> Result<PushResponse> {
        let (tx, rx) = oneshot::channel();
        let mut errors = Vec::new();
        let (req_size, profile_count) = request_size(&req);

        let tasks = self.clients.iter().enumerate().map(|(i, client)| {
            let mut client = client.clone();
            let config = self.config.endpoints[i].clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                loop {
                    let result = client.push(req.clone()).await;
                    if result.is_ok() {
                        metrics.sent_bytes.with_label_values(&[&config.url]).add(req_size as f64);
                        metrics.sent_profiles.with_label_values(&[&config.url]).add(profile_count as f64);
                        break;
                    }
                    if let Err(err) = result {
                        log::warn!("failed to push to endpoint: {:?}", err);
                        errors.push(err.clone());
                        metrics.retries.with_label_values(&[&config.url]).inc();
                    }
                }
            })
        });

        let _ = tokio::spawn(async move {
            let _ = tx.send(());
        });
        let _ = future::try_join_all(tasks).await?;
        if !errors.is_empty() {
            return Err(anyhow::anyhow!("errors occurred during pushing: {:?}", errors).into());
        }

        Ok(PushResponse::default())
    }
}

async fn push_to_client<T>(
    client: &mut PusherServiceClient<T>,
    config: &EndpointOptions,
    req: &PushRequest,
    metrics: &Metrics,
) -> Result<(), anyhow::Error> {
    let mut req = req.clone();

    for (key, value) in &config.headers {
        req.header_mut().insert(key.clone(), value.clone());
    }

    let deadline = config.remote_timeout;
    let timeout = Duration::from_secs(deadline.as_secs() + deadline.subsec_millis() as u64 / 1000);

    let res = tokio::time::timeout(timeout, client.push(req)).await
        .unwrap();

    Ok(())
}

fn request_size(req: &PushRequest) -> (i64, i64) {
    let mut size = 0;
    let mut profiles = 0;

    for raw_series in &req.series {
        for sample in &raw_series.samples {
            size += sample.raw_profile.len() as i64;
            profiles += 1;
        }
    }

    (size, profiles)
}
