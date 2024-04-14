
use std::collections::HashMap;

use std::sync::{Arc};
use std::time::Duration;
use std::borrow::Borrow;










use tonic::transport::Channel;
use common::common::labels::Labels;
use common::ebpf::metrics::write_metrics::WriteMetrics;
use common::ebpf::sd::target::{METRIC_NAME, RESERVED_LABEL_PREFIX};

use common::error::Result;

use crate::common::registry::{Options};
use crate::common::component::Component;
use crate::appender::{Appendable, Appender};
use crate::ebpf::ebpf_linux::push_api::pusher_service_client::PusherServiceClient;
use crate::ebpf::ebpf_linux::push_api::{LabelPair, PushRequest, PushResponse, RawProfileSeries, RawSample};


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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct WriteComponent {
    opts: Options,
    cfg: Arguments,
    metrics: Arc<WriteMetrics>
}

impl WriteComponent {

    async fn update(&mut self, _new_cfg: Arguments) -> Result<()> {
        Ok(())
    }
    pub async fn new(o: Options, c: Arguments) -> Result<(Self, FanOutClient)> {
        let metrics = Arc::new(WriteMetrics::new(o.registerer.borrow()));

        let receiver = tokio::runtime::Runtime::new().unwrap().block_on(async {
            FanOutClient::new(o.clone(), c.clone(), metrics.clone()).await.unwrap()
        });
        Ok((WriteComponent {
            opts: o,
            cfg: c,
            metrics,
        }, receiver))
    }
}

impl Component for WriteComponent {
    fn run(&mut self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct FanOutClient {
    clients: Vec<PusherServiceClient<Channel>>,
    config: Arguments,
    opts: Options,
    metrics: Arc<WriteMetrics>,
}

pub const DELTA_LABEL: &str = "__delta__";

impl Appender for FanOutClient {
    fn append(&self, lbs: Labels, samples: Vec<RawSample>) -> Result<()> {
        // todo: pool label pair arrays and label builder to avoid allocations
        let mut proto_labels: Vec<LabelPair> = Vec::with_capacity(lbs.len() + self.config.external_labels.len());
        let mut proto_samples: Vec<RawSample> = Vec::with_capacity(samples.len());
        let mut lbs_builder = HashMap::<String, String>::new();

        for label in lbs.0 {
            // filter reserved labels, with exceptions for __name__ and __delta__
            if label.name.starts_with(RESERVED_LABEL_PREFIX)
                && label.name != METRIC_NAME
                && label.name != DELTA_LABEL
            {
                continue;
            }
            lbs_builder.insert(label.name, label.value);
        }

        for (name, value) in &self.config.external_labels {
            lbs_builder.insert(name.clone(), value.clone());
        }

        for key in lbs_builder.keys(){
            proto_labels.push(LabelPair {
                name: key.clone(),
                value: lbs_builder.get(key).unwrap().clone(),
            });
        }

        for sample in samples {
            proto_samples.push(RawSample {
                raw_profile: sample.raw_profile,
                id: "".to_string(),
            });
        }

        // push to all clients
        // Assuming Push method is defined elsewhere
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            self.push(PushRequest {
                series: vec![RawProfileSeries {
                    labels: proto_labels,
                    samples: proto_samples,
                }],
            }).await.unwrap();
        });

        Ok(())
    }
}

impl Appendable for FanOutClient {
    fn appender(&self) -> Box<dyn Appender> {
        Box::new(self.clone())
    }
}

impl FanOutClient {
    async fn new(opts: Options, config: Arguments, metrics: Arc<WriteMetrics>) -> Result<Self> {
        let mut clients = Vec::with_capacity(config.endpoints.len());
        let client = PusherServiceClient::connect("http://[::1]:50051").await.unwrap();
        clients.push(client);
        // for endpoint in &config.endpoints {
        //     let client = PusherServiceClient::connect(&endpoint).await.unwrap();
        //     clients.push(client);
        // }
        Ok(Self {
            clients, config, opts, metrics,
        })
    }

    async fn push(&self, req: PushRequest) -> Result<PushResponse> {
        //let mut errors = Vec::new();

        self.clients.iter().enumerate().for_each(|(i, client)| {
            let r = req.clone();
            let mut client = client.clone();
            let config = self.config.endpoints[i].clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                loop {
                    let (req_size, profile_count) = request_size(&r);

                    let result = PusherServiceClient::push(&mut client, r.clone()).await;
                    // let result = tokio::time::timeout(
                    //     Duration::from_secs(10), c.push(r.clone())
                    // ).await.unwrap();

                    if result.is_ok() {
                        metrics.sent_bytes.with_label_values(&[&config.url]).inc_by(req_size as f64);
                        metrics.sent_profiles.with_label_values(&[&config.url]).inc_by(profile_count as f64);
                        break;
                    } else if let Err(err) = result {
                        log::warn!("failed to push to endpoint: {:?}", err);
                        //errors.push(err.clone());
                        metrics.retries.with_label_values(&[&config.url]).inc();
                    }
                }
            });
            ()
        });

        // if !errors.is_empty() {
        //     return Err(WriteError(format!("errors occurred during pushing: {:?}", errors)));
        // }

        Ok(PushResponse::default())
    }
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
