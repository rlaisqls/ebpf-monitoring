use std::any::Any;
use std::collections::HashMap;
use std::panic;

use std::sync::Arc;
use std::time::Duration;
use log::{error, info};
use prometheus::Registry;
use log::LevelFilter;

use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;

use agent::common::component::Component;
use agent::common::registry::Options;
use agent::discover::discover;
use agent::discover::docker_discovery::DockerDiscovery;
use agent::ebpf::ebpf_linux;
use agent::ebpf::ebpf_linux::{EbpfLinuxComponent};
use agent::write::write;
use agent::write::write::WriteComponent;

fn my_get_service_data(_name: &str) -> Result<Box<dyn Any>, String> {
    // Implement your logic here
    // This is just a placeholder implementation
    Ok(Box::new(0))
}

#[tokio::main]
#[allow(unused_variables)]
async fn main() -> Result<(), ()> {
    // env_logger::init();
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Trace))
        .unwrap();
    let _handle = log4rs::init_config(config).unwrap();

    panic::set_hook(Box::new(|panic_info| {
        error!("{:?}", panic_info.to_string());
        let backtrace = std::backtrace::Backtrace::capture();
        error!("My backtrace: {:#?}", backtrace);
    }));

    let discovery_args = discover::Arguments {
        ..Default::default()
    };
    let discovery_component = DockerDiscovery::new(discovery_args);
    let targets = discovery_component.refresh().await;

    let option = Options {
        id: "sdf".to_string(),
        data_path: "/opt".to_string(),
        registerer: Arc::new(Registry::new()),
        get_service_data: my_get_service_data
    };

    let write_args = write::Arguments {
        external_labels: HashMap::new(),
        endpoints: Vec::from([write::EndpointOptions {
            url: "http://pyroscope:4100".to_string(),
            remote_timeout: Duration::from_secs(10),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(300),
            max_backoff_retries: 10,
            ..Default::default()
        }])
    };
    let (mut write_component, fanout_client) = WriteComponent::new(option.clone(), write_args).await.unwrap();

    let argument = ebpf_linux::Arguments {
        forward_to: Arc::new(Vec::from([Box::new(fanout_client)])),
        targets,
        // vec![
        //     [("__address__", "pyroscope:4100"), ("service_name", "pyroscope")],
        //     [("__address__", "agent:12345"), ("service_name", "agent")],
        // ].iter().map(|item| item.iter().cloned()
        //     .map(|(k, v)| (k.to_string(), v.to_string())).collect()
        // ).collect(),
        collect_interval: Duration::from_secs(15),
        sample_rate: 97,
        pid_cache_size: 32,
        build_id_cache_size: 64,
        same_file_cache_size: 8,
        container_id_cache_size: 1024,
        cache_rounds: 3,
        collect_user_profile: true,
        collect_kernel_profile: true,
        python_enabled: true
    };
    let mut ebpf_component = EbpfLinuxComponent::new(option.clone(), argument).await.unwrap();

    info!("Server started");
    write_component.run().await;
    ebpf_component.run().await;
    info!("Server stopped");
    Ok(())
}
