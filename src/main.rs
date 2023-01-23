use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::channel;
use tokio::task::{Builder, JoinHandle};
use tokio::time::sleep;
use tokio::try_join;
use tracing::{error, info};

use zebot2::client;
use zebot2::control;
use zebot2::util;
use zebot2::Settings;

async fn startup(args: Arc<Settings>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (control_send, client_recv) = channel(256);
    let (client_send, control_recv) = channel(256);

    let mut cl = Builder::new().name("client").spawn(client::task(
        client_recv,
        client_send.clone(),
        args.clone(),
    ))?;
    let mut ctrl = Builder::new().name("control").spawn(control::task(
        control_recv,
        control_send.clone(),
        args.clone(),
    ))?;

    // Join tasks and report errors
    async fn join_tasks(
        cl: &mut JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
        ctrl: &mut JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (clr, ctrlr) = try_join!(cl, ctrl)?;
        clr?;
        ctrlr?;
        Ok(())
    }

    match join_tasks(&mut cl, &mut ctrl).await {
        Ok(_) => (),
        Err(e) => {
            error!("A task returned an error: {:?}", e);
            // try aborting ...
            cl.abort();
            ctrl.abort();
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    use clap::Parser;

    let args = Settings::parse();
    let args = Arc::new(args);

    if args.tokio_console {
        let port = if let Some(port) = std::env::var("TOKIO_CONSOLE_PORT")
            .ok()
            .and_then(|x| x.parse::<u16>().ok())
        {
            port
        } else {
            5555
        };

        console_subscriber::ConsoleLayer::builder()
            .retention(Duration::from_secs(60))
            .server_addr(([127, 0, 0, 1], port))
            .init();
    } else {
        let my_subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::INFO)
            .with_thread_ids(false)
            .with_thread_names(false)
            .finish();
        tracing::subscriber::set_global_default(my_subscriber)
            .expect("setting tracing default failed");
    }

    info!("This is ZeBot2 {}", util::zebot_version());

    if args.no_stdin {
        info!("Running w/o support to read from stdin (-N)");
    }

    if args.restart {
        loop {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?
                .block_on(async {
                    if let Err(e) = startup(args.clone()).await {
                        error!("There was an unrecoverable error: {e:?}");
                    }
                    info!("Sleeping for 10 seconds before restart...");
                    sleep(Duration::from_secs(10)).await;
                    info!("Starting again!");
                });
        }
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?
            .block_on(async { startup(args).await })?;
    }

    Ok(())
}
