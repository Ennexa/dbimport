extern crate clap;
extern crate ctrlc;
extern crate regex;
extern crate rpassword;
extern crate shell_escape;
extern crate ssh2;

use bzip2::read::BzDecoder;
use clap::{Arg, Command as App};
use env_logger::Env;
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{copy, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process;
use std::process::{Command, Stdio};
use tempfile::Builder;

#[derive(Default, Debug, Serialize, Deserialize)]
struct Config {
    ssh_host: String,
    #[serde(default = "Config::default_port")]
    ssh_port: String,
    ssh_user: String,
    db_user: Option<String>,
    db_pass: Option<String>,
    db_name: Option<String>,
}

impl Config {
    pub fn default_port() -> String {
        return "22".to_string();
    }
    pub fn load(host: &str) -> Config {
        let config_file = dirs::home_dir().unwrap().join(".config/dbimport.yml");

        let re = Regex::new(r"^(?:([a-z0-9-]+)@)?([a-z0-9_.-]+)(?::(\d+))?$").unwrap();
        let cap = re.captures(host).unwrap();

        let ssh_host = cap
            .get(2)
            .unwrap_or_else(|| {
                error!("Failed to parse ssh host");
                process::exit(1);
            })
            .as_str();

        let mut config: Config = match config_file.exists() {
            true => Config::parse(config_file.to_str().unwrap(), ssh_host),
            false => Config {
                ssh_host: ssh_host.to_string(),
                ssh_port: "22".to_string(),
                ..Default::default()
            },
        };

        match cap.get(1) {
            Some(val) => config.ssh_user = val.as_str().to_string(),
            None => {
                error!("SSH username cannot be empty");
                process::exit(1);
            }
        }

        if let Some(ssh_port) = cap.get(3) {
            config.ssh_port = ssh_port.as_str().to_string();
        }

        config
    }

    pub fn parse(path: &str, host: &str) -> Config {
        match Config::parse_config_file(path, host) {
            Ok(config) => config,
            Err(err) => {
                error!("Failed to parse config file - {}", err);
                Config {
                    ssh_host: host.to_string(),
                    ..Default::default()
                }
            }
        }
    }

    fn parse_config_file(path: &str, host: &str) -> Result<Config, Box<dyn Error>> {
        let f = std::fs::File::open(path)?;
        let mut config: HashMap<String, Config> = serde_yaml::from_reader(f)?;
        match config.remove(host) {
            Some(n) => Ok(n),
            None => Err(From::from(
                "No matching cities with a population were found.",
            )),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the logger with the default environment variable "RUST_LOG"
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "[{}] {}", record.level(), record.args()))
        .init();

    let matches = App::new("Database Importer")
        .about("Import database from remote server")
        .arg(
            Arg::new("database")
                .short('d')
                .long("database")
                .help("Target Database")
                .takes_value(true),
        )
        .arg(
            Arg::new("out_file")
                .short('o')
                .long("out_file")
                .help("Output file path")
                .takes_value(true),
        )
        .arg(
            Arg::new("dbuser")
                .short('u')
                .long("user")
                .help("Database username")
                .takes_value(true),
        )
        .arg(
            Arg::new("dbpass")
                .short('p')
                .long("password")
                .help("Database password")
                .takes_value(true),
        )
        .arg(
            Arg::new("extra_args")
                .short('x')
                .long("extra-args")
                .allow_hyphen_values(true)
                .help("Extra arguments to be passed to mysqldump")
                .takes_value(true),
        )
        // .arg(Arg::with_name("dump")
        // .long("dump")
        //     .help("dump mode (for remote)")
        //     .required(false)
        //     .takes_value(false))
        .arg(
            Arg::new("host")
                .value_name("user@hostname")
                .help("SSH Destination")
                .takes_value(true)
                .required(true),
        )
        .arg(Arg::new("table").multiple_values(true).required(true))
        .get_matches();

    let host = match matches.value_of("host") {
        Some(n) => n,
        None => {
            error!("Target host cannot be empty");
            process::exit(1);
        }
    };

    let config = Config::load(host);

    let tables = match matches.values_of("table") {
        Some(n) => n,
        None => {
            error!("Target tables cannot be empty");
            process::exit(1);
        }
    };

    let extra_args = matches.value_of("extra_args").unwrap_or("");
    let out_file = matches.value_of("out_file");

    // Try to fetch username from command-line options
    let db_user = match matches.value_of("dbuser") {
        Some(val) => val.to_owned(),
        None => match config.db_user {
            Some(val) => val,
            None => {
                // User option was not specified.
                // Use ssh username, if available
                info!("Using SSH username as database username");
                config.ssh_user.to_owned()
            }
        },
    };

    let db_name = match matches.value_of("database") {
        Some(v) => v.to_string(),
        None => match config.db_name {
            Some(v) => v,
            None => {
                // User option was not specified.
                // Use ssh username, if available
                info!("Inferring database name as {}_db", db_user);
                format!("{}_db", db_user)
            }
        },
    };

    let db_pass = match matches.value_of("dbpass") {
        Some(val) => val.to_owned(),
        None => match config.db_pass {
            Some(val) => val,
            None => {
                error!("Database password cannot be empty");
                process::exit(2);
            }
        },
    };

    //let db_pass = matches.value_of("dbpass").unwrap_or("");

    // Connect to the remote server
    let ssh_host_port = format!("{}:{}", config.ssh_host, config.ssh_port);
    let tcp = TcpStream::connect(&ssh_host_port).unwrap_or_else(|err| {
        error!("{}", err);
        process::exit(1);
    });

    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().expect("SSH handshake failed");

    // Try to authenticate with the first identity in the agent.
    info!("Attempt to authenticate with ssh-agent...");
    let _ = sess.userauth_agent(&config.ssh_user);

    // Make sure we succeeded
    if !sess.authenticated() {
        warn!("SSH-agent authentication failed. Falling back to password login.");
        info!("Enter password: ");
        let ssh_pass = rpassword::read_password().unwrap();
        sess.userauth_password(&config.ssh_user, &ssh_pass)
            .unwrap_or_else(|_| {
                error!("Failed to authenticate to remote server");
                process::exit(1);
            });
    } else {
        info!("SSH-agent authentication succeeded.");
    }

    let mut remote_temp_file = String::new();
    let mut channel = sess.channel_session().unwrap();
    channel
        .exec("mktemp -t 'dbimport_XXXXXXXX.sql.bz2'")
        .unwrap();
    channel.read_to_string(&mut remote_temp_file).unwrap();
    let remote_temp_file = remote_temp_file.trim();

    let pass_arg = format!("-p{}", &db_pass);
    let mut v = vec!["mysqldump", "-u", &db_user, &pass_arg, &db_name];

    for table in tables {
        v.push(table);
    }

    let v: Vec<String> = v
        .into_iter()
        .map(|item| shell_escape::unix::escape(std::borrow::Cow::from(item)).into_owned())
        .collect();
    let arg = format!(
        "{} {} | tail +2 | bzip2 > {}",
        v.join(" "),
        extra_args,
        remote_temp_file
    );

    info!("Exporting database on target server...");
    let mut channel = sess.channel_session().ok().unwrap();
    let exit_status = channel
        .exec(&arg)
        .and_then(|_| {
            let mut stdout = String::new();
            let mut stderr = String::new();
            channel.read_to_string(&mut stdout).unwrap();
            channel.stderr().read_to_string(&mut stderr).unwrap();

            channel.wait_close()
        })
        .and_then(|_| channel.exit_status());

    match exit_status {
        Ok(0) => info!("Database export succeeded."),
        _ => {
            error!("Failed to export database");
            process::exit(4);
        }
    }

    let (remote_file, stat) = sess
        .scp_recv(Path::new(&remote_temp_file))
        .unwrap_or_else(|err| {
            error!("Failed to download file - {}", err);
            process::exit(2);
        });

    info!("Exported file size: {}", stat.size());

    let temp_file = Builder::new()
        .suffix(".sql.bz2")
        .tempfile()
        .expect("Failed to create temporary file");

    let path = match out_file {
        Some(n) => Path::new(n),
        None => temp_file.path(),
    };

    let mut target = File::create(path).unwrap();
    let progressbar = indicatif::ProgressBar::new(stat.size());
    let mut remote_file = progressbar.wrap_read(remote_file);
    // copy(&mut remote_file, &mut target);

    match copy(&mut remote_file, &mut target) {
        Ok(_) => (),
        Err(err) => {
            error!("Failed to download exported database dump - {}", err);
            process::exit(3);
        }
    }
    debug!("Database dump downloaded to {:?}", path);

    progressbar.finish_and_clear();

    let mut channel = sess.channel_session().ok().unwrap();
    let arg = format!("rm -f {}", remote_temp_file);
    let exit_status = channel
        .exec(&arg)
        .and_then(|_| channel.close())
        .and_then(|_| channel.exit_status());

    match exit_status {
        Ok(0) => info!("Removed temporary file from remote filesystem."),
        _ => warn!("Failed to delete temporary file from remote filesystem."),
    }

    let f = BufReader::new(File::open(&path).unwrap());

    let v = vec!["-u", &db_user, &pass_arg, &db_name];
    let mut cmd = Command::new("mysql")
        .args(&v)
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to spawn mysql client");

    debug!("Spawning mysql client");
    if let Some(stdin) = &mut cmd.stdin {
        let mut writer = BufWriter::new(stdin);

        debug!("Copying uncompressed dump to mysql client stdin");
        // Decompress and import to local mysql database
        match copy(&mut Box::new(BzDecoder::new(f)), &mut writer) {
            Ok(_) => info!("Database import completed successfully."),
            Err(err) => {
                error!("Failed to import database dump - {}", err);
                process::exit(5);
            }
        };
    }

    debug!("Waiting for import to complete");

    let result = match cmd.try_wait() {
        Ok(Some(status)) => status.code(),
        Ok(None) => cmd.wait().unwrap().code(),
        Err(e) => {
            error!("Error attempting to wait: {}", e);
            process::exit(5);
        }
    };

    debug!("Removing temporary file {:?}", path);
    fs::remove_file(path)?;

    match result {
        Some(0) => (),
        n => error!("Import failed with exit code {:?}", n),
    };

    Ok(())
}
