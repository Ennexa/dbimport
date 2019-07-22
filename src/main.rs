extern crate clap;
extern crate regex;
extern crate ssh2;
extern crate rpassword;
extern crate shell_escape;
extern crate ctrlc;

use clap::{Arg, App};
use regex::Regex;
use std::process;
use std::net::TcpStream;
use ssh2::Session;
use std::io::{copy,BufReader,BufWriter,Read};
use std::path::Path;
use std::fs::File;
use tempfile::Builder;
use bzip2::read::BzDecoder;
use std::process::{Command, Stdio};

fn main() {
    let matches = App::new("Database Importer")
        .about("Import database from remote server")
        .arg(Arg::with_name("database")
           .short("d")
           .long("database")
           .help("Target Database")
           .takes_value(true))
        .arg(Arg::with_name("out_file")
           .short("o")
           .long("out_file")
           .help("Output file path")
           .takes_value(true))
        .arg(Arg::with_name("dbuser")
            .short("u")
              .long("user")
            .help("Database username")
            .takes_value(true))
        .arg(Arg::with_name("dbpass")
            .short("p")
              .long("password")
            .help("Database password")
            .takes_value(true))
        .arg(Arg::with_name("extra_args")
            .short("x")
              .long("extra-args")
              .allow_hyphen_values(true)
            .help("Extra arguments to be passed to mysqldump")
            .takes_value(true))
        // .arg(Arg::with_name("dump")
              // .long("dump")
        //     .help("dump mode (for remote)")
        //     .required(false)
        //     .takes_value(false))
        .arg(Arg::with_name("host")
            .value_name("user@hostname")
            .help("SSH Destination")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("table")
            .multiple(true)
            .required(true))
        .get_matches();

    let host = match matches.value_of("host")
    {
        Some(n) => n,
        None => {
            eprintln!("Target host cannot be empty");
            process::exit(1);
        }
    };
    let tables = match matches.values_of("table")
    {
        Some(n) => n,
        None => {
            eprintln!("Target tables cannot be empty");
            process::exit(1);
        }
    };

    let extra_args = matches.value_of("extra_args").unwrap_or("");
    let out_file = matches.value_of("out_file");

    let re = Regex::new(r"^(?:([a-z0-9-]+)@)?([a-z0-9_.-]+)(?::(\d+))?$").unwrap();
    let cap = re.captures(host).unwrap();

    let ssh_user = match cap.get(1) {
        Some(v) => v.as_str(),
        None => {
            eprintln!("Failed to detect database username");
            process::exit(1);
        },
    };
    let ssh_host = cap.get(2).unwrap().as_str();
    let ssh_port = match cap.get(3) {
        Some(v) => v.as_str(),
        None => "22"
    };

    // Try to fetch username from command-line options
    let db_user = match matches.value_of("dbuser") {
        Some(v) => v,
        None => {
            // User option was not specified.
            // Use ssh username, if available
            eprintln!("Using SSH username as database username");
            ssh_user
        }
    };

    let db_name = match matches.value_of("database") {
        Some(v) => v.to_string(),
        None => {
            // User option was not specified.
            // Use ssh username, if available
            eprintln!("Inferring database name as {}_db", db_user);
            format!("{}_db", db_user)
        }
    };

    let db_pass = matches.value_of("dbpass").unwrap_or("");

    // Connect to the remote server
    let ssh_host_port = format!("{}:{}", ssh_host, ssh_port);
    let tcp = TcpStream::connect(&ssh_host_port).unwrap_or_else(|err| {
        eprintln!("{}", err);
        process::exit(1);
    });

    let mut sess = Session::new().unwrap();
    sess.handshake(&tcp).expect("SSH handshake failed");

    // Try to authenticate with the first identity in the agent.
    eprint!("Attept to authenticate with ssh-agent...");
    let _ = sess.userauth_agent(ssh_user);

    // Make sure we succeeded
    if !sess.authenticated() {
        eprintln!("FAILED");

        eprintln!("Falling back to password login");
        eprint!("Enter password: ");

        let ssh_pass = rpassword::read_password().unwrap();
        sess.userauth_password(&ssh_user, &ssh_pass).unwrap_or_else(|_| {
            eprintln!("Failed to authenticate to remote server");
            process::exit(1);
        });
    } else {
        eprintln!("OK");
    }

    let mut remote_temp_file = String::new();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("mktemp -t 'dbimport_XXXXXXXX.sql.bz2'").unwrap();
    channel.read_to_string(&mut remote_temp_file).unwrap();
    let remote_temp_file = remote_temp_file.trim();

    // ctrlc::set_handler(move || {
    //     // Handle early termination
    //     let status = sess.sftp().and_then(|sftp| {
    //     	sftp.unlink(Path::new(remote_temp_file))
    //     });
    // }).expect("Error setting Ctrl-C handler");

    let pass_arg = format!("-p{}", db_pass);
    let mut v = vec![
        "mysqldump",
        "-u", db_user,
        &pass_arg,
        &db_name,
    ];

    for table in tables {
        v.push(table);
    }

    let v:Vec<String> = v.into_iter().map(|item| shell_escape::unix::escape(std::borrow::Cow::from(item)).into_owned()).collect();
    let arg = format!("{} {} | bzip2 > {}", v.join(" "), extra_args, remote_temp_file);

    eprint!("Exporting database on target server...");
    let mut channel = sess.channel_session().unwrap_or_else(|err| {
        eprintln!("Failed to export database - {}", err);
        process::exit(4);
    });

    let exit_status = channel.exec(&arg)
        .and_then(|_| channel.close())
        // .and_then(|_| channel.wait_close())
        .and_then(|_| channel.exit_status());

    match exit_status {
        Ok(0) => (),
        _ => {
        	eprintln!("ERR");
            eprintln!("Failed to export database");
            process::exit(4);
        }
    }

    eprintln!("OK");

    let (remote_file, stat) = sess.scp_recv(Path::new(&remote_temp_file)).unwrap_or_else(|err| {
        eprintln!("Failed to download file - {}", err);
        process::exit(2);
    });

    eprintln!("Exported file size: {}", stat.size());

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
            eprintln!("Failed to copy exported database dump - {}", err);
            process::exit(3);
        }
    }
    progressbar.finish_and_clear();
    println!("Downloading database dump...OK");

    let f = BufReader::new(File::open(&path).unwrap());

    let v = vec![
        "-u", db_user,
        &pass_arg,
        &db_name
    ];
    let mut cmd = Command::new("mysql")
         .args(&v)
         .stdin(Stdio::piped())
         .spawn()
         .expect("Failed to spawn mysql client");

    if let Some(stdin) = &mut cmd.stdin {
	    let mut writer = BufWriter::new(stdin);

	    // Decompress and import to local mysql database
	    match copy(&mut Box::new(BzDecoder::new(f)), &mut writer) {
	        Ok(_) => {
	        	eprintln!("Import completed successfully")
	        },
	        Err(err) => {
	            eprintln!("Failed to import database dump - {}", err);
	            process::exit(5);
	        }
	    };
    }

    let result = match cmd.try_wait() {
    	Ok(Some(status)) => status.code(),
	    Ok(None) => cmd.wait().unwrap().code(),
	    Err(e) => {
	    	eprintln!("error attempting to wait: {}", e);
	    	process::exit(5);
	    }
    };

    match result {
    	Some(0) => (),
    	n => eprintln!("Import failed with exit code {:?}", n),
    };

    ()
}
