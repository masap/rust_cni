extern crate rust_bridge;
extern crate scopeguard;

use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::unix::prelude::*;
use std::result::Result;
use std::thread;

use nix::{fcntl, sched};
use rand::Rng;
use serde_json::{json, Value};

use rust_bridge::{cni_utils, iptables_utils, CniArgs, CniConf};

fn cmd_version() -> String{
    let version_json = json!({
        "cniVersion": "0.4.0",
        "supportedVersions": ["0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0"]
    });
    version_json.to_string()
}

fn cmd_add(args: &CniArgs) -> Result<String, Error> {
    let conf = match CniConf::new(&args.stdin_data_raw) {
        Ok(conf) => conf,
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to load cni conf: {}", err))),
    };

    let ipam_ret = match cni_utils::exec_ipam(&args.stdin_data_raw, &args.cni_path, &conf.ipam_type) {
        Ok(ret) => ret,
        Err(err) => return Err(err),
    };

    let mut result_json: Value = match serde_json::from_str(&ipam_ret) {
        Ok(val) => val,
        Err(err) => return Err(Error::new(ErrorKind::InvalidInput, format!("failed to parse IPAM return: {}", err))),
    };
    if result_json["code"] != Value::Null {
        return Err(Error::new(ErrorKind::Other, format!("failed to exec ipam: {}", result_json)));
    }

    let ipv4_addr_mask = cni_utils::trim_quoted_json_string(&result_json["ips"][0]["address"]);
    let token: Vec<&str> = ipv4_addr_mask.split('/').collect();
    if token.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidInput, format!("invalid ipv4 addr: {}", ipv4_addr_mask)))
    }
    let netns_ipv4_addr = token[0].to_string();
    let ipv4_mask = token[1].to_string();

    let gw_ipv4_addr = cni_utils::trim_quoted_json_string(&result_json["ips"][0]["gateway"]);
    if let Err(err) = cni_utils::configure_bridge(&conf.bridge_name, &gw_ipv4_addr, &ipv4_mask) {
        return Err(err)
    }

    if let Err(err) = iptables_utils::add_iptables(&conf.conf_name, &args.cni_containerid, &netns_ipv4_addr, &conf.ipam_subnet) {
        return Err(err)
    }

    let veth_name = format!("veth{:x}", rand::thread_rng().gen::<u32>());

    if let Err(err) = cni_utils::configure_veth(&veth_name, &args.cni_ifname, &conf.bridge_name, &args.cni_netns) {
        return Err(err)
    }

    result_json["ips"][0]["interface"] = json!(2);
    result_json["interfaces"] = json!([{}, {}, {}]);
    match cni_utils::get_hardware_addr(&conf.bridge_name) {
        Ok(addr) => result_json["interfaces"][1] = json!({"name": &conf.bridge_name, "mac": addr}),
        Err(err) => return Err(err),
    }
    match cni_utils::get_hardware_addr(&veth_name) {
        Ok(addr) => result_json["interfaces"][2] = json!({"name": &veth_name, "mac": addr}),
        Err(err) => return Err(err),
    }

    match File::open(&args.cni_netns) {
        Ok(netns_file) => {
            let netns_fd = netns_file.as_raw_fd();
            let cni_ifname = args.cni_ifname.clone();
            let handle = thread::spawn(move || -> Result<String, Error> {
                if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                    panic!(format!("failed to setns to fd={}: {}", netns_fd, err));
                }

                if let Err(err) = cni_utils::configure_netns_interface(&cni_ifname, &netns_ipv4_addr, &ipv4_mask, &gw_ipv4_addr) {
                    return Err(err)
                }

                match cni_utils::get_hardware_addr(&cni_ifname) {
                    Ok(addr) => Ok(addr),
                    Err(err) => return Err(err),
                }
            });
            match handle.join() {
                Ok(mac_address) => result_json["interfaces"][0] = json!({"name": &args.cni_ifname, "mac": mac_address.unwrap()}),
                Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to join: {:?}", err))),
            }
        },
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to open the netns file: {}", err))),
    }

    Ok(result_json.to_string())
}

fn cmd_del(args: &CniArgs) -> Result<String, Error> {
    let conf = match CniConf::new(&args.stdin_data_raw) {
        Ok(conf) => conf,
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to load cni conf: {}", err))),
    };

    let ipam_ret = match cni_utils::exec_ipam(&args.stdin_data_raw, &args.cni_path, &conf.ipam_type) {
        Ok(ret) => ret,
        Err(err) => return Err(err),
    };

    if let Err(err) = iptables_utils::del_iptables(&conf.conf_name, &args.cni_containerid, &conf.ipam_subnet) {
        return Err(err)
    }

    match File::open(&args.cni_netns) {
        Ok(netns_file) => {
            let netns_fd = netns_file.as_raw_fd();
            let cni_ifname = args.cni_ifname.clone();
            let handle = thread::spawn(move || -> Result<(), Error> {
                if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                    panic!(format!("failed to setns to fd={}: {}", netns_fd, err))
                }

                if let Err(err) = cni_utils::delete_interface(&cni_ifname) {
                    return Err(err)
                }

                Ok(())
            });
            if let Err(err) = handle.join() {
                return Err(Error::new(ErrorKind::Other, format!("failed to join: {:?}", err)))
            }
        },
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to open the netns file: {}", err))),
    };

    // Do not delete bridge interface here. Because other containers may be using it.

    Ok(ipam_ret)
}

fn cmd_check(args: &CniArgs) -> Result<String, Error> {
    let conf = match CniConf::new(&args.stdin_data_raw) {
        Ok(conf) => conf,
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to load cni conf: {}", err))),
    };

    let ipam_ret = match cni_utils::exec_ipam(&args.stdin_data_raw, &args.cni_path, &conf.ipam_type) {
        Ok(ret) => ret,
        Err(err) => return Err(err),
    };

    // XXX: Do more check

    Ok(ipam_ret)
}

fn __main() -> Result<(), Error> {
    let args = match CniArgs::new() {
        Ok(args) => args,
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to get environment variables: {}", err))),
    };

    if let Err(err) = cni_utils::write_to_log(&format!("cni_command={}\n", args.cni_command)) {
        panic!("failed to write to log file: {}", err);
    }

    if args.cni_command == "VERSION" {
        println!("{}", cmd_version());
        return Ok(())
    }

    const LOCK_FILE_NAME: &str = "/var/run/lock/rust_cni.lock";
    let lock_file = match File::open(LOCK_FILE_NAME) {
        Ok(file) => file,
        Err(ref error) if error.kind() == ErrorKind::NotFound => {
            match File::create(LOCK_FILE_NAME) {
                Ok(fc) => fc,
                Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to create the lock file: {}", err))),
            }
        },
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to open the lock file: {}", err))),
    };

    if let Err(err) = fcntl::flock(lock_file.as_raw_fd(), fcntl::FlockArg::LockExclusive) {
        return Err(Error::new(ErrorKind::Other, format!("failed to lock the file: {}", err)))
    }
    let _guard = scopeguard::guard((), |_| {
        if let Err(err) = fcntl::flock(lock_file.as_raw_fd(), fcntl::FlockArg::Unlock) {
            panic!("failed to unlock the file: {}", err);
        }
    });

    let handler = match &args.cni_command[..] {
        "ADD" => cmd_add,
        "DEL" => cmd_del,
        "CHECK" => cmd_check,
        _ => return Err(Error::new(ErrorKind::Other, format!("Unknown CNI command {}", args.cni_command))),
    };

    match handler(&args) {
        Ok(ret) => {
            if let Err(err) = cni_utils::write_to_log(&format!("{} OK,CNI_CONTAINERID={},CNI_NETNS={}\n", args.cni_command, args.cni_containerid, args.cni_netns)) {
                panic!("failed to write to log file: {}", err);
            }

            println!("{}", ret);
        },
        Err(err) => return Err(Error::new(ErrorKind::Other, format!("{} command failed: {}", args.cni_command, err))),
    }

    Ok(())
}

fn main() {
    if let Err(err) = __main() {
        if let Err(err) = cni_utils::write_to_log(&format!("{}\n", err)) {
            panic!("failed to write to log file: {}", err);
        }
    }
}
