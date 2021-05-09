use std::env;
use std::io::{self, Error, ErrorKind, Read};

use serde_json::Value;

#[derive(Debug)]
pub struct CniArgs {
    pub cni_command: String,
    pub cni_containerid: String,
    pub cni_netns: String,
    pub cni_ifname: String,
    pub cni_path: String,
    pub cni_args: String,
    pub stdin_data_raw: String,
}

impl CniArgs {
    pub fn new() -> Result<CniArgs, Error> {
        Ok(CniArgs {
            cni_command: match env::var("CNI_COMMAND") {
                Ok(val) => val,
                Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("failed to get CNI_COMMAND: {}", err))),
            },
    
            cni_containerid: match env::var("CNI_CONTAINERID") {
                Ok(val) => val,
                Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("failed to get CNI_CONTAINERID: {}", err))),
            },
    
            cni_netns: match env::var("CNI_NETNS") {
                Ok(val) => val,
                Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("failed to get CNI_NETNS: {}", err))),
            },
    
            cni_ifname: match env::var("CNI_IFNAME") {
                Ok(val) => val,
                Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("failed to get CNI_IFNAME: {}", err))),
            },
    
            cni_path: match env::var("CNI_PATH") {
                Ok(val) => val,
                Err(err) => return Err(Error::new(ErrorKind::NotFound, format!("failed to get CNI_PATH: {}", err))),
            },
    
            cni_args: match env::var("CNI_ARGS") {
                Ok(val) => val,
                Err(err) => {
                    if err != env::VarError::NotPresent {
                        return Err(Error::new(ErrorKind::Other, format!("failed to get CNI_ARGS: {}", err)))
                    }
                    String::new()
                },
            },
    
            stdin_data_raw: {
                let mut buffer = String::new();
                match io::stdin().read_to_string(&mut buffer) {
                    Ok(_) => buffer,
                    Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to read stdin: {}", err))),
                }
            },
        })
    }
}

#[derive(Debug)]
pub struct CniConf {
    pub conf_name: String,
    pub bridge_name: String,
    pub ipam_type: String,
    pub ipam_subnet: String,
}

impl CniConf {
    pub fn new(stdin_data_raw: &str) -> Result<CniConf, Error> {
        let stdin_json: Value = match serde_json::from_str(stdin_data_raw) {
            Ok(val) => val,
            Err(err) => return Err(Error::new(ErrorKind::InvalidInput, format!("failed to convert stdin to json: {}", err))),
        };
    
        Ok(CniConf {
            conf_name: match stdin_json["name"] {
                Value::Null => String::new(),
                _ => cni_utils::trim_quoted_json_string(&stdin_json["name"]),
            },
    
            bridge_name: match stdin_json["bridge"] {
                Value::Null => String::new(),
                _ => cni_utils::trim_quoted_json_string(&stdin_json["bridge"]),
            },
    
            ipam_type: match stdin_json["ipam"] {
                Value::Null => String::new(),
                _ => {
                    if stdin_json["ipam"]["type"] == Value::Null {
                        return Err(Error::new(ErrorKind::InvalidInput, format!("ipam type not found")))
                    }
                    cni_utils::trim_quoted_json_string(&stdin_json["ipam"]["type"])
                },
            },
    
            ipam_subnet: match stdin_json["ipam"] {
                Value::Null => String::new(),
                _ => {
                    if stdin_json["ipam"]["subnet"] == Value::Null {
                        return Err(Error::new(ErrorKind::InvalidInput, format!("ipam subnet not found")))
                    }
                    cni_utils::trim_quoted_json_string(&stdin_json["ipam"]["subnet"])
                },
            },
        })
    }
}

pub mod cni_utils {
    use std::fs::{self, File};
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::prelude::*;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use futures::stream::TryStreamExt;
    use interfaces::Interface;
    use ipnetwork::{IpNetwork, Ipv4Network};
    use rtnetlink;
    use serde_json::Value;

    pub const NETNS_FILE_PATH: &str = "/var/run/netns/";
    const LOG_FILE_NAME: &str = "/tmp/rust_cni.log";
    
    async fn add_ip_address(handle: &rtnetlink::Handle, ifname: &str, ip: &IpNetwork) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().set_name_filter(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle.address().add(link.header.index, ip.ip(), ip.prefix()).execute().await {
                    Ok(_) => Ok(()),
                    Err(rtnetlink::Error::NetlinkError(err)) => {
                        if err.code == -17 { // EEXIST
                            Ok(())
                        } else {
                            Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to set ip address to {}: {}", ifname, err)))
                        }
                    },
                    Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to set ip address to {}: {}", ifname, err))),
                }
            },
            Ok(None) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("interface {} not found", ifname))),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {} up: {}", ifname, err))),
        }
    }
    
    async fn add_route(handle: &rtnetlink::Handle, dest: &Ipv4Network, gateway: &Ipv4Network) -> Result<(), std::io::Error> {
        let route = handle.route();
        match route.add().v4().destination_prefix(dest.ip(), dest.prefix()).gateway(gateway.ip()).execute().await {
            Ok(_) => Ok(()),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to add route: {}", err))),
        }
    }

    async fn del_link(handle: &rtnetlink::Handle, ifname: &str) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().set_name_filter(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle.link().del(link.header.index).execute().await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to delete interface {}: {}", ifname, err))),
                }
            },
            Ok(None) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("interface {} not found", ifname))),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {}: {}", ifname, err))),
        }
    }

    async fn set_link_up(handle: &rtnetlink::Handle, ifname: &str) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().set_name_filter(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle.link().set(link.header.index).up().execute().await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to set {} up: {}", ifname, err))),
                }
            },
            Ok(None) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("interface {} not found", ifname))),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {} up: {}", ifname, err))),
        }
    }

    #[tokio::main]
    pub async fn configure_bridge(ifname: &str, ipv4_addr: &str, ipv4_mask: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to connect to netlink: {}", err))),
        };
    
        tokio::spawn(connection);

        // create if not exist
        let mut links = handle.link().get().set_name_filter(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(_)) => (),
            Ok(None) => if let Err(err) = handle.link().add().bridge(ifname.to_string()).execute().await {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to create a bridge {}: {}", &ifname, err)))
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {}: {}", ifname, err))),
        }

        // add an ip address to the bridge interface
        match format!("{}/{}", ipv4_addr, ipv4_mask).parse() {
            Ok(ip) => if let Err(err) = add_ip_address(&handle, &ifname, &ip).await {
                return Err(err)
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to parse ip address {}: {}", format!("{}/{}", ipv4_addr, ipv4_mask), err))),
        }

        // make the bridge interface up
        if let Err(err) = set_link_up(&handle, &ifname).await {
            return Err(err)
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn configure_veth(veth0: &str, veth1: &str, br_if: &str, netns_path: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to connect to netlink: {}", err))),
        };

        tokio::spawn(connection);

        // get bridge interface index
        let mut links = handle.link().get().set_name_filter(br_if.to_string()).execute();
        let bridge_interface_index = match links.try_next().await {
            Ok(Some(link)) => link.header.index,
            Ok(None) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("bridge {} not found", &br_if))),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {}: {}", &br_if, err))),
        };

        // sudo ip link add ${VETH_NAME} type veth peer name ${CNI_IFNAME}
        if let Err(err) = handle.link().add().veth(veth0.to_string(), veth1.to_string()).execute().await {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to create a pair of veth: {}", err)))
        }

        // sudo ip link set ${VETH_NAME} master ${BRIDGE_NAME}
        let mut links = handle.link().get().set_name_filter(veth0.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle.link().set(link.header.index).master(bridge_interface_index).execute().await {
                    Ok(_) => (),
                    Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to set {} to bridge {}: {}", veth0, br_if, err))),
                }
            },
            Ok(None) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("interface {} not found", veth0))),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {}: {}", veth0, err))),
        }

        // sudo ip link set ${VETH_NAME} up
        if let Err(err) = set_link_up(&handle, &veth0).await {
            return Err(err)
        }

        // sudo ip link set ${CNI_IFNAME} netns ${NETNS_NAME} up
        match File::open(netns_path) {
            Ok(netns_file) => {
                let netns_fd = netns_file.as_raw_fd();
                let mut links = handle.link().get().set_name_filter(veth1.to_string()).execute();
                match links.try_next().await {
                    Ok(Some(link)) => {
                        match handle.link().set(link.header.index).setns_by_fd(netns_fd).execute().await {
                            Ok(_) => (),
                            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to set {} to netns: {}", &veth1, err))),
                        }
                    },
                    Ok(None) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("interface {} not found", &veth1))),
                    Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to get interface {}: {}", &veth1, err))),
                }
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to open the netns file: {}", err))),
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn configure_netns_interface(ifname: &str, ipv4_addr: &str, ipv4_mask: &str, gw_ipv4_addr: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to connect to netlink: {}", err))),
        };

        tokio::spawn(connection);

        // sudo ip netns exec ip link set ${CNI_IFNAME} up
        if let Err(err) = set_link_up(&handle, &ifname).await {
            return Err(err)
        }

        // sudo ip netns exec ${NETNS_NAME} ip addr add ${NETNS_IPV4_ADDR}/${IPV4_ADDR_MASK} dev ${CNI_IFNAME}
        match format!("{}/{}", ipv4_addr, ipv4_mask).parse() {
            Ok(ip) => if let Err(err) = add_ip_address(&handle, &ifname, &ip).await {
                return Err(err)
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to parse ip address {}: {}", format!("{}/{}", ipv4_addr, ipv4_mask), err))),
        }

        // sudo ip netns exec ${NETNS_NAME} ip route add default via ${GW_IPV4_ADDR} dev ${CNI_IFNAME}
        match format!("{}", gw_ipv4_addr).parse() {
            Ok(gateway) => {
                match format!("0.0.0.0/0").parse() {
                    Ok(dest) => if let Err(err) = add_route(&handle, &dest, &gateway).await {
                        return Err(err)
                    },
                    Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to parse ip address 0.0.0.0/0: {}", err))),
                }
            },
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to parse ip address {}: {}", gw_ipv4_addr, err))),
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn delete_interface(ifname: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("failed to connect to netlink: {}", err))),
        };

        tokio::spawn(connection);

        // sudo ip netns exec ${NETNS_NAME} ip link del ${CNI_IFNAME}
        if let Err(err) = del_link(&handle, ifname).await {
            return Err(err)
        }

        Ok(())
    }

    pub fn exec_ipam(stdin_data_raw: &str, cni_path: &str, ipam_type: &str) -> Result<String, Error> {
        let ipam_path = format!("{}/{}", cni_path, ipam_type);
        let mut ipam_process = match Command::new(&ipam_path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn() {
            Ok(child) => child,
            Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to exec ipam({}): {}", &ipam_path, err))),
        };
        {
            let stdin = match ipam_process.stdin.as_mut() {
                Some(val) => val,
                None => return Err(Error::new(ErrorKind::Other, "failed to open stdin of ipam")),
            };
            if let Err(err) = stdin.write_all(stdin_data_raw.as_bytes()) {
                return Err(Error::new(ErrorKind::Other, format!("failed to write to stdin of ipam: {}", err)))
            }
        }
        match ipam_process.wait_with_output() {
            Ok(output) => Ok(String::from_utf8_lossy(&output.stdout).to_string()),
            Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to get stdout of ipam: {}", err))),
        }
    }

    // XXX: Replace this by rtnetlink
    pub fn get_hardware_addr(ifname: &str) -> Result<String, Error> {
        match Interface::get_by_name(ifname) {
            Ok(Some(iface)) => {
                match iface.hardware_addr() {
                    Ok(addr) => Ok(addr.as_string()),
                    Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to get hardware address: {}", err))),
                }
            },
            Ok(None) => return Err(Error::new(ErrorKind::Other, format!("interface {} is not found", ifname))),
            Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to get interface {}: {}", ifname, err))),
        }
    }

    pub fn trim_quoted_json_string(v: &Value) -> String {
        let s = v.to_string();
        s[1..(s.len() - 1)].to_string()
    }

    pub fn write_to_log(msg: &str) -> Result<(), Error> {
        let mut file = match Path::new(LOG_FILE_NAME).exists() {
            true => match fs::OpenOptions::new().append(true).open(LOG_FILE_NAME) {
                Ok(f) => f,
                Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to open log file: {}", err))),
            },
            false => match File::create(LOG_FILE_NAME) {
                Ok(f) => f,
                Err(err) => return Err(Error::new(ErrorKind::Other, format!("failed to create log file: {}", err))),
            },
        };
    
        if let Err(err) = file.write_all(msg.as_bytes()) {
            return Err(Error::new(ErrorKind::Other, format!("failed to write to log file: {}", err)))
        }
    
        if let Err(err) = file.flush() {
            return Err(Error::new(ErrorKind::Other, format!("failed to flush log file: {}", err)))
        }

        Ok(())
    }
}

pub mod iptables_utils {
    use std::io::{Error, ErrorKind};
    use sha2::{Digest, Sha512};

    fn generate_chain_name(conf_name: &str, containerid: &str) -> String {
        let mut hasher = Sha512::new();
        hasher.update(conf_name);
        hasher.update(containerid);
        format!("CNI-{}", hex::encode(hasher.finalize()))[..28].to_string()
    }

    pub fn add_iptables(conf_name: &str, cni_containerid: &str, ipv4_addr: &str, subnet: &str) -> Result<(), Error> {
        match iptables::new(false) {
            Ok(ipt) => {
                // sudo iptables --append FORWARD --source 10.244.0.0/24 --jump ACCEPT
                if let Err(err) = ipt.append("filter", "FORWARD", &format!("--source {} --jump ACCEPT", subnet)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to append a rule to FORWARD: {}", err)))
                }
    
                // sudo iptables --append FORWARD --destination 10.244.0.0/24 --jump ACCEPT
                if let Err(err) = ipt.append("filter", "FORWARD", &format!("--destination {} --jump ACCEPT", subnet)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to append a rule to FORWARD: {}", err)))
                }
    
                let chain_name = generate_chain_name(conf_name, cni_containerid);
                // sudo iptables --table nat --new ${CNI_CHAIN_NAME}
                if let Err(err) = ipt.new_chain("nat", &chain_name) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to create a chain: {}", err)))
                }
    
                // sudo iptables --table nat --append ${CNI_CHAIN_NAME} --jump ACCEPT --destination 10.22.0.0/${IPV4_ADDR_MASK}
                if let Err(err) = ipt.append("nat", &chain_name, &format!("--jump ACCEPT --destination {}", subnet)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to append a rule to {}: {}", &chain_name, err)))
                }
    
                // sudo iptables --table nat --append ${CNI_CHAIN_NAME} --jump MASQUERADE ! --destination base-address.mcast.net/4
                if let Err(err) = ipt.append("nat", &chain_name, "--jump MASQUERADE ! --destination base-address.mcast.net/4") {
                    return Err(Error::new(ErrorKind::Other, format!("failed to append a rule to {}: {}", &chain_name, err)))
                }
    
                // sudo iptables --table nat --append POSTROUTING --jump ${CNI_CHAIN_NAME} --source ${NETNS_IPV4_ADDR}
                if let Err(err) = ipt.append("nat", "POSTROUTING", &format!("--jump {} --source {}", &chain_name, ipv4_addr)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to append a rule to POSTROUTING: {}", err)))
                }

                Ok(())
            },
            Err(err) => Err(Error::new(ErrorKind::Other, format!("failed to init iptables: {}", err))),
        }
    }
    
    pub fn del_iptables(conf_name: &str, cni_containerid: &str, subnet: &str) -> Result<(), Error> {
        match iptables::new(false) {
            Ok(ipt) => {
                // sudo iptables --delete FORWARD --source 10.244.0.0/24 --jump ACCEPT
                if let Err(err) = ipt.delete("filter", "FORWARD", &format!("--source {} --jump ACCEPT", subnet)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to delete a rule from FORWARD: {}", err)))
                }
    
                // sudo iptables --delete FORWARD --destination 10.244.0.0/24 --jump ACCEPT
                if let Err(err) = ipt.delete("filter", "FORWARD", &format!("--destination {} --jump ACCEPT", subnet)) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to delete a rule from FORWARD: {}", err)))
                }
    
                let chain_name = generate_chain_name(conf_name, cni_containerid);
                // sudo iptables --table nat --list POSTROUTING --line-numbers
                match ipt.execute("nat", &format!("--list POSTROUTING --line-numbers")) {
                    Ok(output) => {
                        let output_str = String::from_utf8_lossy(&output.stdout).to_string();
                        let lines: Vec<&str> = output_str.split('\n').collect();
                        for line in lines {
                            if !line.contains(&chain_name) {
                                continue;
                            }
    
                            let tokens: Vec<&str> = line.split(' ').collect();
    
                            // sudo iptables --table nat --delete POSTROUTING --jump ${CNI_CHAIN_NAME} --source ${NETNS_IPV4_ADDR}
                            if let Err(err) = ipt.delete("nat", "POSTROUTING", tokens[0]) {
                                return Err(Error::new(ErrorKind::Other, format!("failed to delete a rule from POSTROUTING: {}", err)))
                            }
                        }
                    },
                    Err(err) => println!("{:?}", err),
                }
    
                // sudo iptables --table nat --flush ${CNI_CHAIN_NAME}
                if let Err(err) = ipt.flush_chain("nat", &chain_name) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to flush rules from {}: {}", &chain_name, err)))
                }
    
                // sudo iptables --table nat --delete-chain ${CNI_CHAIN_NAME}
                if let Err(err) = ipt.delete_chain("nat", &chain_name) {
                    return Err(Error::new(ErrorKind::Other, format!("failed to delete a chain {}: {}", &chain_name, err)))
                }
    
                Ok(())
            },
            Err(err) => Err(Error::new(ErrorKind::Other, format!("failed to init iptables: {}", err))),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_generate_chain_name() {
            let chain_name = generate_chain_name("mynet", "cnitool-77383ca0a0715733ca6f");
            assert_eq!(chain_name, "CNI-d0b3203be6ffc55cd4087ca5");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cni_conf() {
        // normal input
        let stdin = r###"
        {
            "cniVersion": "0.4.0",
            "name": "mynet",
            "type": "rust_bridge",
            "bridge": "cni0",
            "isGateway": true,
            "ipMasq": true,
            "ipam": {
                "type": "host-local",
                "subnet": "10.244.1.0/24",
                "routes": [
                    { "dst": "0.0.0.0/0" }
                ]
            }
        }
        "###;
        let result = match CniConf::new(stdin) {
            Ok(val) => val,
            Err(err) => panic!("CniConf::new parse failed: {}", err),
        };
        assert_eq!(result.conf_name, "mynet");
        assert_eq!(result.bridge_name, "cni0");
        assert_eq!(result.ipam_type, "host-local");
        assert_eq!(result.ipam_subnet, "10.244.1.0/24");

        // empty input
        let result = match CniConf::new("{}") {
            Ok(val) => val,
            Err(err) => panic!("CniConf::new parse failed: {}", err),
        };
        assert_eq!(result.conf_name, "");
        assert_eq!(result.bridge_name, "");
        assert_eq!(result.ipam_type, "");
        assert_eq!(result.ipam_subnet, "");

        // invalid input
        match CniConf::new("{") {
            Ok(_) => panic!("CniConf::new parse succeeded unexpectedly"),
            Err(err) => assert!(err.to_string().contains("failed to convert stdin to json: EOF while parsing an object at line 1 column 1")),
        };
    }
}
