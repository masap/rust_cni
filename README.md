# Rust CNI
This is a Kubernetes CNI plugin written with [Rust](https://www.rust-lang.org/).

This is a re-write of [bridge plugin](https://github.com/containernetworking/plugins/tree/master/plugins/main/bridge).

This CNI plugin depends on [host-local](https://github.com/containernetworking/plugins/tree/master/plugins/ipam/host-local) IPAM.

----

## How to install Rust CNI
Build and place the binary on Ubuntu 20.04.
```
sudo apt install rustc kubernetes-cni
git clone https://github.com/masap/rust_cni
cd rust_cni/rust_bridge
cargo build --release
sudo cp target/release/rust_bridge /opt/cni/bin/
```

Put this conf file to ```/etc/cni/net.d/10-rust_cni.conf```.
```
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
```

Log file is at ```/tmp/rust_cni.log```.