use crate::{chmod, ensure_dirs_exist, Endpoint, Error, IoErrorContext, WrappedIoError, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use regex::Regex;
use indoc::writedoc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};
use wireguard_control::InterfaceName;

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    /// The information to bring up the interface.
    pub interface: InterfaceInfo,

    /// The necessary contact information for the server.
    pub server: ServerInfo,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
/// Configuration for a vanilla WireGuard client
pub struct VanillaConfig {
    pub interface: VanillaInterface,
    pub peer: VanillaPeer,
}

impl From<InterfaceConfig> for VanillaConfig {
    fn from(config: InterfaceConfig) -> Self {
        VanillaConfig {
            interface: VanillaInterface::from(&config.interface),
            peer: VanillaPeer::from(&config.server),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceInfo {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix.
    pub address: IpNet,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// The local listen port. A random port will be used if `None`.
    pub listen_port: Option<u16>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
/// Interface information for a vanilla WireGuard client
pub struct VanillaInterface {
    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix.
    address: IpNet,
    /// The WireGuard private key (base64)
    private_key: String,
    /// The local listen port. A random port will be used if 0.
    listen_port: u16,
    #[serde(skip)]
    network_name: Option<String>,
}

impl From<&InterfaceInfo> for VanillaInterface {
    fn from(interface: &InterfaceInfo) -> Self {
        VanillaInterface {
            address: interface.address,
            private_key: interface.private_key.clone(),
            listen_port: interface.listen_port.unwrap_or(0),
            network_name: Some(interface.network_name.clone()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ServerInfo {
    /// The server's WireGuard public key
    pub public_key: String,

    /// The external internet endpoint to reach the server.
    pub external_endpoint: Endpoint,

    /// An internal endpoint in the WireGuard network that hosts the coordination API.
    pub internal_endpoint: SocketAddr,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
/// Server information for the vanilla WireGuard client
pub struct VanillaPeer {
    /// The server's public key
    public_key: String,
    /// The external internet endpoint to reach the server.
    endpoint: Endpoint,
    /// The IP addresses CIDR that this peer is allowed to communicate with, comma separated.
    #[serde(alias = "AllowedIPs")]
    allowed_ips: String,
    /// The persistent keepalive interval in seconds
    persistent_keepalive: u16,
    #[serde(skip)]
    internal_endpoint: Option<SocketAddr>,
}

impl From<&ServerInfo> for VanillaPeer {
    fn from(server: &ServerInfo) -> Self {
        let allowed_ips = format!("{}/32", server.internal_endpoint.ip());

        VanillaPeer {
            public_key: server.public_key.clone(),
            endpoint: server.external_endpoint.clone(),
            persistent_keepalive: PERSISTENT_KEEPALIVE_INTERVAL_SECS,
            allowed_ips,
            internal_endpoint: Some(server.internal_endpoint),
        }
    }
}

impl InterfaceConfig {
    pub fn write_to(
        &self,
        target_file: &mut File,
        comments: bool,
        mode: Option<u32>,
    ) -> Result<(), io::Error> {
        if let Some(val) = mode {
            chmod(target_file, val)?;
        }

        if comments {
            writedoc!(
                target_file,
                r"
                    # This is an invitation file to an innernet network.
                    #
                    # To join, you must install innernet.
                    # See https://github.com/tonarino/innernet for instructions.
                    #
                    # If you have innernet, just run:
                    #
                    #   innernet install <this file>
                    #
                    # Don't edit the contents below unless you love chaos and dysfunction.
                "
            )?;
        }
        target_file.write_all(toml::to_string(self).unwrap().as_bytes())?;
        Ok(())
    }

    pub fn write_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        comments: bool,
        mode: Option<u32>,
    ) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        let mut target_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_path(path)?;
        self.write_to(&mut target_file, comments, mode)
            .with_path(path)
    }

    /// Overwrites the config file if it already exists.
    pub fn write_to_interface(
        &self,
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(toml::to_string(self).unwrap().as_bytes())?;
        Ok(path)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(toml::from_str(
            &std::fs::read_to_string(&path).with_path(path)?,
        )?)
    }

    pub fn from_interface(config_dir: &Path, interface: &InterfaceName) -> Result<Self, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        crate::warn_on_dangerous_mode(&path).with_path(&path)?;
        Self::from_file(path)
    }

    pub fn get_path(config_dir: &Path, interface: &InterfaceName) -> PathBuf {
        config_dir
            .join(interface.to_string())
            .with_extension("conf")
    }

    fn build_config_file_path(
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, WrappedIoError> {
        ensure_dirs_exist(&[config_dir])?;
        Ok(Self::get_path(config_dir, interface))
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wireguard_control::Key::from_base64(&self.private_key)?
            .get_public()
            .to_base64())
    }
}

impl VanillaConfig {
    pub fn write_to(
        &self,
        target_file: &mut File,
        mode: Option<u32>,
    ) -> Result<(), io::Error> {
        if self.peer.internal_endpoint.is_none() || self.interface.network_name.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot write vanilla config without internal endpoint and network name",
            ));
        }

        if let Some(val) = mode {
            chmod(target_file, val)?;
        }

        writedoc!(
            target_file,
            r"
            # This is an exported innernet peer for WireGuard clients.
            #
            # Any changes to the peer configuration should be made using innernet
            # and then this file imported and re-exported.
            #
            # Don't edit the contents below unless you love chaos and dysfunction.
            "
        )?;

        // unwrap ok because we checked above
        // comments because WireGuard clients don't accept unknown keys
        target_file.write_fmt(format_args!("# !network_name,{}\n", self.interface.network_name.as_ref().unwrap()))?;
        target_file.write_fmt(format_args!("# !internal_endpoint,{}\n", self.peer.internal_endpoint.unwrap()))?;

        // Remove quotes from the generated TOML because WireGuard uses INI
        // can't see a nicer way to do this!
        let mut toml = toml::to_string(self).unwrap();
        toml = toml.replace('"', "");
        target_file.write_all(toml.as_bytes())?;
        Ok(())
    }

    pub fn write_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        truncate: bool,
        mode: Option<u32>,
    ) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        // this will truncate the file if it already exists
        let mut target_file = OpenOptions::new()
            .create(truncate)
            .truncate(truncate)
            .create_new(!truncate)
            .write(true)
            .open(path)
            .with_path(path)?;
        self.write_to(&mut target_file, mode)
            .with_path(path)
    }

    fn read_comment_network_name(s: &str) -> Result<String, Error> {
        let re = Regex::new(r"(?m)^#\s?!network_name,(?P<network>.*)$")?;

        Ok(re
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("Regex matches failed"))?
            .name("network")
            .ok_or_else(|| anyhow::anyhow!("No network name found in comments"))?
            .as_str()
            .to_string()
        )
    }

    fn read_comment_internal_endpoint(s: &str) -> Result<SocketAddr, Error> {
        let re = Regex::new(r"(?m)^#\s?!internal_endpoint,(?P<endpoint>.*)$")?;

        Ok(re
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("No internal endpoint found in comments"))?
            .name("endpoint")
            .ok_or_else(|| anyhow::anyhow!("No internal endpoint found in comments"))?
            .as_str()
            .parse()?
        )
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file_str = std::fs::read_to_string(&path).with_path(path)?;
        let mut ret: Self = serde_ini::from_str(&file_str)?;
        ret.interface.network_name = Self::read_comment_network_name(&file_str).ok();
        ret.peer.internal_endpoint = Self::read_comment_internal_endpoint(&file_str).ok();

        Ok(ret)
    }

    pub fn set_network_name(&mut self, network_name: String) {
        self.interface.network_name = Some(network_name);
    }

    pub fn set_internal_endpoint(&mut self, internal_endpoint: SocketAddr) {
        self.peer.internal_endpoint = Some(internal_endpoint);
    }

    pub fn to_interface_config(&self) -> Result<InterfaceConfig, Error> {
        if self.interface.network_name.is_none() || self.peer.internal_endpoint.is_none() {
            anyhow::bail!("network_name and internal_endpoint must be passed");
        }

        let interface = InterfaceInfo {
            network_name: self.interface.network_name.clone().unwrap(),
            private_key: self.interface.private_key.clone(),
            listen_port: match self.interface.listen_port {
                0 => None,
                n => Some(n),
            },
            address: self.interface.address,
        };

        let server = ServerInfo {
            public_key: self.peer.public_key.clone(),
            external_endpoint: self.peer.endpoint.clone(),
            internal_endpoint: self.peer.internal_endpoint.unwrap(),
        };

        Ok(InterfaceConfig {
            interface,
            server,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    const VANILLA_CONF: &'static str = r#"
# This is an exported innernet peer for WireGuard clients.
#
# Any changes to the peer configuration should be made using innernet
# and then this file re-exported.
#
# Don't edit the contents below unless you love chaos and dysfunction.
# !network_name,test
# !internal_endpoint,10.1.2.1:5555
[Interface]
PrivateKey = SH5Opig14+WK3tNApHIfP++hq1Dn+W7S3+qj0YJNQmw=
ListenPort = 0
Address = 10.1.2.8/24

[Peer]
PublicKey = aO5eEOeDwoCNzIJ0Z97EvVWmZAu6XuXpuzvbIDKPv08=
AllowedIPs = 10.1.2.1/32
Endpoint = 165.12.32.3:5555
PersistentKeepalive = 25"#;

    #[test]
    fn serialize_vanilla_config_interface() {
        let config = VanillaConfig {
            interface: VanillaInterface {
                network_name: Some("test".to_string()),
                private_key: "SH5Opig14+WK3tNApHIfP++hq1Dn+W7S3+qj0YJNQmw=".to_string(),
                listen_port: 0,
                address: IpNet::from_str("10.1.2.8/24").unwrap(),
            },
            peer: VanillaPeer {
                public_key: "aO5eEOeDwoCNzIJ0Z97EvVWmZAu6XuXpuzvbIDKPv08=".to_string(),
                endpoint: Endpoint::from_str("165.12.32.3:5555").unwrap(),
                allowed_ips: "10.1.2.1/32".to_string(),
                persistent_keepalive: 25,
                internal_endpoint: Some(SocketAddr::from_str("10.1.2.1:5555").unwrap()),
            }
        };

        config.write_to_path("test.conf", true, None).unwrap();
    }

    #[test]
    fn deserialize_vanilla_config_interface() {
        let mut config: VanillaConfig = serde_ini::from_str(VANILLA_CONF).unwrap();
        config.interface.network_name = VanillaConfig::read_comment_network_name(VANILLA_CONF).ok();
        config.peer.internal_endpoint = VanillaConfig::read_comment_internal_endpoint(VANILLA_CONF).ok();

        assert_eq!(config.interface.private_key, "SH5Opig14+WK3tNApHIfP++hq1Dn+W7S3+qj0YJNQmw=");
        assert_eq!(config.interface.listen_port, 0);
        assert_eq!(config.peer.public_key, "aO5eEOeDwoCNzIJ0Z97EvVWmZAu6XuXpuzvbIDKPv08=");
        assert_eq!(config.peer.endpoint, Endpoint::from_str("165.12.32.3:5555").unwrap());
        assert_eq!(config.peer.allowed_ips, "10.1.2.1/32");
        assert_eq!(config.peer.persistent_keepalive, 25);

        // should have read from comments
        assert!(config.interface.network_name.is_some());
        assert!(config.peer.internal_endpoint.is_some());

        let inner_config = config.to_interface_config();
        assert!(inner_config.is_ok());
    }
}
