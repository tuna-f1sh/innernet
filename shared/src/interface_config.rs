use crate::{chmod, ensure_dirs_exist, Endpoint, Error, IoErrorContext, WrappedIoError, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
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

#[derive(Clone, Serialize, Debug)]
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

#[derive(Clone, Serialize, Debug)]
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
}

impl From<&InterfaceInfo> for VanillaInterface {
    fn from(interface: &InterfaceInfo) -> Self {
        VanillaInterface {
            address: interface.address,
            private_key: interface.private_key.clone(),
            listen_port: interface.listen_port.unwrap_or(0),
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

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
/// Server information for the vanilla WireGuard client
pub struct VanillaPeer {
    /// The server's public key
    public_key: String,
    /// The external internet endpoint to reach the server.
    endpoint: Endpoint,
    /// The IP addresses CIDR that this peer is allowed to communicate with, comma separated.
    allowed_ips: String,
    /// The persistent keepalive interval in seconds
    persistent_keepalive: u16,
}

impl From<&ServerInfo> for VanillaPeer {
    fn from(server: &ServerInfo) -> Self {
        let allowed_ips = format!("{}/32", server.internal_endpoint.ip());

        VanillaPeer {
            public_key: server.public_key.clone(),
            endpoint: server.external_endpoint.clone(),
            persistent_keepalive: PERSISTENT_KEEPALIVE_INTERVAL_SECS,
            allowed_ips,
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
        if let Some(val) = mode {
            chmod(target_file, val)?;
        }

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
}
