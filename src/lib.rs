//! Cross-platform TUN/TAP interfaces for Rust.
//!
//!

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "netbsd")]
pub mod netbsd;
#[cfg(target_os = "openbsd")]
pub mod openbsd;
#[cfg(target_os = "solaris")]
pub mod solaris;
#[cfg(all(target_os = "windows", feature = "tapwin6"))]
pub mod tapwin6;
#[cfg(all(target_os = "windows", feature = "wintun"))]
pub mod wintun;

#[cfg(not(target_os = "windows"))]
mod tap;
#[cfg(any(
    not(target_os = "windows"),
    all(target_os = "windows", feature = "wintun")
))]
mod tun;

#[cfg(not(target_os = "windows"))]
pub use tap::Tap;
#[cfg(any(
    not(target_os = "windows"),
    all(target_os = "windows", feature = "wintun")
))]
pub use tun::Tun;

#[cfg(not(target_os = "windows"))]
use std::ffi::CStr;
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Display};
#[cfg(target_os = "windows")]
use std::ptr;
use std::str::FromStr;
use std::{array, io};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{ERROR_DEV_NOT_EXIST, ERROR_NO_DATA};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdapterIndex, MAX_ADAPTER_NAME};

#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

/// The device state of an [`Interface`].
///
/// Intefaces can generally be configured to be either up (active) or down (inactive). [`Tun`] and
/// [`Tap`] both allow this state to be set via the [`set_state()`](Tun::set_state) method.
#[derive(Clone, Copy, Debug)]
pub enum DeviceState {
    Up,
    Down,
}

#[cfg(not(target_os = "windows"))]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = libc::IF_NAMESIZE - 1;
#[cfg(target_os = "windows")]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = MAX_ADAPTER_NAME as usize - 1;

/// An identifier associated with a particular network device.
///
/// Network interfaces are not guaranteed to be static; network devices can be added and removed,
/// and in certain circumstances an interface that once pointed to one device may end up pointing
/// to another during the course of a program's lifetime.  Likewise, [`index()`](Interface::index)
/// isn't guaranteed to always return the same index for a given interface as the network device
/// associated to that interface could change between consecutive calls to `name()`/`name_raw()`.
/// Conversely, [`from_index()`](Interface::from_index) may not always return the same interface.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    /// The stored name of the interface.
    #[cfg(not(target_os = "windows"))]
    name: [u8; Self::MAX_INTERFACE_NAME_LEN + 1],
    #[cfg(target_os = "windows")]
    name: [u16; Self::MAX_INTERFACE_NAME_LEN + 1],
    is_catchall: bool,
}

impl Interface {
    /// The maximum length (in bytes) that an interface name can be.
    ///
    /// Note that this value is platform-dependent. It determines the size of the buffer used for
    /// storing the interface name in an `Interface` instance, so the size of an `Interface` is
    /// likewise platform-dependent.
    pub const MAX_INTERFACE_NAME_LEN: usize = INTERNAL_MAX_INTERFACE_NAME_LEN;

    /// A special catch-all interface identifier that specifies all operational interfaces.
    #[cfg(not(target_os = "windows"))]
    pub fn any() -> io::Result<Self> {
        let name = [0; Self::MAX_INTERFACE_NAME_LEN + 1];

        // Leave the interface name blank since this is the catch-all identifier
        Ok(Self {
            name,
            is_catchall: true,
        })
    }

    /// Constructs an `Interface` from the given `if_name`.
    ///
    /// `if_name` must not consist of more than 15 bytes of UTF-8, and must not have any null
    /// characters.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if `if_name` is longer than 15 characters
    /// or contains a null byte.
    #[inline]
    pub fn new(if_name: &impl AsRef<OsStr>) -> io::Result<Self> {
        Self::new_inner(if_name)
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    pub fn from_cstr(if_name: &CStr) -> io::Result<Self> {
        Self::new_raw(if_name.to_bytes())
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn new_inner(if_name: &impl AsRef<OsStr>) -> io::Result<Self> {
        let mut utf16 = if_name.as_ref().encode_wide();
        let name = array::from_fn(|_| utf16.next().unwrap_or(0));

        let interface = Interface {
            name,
            is_catchall: false,
        };

        Ok(interface)
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn new_inner(if_name: &impl AsRef<OsStr>) -> io::Result<Self> {
        // Note: `as_encoded_bytes()` is the only think keeping MSRV as high as 1.74
        Self::new_raw(if_name.as_ref().as_encoded_bytes())
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn new_raw(if_name: &[u8]) -> io::Result<Self> {
        if if_name.len() > Self::MAX_INTERFACE_NAME_LEN || if_name.contains(&0x00) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed interface name",
            ));
        }

        let mut name_iter = if_name.iter();
        let name = array::from_fn(|_| name_iter.next().cloned().unwrap_or(0));

        Ok(Interface {
            name,
            is_catchall: false,
        })
    }

    /*
    /// Find all available interfaces on the given machine.
    pub fn find_all() -> io::Result<Vec<Self>> {

    }
    */

    /// Returns the `Interface` corresponding to the given interface index.
    ///
    /// # Errors
    ///
    /// Any returned error indicates that `if_index` does not correspond to a valid interface.
    #[inline]
    #[cfg(not(target_os = "windows"))]
    pub fn from_index(if_index: u32) -> io::Result<Self> {
        // TODO: do Unix systems other than Linux actually consider '0' to be a catch-all?
        if if_index == 0 {
            return Self::any();
        }

        let mut name = [0u8; Self::MAX_INTERFACE_NAME_LEN + 1];
        match unsafe { libc::if_indextoname(if_index, name.as_mut_ptr() as *mut i8) } {
            ptr if ptr.is_null() => Err(io::Error::last_os_error()),
            _ => Ok(Self {
                name,
                is_catchall: false,
            }),
        }
    }

    /// Retrieves the associated index of the network interface.
    #[inline]
    pub fn index(&self) -> io::Result<u32> {
        self.index_impl()
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn index_impl(&self) -> io::Result<u32> {
        match unsafe { libc::if_nametoindex(self.name.as_ptr() as *const i8) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(i),
        }
    }

    #[cfg(target_os = "windows")]
    #[inline]
    fn index_impl(&self) -> io::Result<u32> {
        let mut index = 0u32;
        match unsafe { GetAdapterIndex(self.name.as_ptr(), ptr::addr_of_mut!(index)) } {
            0 => Ok(index),
            ERROR_DEV_NOT_EXIST | ERROR_NO_DATA => Err(io::ErrorKind::NotFound.into()),
            e => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("GetAdapterIndex returned error {}", e),
            )),
        }
    }

    // If the above doesn't work, use
    // ConvertInterfaceNameToLuidA (or else get the LUID directly) and
    // ConvertInterfaceLuidToIndex

    /// Retrieves the name of the interface.
    pub fn name(&self) -> OsString {
        self.name_inner()
    }

    #[cfg(not(target_os = "windows"))]
    fn name_inner(&self) -> OsString {
        let length = self.name.iter().position(|c| *c == 0).unwrap();
        OsStr::from_bytes(&self.name[..length]).to_owned()
    }

    #[cfg(target_os = "windows")]
    fn name_inner(&self) -> OsString {
        let length = self.name.iter().position(|c| *c == 0).unwrap();
        OsString::from_wide(&self.name[..length])
    }

    #[cfg(not(target_os = "windows"))]
    pub fn name_raw_i8(&self) -> [i8; Self::MAX_INTERFACE_NAME_LEN + 1] {
        array::from_fn(|i| self.name[i] as i8)
    }

    /// Returns the name associated with the given interface in C-string format.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if the name assigned to the interface is
    /// not valid UTF-8.
    ///
    /// Otherwise, a returned error indicates that [`Interface`] does not correspond to a valid
    /// interface.
    #[cfg(not(target_os = "windows"))]
    pub fn name_cstr(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.name.as_ptr() as *const i8) }
    }
}

/// A MAC (Media Access Control) address.
pub struct MacAddr {
    addr: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(value: [u8; 6]) -> Self {
        Self { addr: value }
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(value: MacAddr) -> Self {
        value.addr
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacAddress")
            .field(
                "addr",
                &format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    self.addr[0],
                    self.addr[1],
                    self.addr[2],
                    self.addr[3],
                    self.addr[4],
                    self.addr[5]
                ),
            )
            .finish()
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = AddrConversionError; // TODO: change to MacAddrParseError?

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        let mut addr_idx = 0;

        if let Some(delim @ (b':' | b'-')) = s.as_bytes().get(2) {
            // Hexadecimal separated by colons (XX:XX:XX:XX:XX:XX) or dashes (XX-XX-XX-XX-XX-XX)

            if s.bytes().len() != 17 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod3_idx = idx % 3;
                if (mod3_idx) == 2 {
                    if b != *delim {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected colon/dash",
                        ));
                    }
                    addr_idx += 1;
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod3_idx == 0 {
                        b <<= 4;
                    }

                    addr[addr_idx] |= b;
                }
            }
        } else if let Some(b'.') = s.as_bytes().get(4) {
            // Hexadecimal separated by dots (XXXX.XXXX.XXXX)

            if s.bytes().len() != 14 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod5_idx = idx % 5;
                if (mod5_idx) == 4 {
                    if b != b'.' {
                        return Err(AddrConversionError::new("invalid character in MAC address: expected '.' after four hexadecimal values"));
                    }
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod5_idx & 0b1 == 0 {
                        // Evens, i.e. every first hex value in a byte
                        addr[addr_idx] = b << 4;
                    } else {
                        // Odds, i.e. every 2nd hex value
                        addr[addr_idx] |= b;
                        addr_idx += 1;
                    }
                }
            }
        } else {
            // Unseparated hexadecimal (XXXXXXXXXXXX)

            if s.bytes().len() != 12 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                b = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => 10 + (b - b'a'),
                    b'A'..=b'F' => 10 + (b - b'A'),
                    _ => {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected hexadecimal value",
                        ))
                    }
                };

                let even_bit = (idx & 0b1) == 0;

                if even_bit {
                    // Evens, i.e. every first hex value in a byte
                    addr[addr_idx] = b << 4;
                } else {
                    // Odds, i.e. every 2nd hex value
                    addr[addr_idx] |= b;
                    addr_idx += 1;
                }
            }
        }

        Ok(Self { addr })
    }
}

/// An error in converting the format of an address.
///
/// This type encompasses errors in parsing either a `sockaddr_*` type or a string into an address.
#[derive(Debug)]
pub struct AddrConversionError {
    reason: &'static str,
}

impl AddrConversionError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a string describing the nature of the conversion error.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.reason
    }
}
