use std::{
    io,
    iter,
    mem::{MaybeUninit, size_of},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str::FromStr,
    time::Duration,
};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, U16, Unaligned, byteorder::BigEndian};

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::UdpBind)?;
    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(500)));

    let stun = SocketAddr::from_str("162.159.207.0:3478").unwrap(); // stun.cloudflare.com

    let magic_cookie: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
    #[allow(invalid_value)]
    #[allow(clippy::uninit_assumed_init)]
    let random = unsafe { MaybeUninit::<[u8; 12]>::uninit().assume_init() }; // :)
    let request = StunRequest::new(magic_cookie, &random);

    let mut response = [0u8; 548];

    for _ in 0..3 {
        socket.send_to(&request, stun).map_err(Error::Send)?;

        match socket.recv_from(&mut response) {
            Ok((size, addr)) if addr == stun => {
                if size < size_of::<StunHeader>() {
                    eprintln!("Received STUN response is too small: {size}");
                    continue;
                }

                let Some(response) = StunResponse::new(&response[..size]) else {
                    eprintln!("Failed to parse STUN response");
                    continue;
                };

                if !response
                    .header
                    .matches(StunMessageType::SuccessResponse, magic_cookie, &random)
                {
                    eprintln!("Received STUN response does not match request");
                    continue;
                }

                for attr in response.attrs() {
                    let xored = match attr.r#type() {
                        StunAttrType::XorMappedAddress => true,
                        StunAttrType::MappedAddress => false,
                        _ => continue,
                    };

                    if let Some(ipv4) = attr.as_ipv4() {
                        let ip_addr = ipv4.address(xored, magic_cookie);
                        let port = ipv4.port(xored, magic_cookie);
                        println!("Public IP: {ip_addr}, Port: {port}");
                        return Ok(());
                    } else if let Some(ipv6) = attr.as_ipv6() {
                        let ip_addr = ipv6.address(xored, magic_cookie, &random);
                        let port = ipv6.port(xored, magic_cookie);
                        println!("Public IP: {ip_addr}, Port: {port}");
                        return Ok(());
                    }
                }

                eprintln!("No MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute found in STUN response");
                continue;
            },
            Ok((_, addr)) => {
                eprintln!("Received response from unexpected address: {addr:?}");
                continue;
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                eprintln!("Timeout waiting for STUN response");
                continue;
            },
            Err(e) => {
                eprintln!("Error receiving response: {e:?}");
                continue;
            },
        }
    }

    Ok(())
}

struct StunResponse<'a> {
    header: &'a StunHeader,
    payload: &'a [u8],
}

impl StunResponse<'_> {
    fn new(data: &[u8]) -> Option<StunResponse<'_>> {
        let (header, payload) = StunHeader::ref_from_prefix(data).ok()?;
        let payload = payload.get(..header.len())?;
        debug_assert_eq!(payload.len(), header.len());
        Some(StunResponse { header, payload })
    }

    fn len(&self) -> usize { self.payload.len() }

    fn attrs(&self) -> impl Iterator<Item = StunAttribute<'_>> {
        let length = self.len();
        let mut offset = 0;

        iter::from_fn(move || {
            if offset + 4 <= length {
                let attr_length = u16::from_be_bytes([self.payload[offset + 2], self.payload[offset + 3]]) as usize;
                let total_length = 4 + ((attr_length + 3) & !3); // align to 4 bytes

                if offset + total_length <= length {
                    let (header, payload) =
                        StunAttrHeader::ref_from_prefix(&self.payload[offset..offset + total_length]).ok()?;
                    offset += total_length;
                    return StunAttribute::new(header, payload);
                }
            }
            None
        })
    }
}

struct StunAttribute<'a> {
    header: &'a StunAttrHeader,
    payload: &'a [u8],
}

impl StunAttribute<'_> {
    fn new<'a>(header: &'a StunAttrHeader, payload: &'a [u8]) -> Option<StunAttribute<'a>> {
        let payload = payload.get(..header.length.get() as usize)?;
        debug_assert_eq!(payload.len(), header.length.get() as usize);
        Some(StunAttribute { header, payload })
    }

    fn r#type(&self) -> StunAttrType { self.header.r#type() }

    fn len(&self) -> usize { self.payload.len() }

    fn as_ipv4(&self) -> Option<&StunAddrV4> {
        if self.len() >= size_of::<StunAddrV4>() && self.payload[1] == 0x01 {
            return StunAddrV4::ref_from_bytes(self.payload).ok();
        }
        None
    }

    fn as_ipv6(&self) -> Option<&StunAddrV6> {
        if self.len() >= size_of::<StunAddrV6>() && self.payload[1] == 0x02 {
            return StunAddrV6::ref_from_bytes(self.payload).ok();
        }
        None
    }
}

// lower

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug)]
#[repr(C)]
struct StunHeader {
    r#type: U16<BigEndian>,
    length: U16<BigEndian>,
    magic_cookie: [u8; 4],
    transaction_id: [u8; 12],
}

const _: () = assert!(size_of::<StunHeader>() == 20);

impl StunHeader {
    #[inline]
    fn len(&self) -> usize { self.length.get() as usize }

    fn matches(&self, r#type: StunMessageType, magic_cookie: [u8; 4], transaction_id: &[u8; 12]) -> bool {
        self.r#type() == r#type && self.magic_cookie == magic_cookie && self.transaction_id == *transaction_id
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum StunMessageType {
    Unknown = 0x0000,
    Request = 0x0001,
    SuccessResponse = 0x0101,
    ErrorResponse = 0x0111,
    Indication = 0x0011,
}

impl StunHeader {
    fn r#type(&self) -> StunMessageType {
        match self.r#type.get() {
            0x0001 => StunMessageType::Request,
            0x0101 => StunMessageType::SuccessResponse,
            0x0111 => StunMessageType::ErrorResponse,
            0x0011 => StunMessageType::Indication,
            _ => StunMessageType::Unknown,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug)]
#[repr(C)]
struct StunAttrHeader {
    r#type: U16<BigEndian>,
    length: U16<BigEndian>,
}

const _: () = assert!(size_of::<StunAttrHeader>() == 4);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum StunAttrType {
    Unknown = 0x0000,
    MappedAddress = 0x0001,
    XorMappedAddress = 0x0020,
    ErrorCode = 0x0009,
    Software = 0x8022,
    Fingerprint = 0x8028,
}

impl StunAttrHeader {
    fn r#type(&self) -> StunAttrType {
        match self.r#type.get() {
            0x0001 => StunAttrType::MappedAddress,
            0x0020 => StunAttrType::XorMappedAddress,
            0x0009 => StunAttrType::ErrorCode,
            0x8022 => StunAttrType::Software,
            0x8028 => StunAttrType::Fingerprint,
            _ => StunAttrType::Unknown,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug)]
#[repr(C)]
struct StunAddrV4 {
    reserved: u8,
    family: u8,
    port: U16<BigEndian>,
    address: [u8; 4],
}

const _: () = assert!(size_of::<StunAddrV4>() == 8);

impl StunAddrV4 {
    fn address(&self, xored: bool, magic_cookie: [u8; 4]) -> Ipv4Addr {
        let mut addr = self.address;
        if xored {
            for i in 0..4 {
                addr[i] ^= magic_cookie[i];
            }
        }
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])
    }

    fn port(&self, xored: bool, magic_cookie: [u8; 4]) -> u16 {
        let mut port = self.port.get();
        if xored {
            port ^= u16::from_be_bytes([magic_cookie[0], magic_cookie[1]])
        }
        port
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug)]
#[repr(C)]
struct StunAddrV6 {
    reserved: u8,
    family: u8,
    port: U16<BigEndian>,
    address: [u8; 16],
}

const _: () = assert!(size_of::<StunAddrV6>() == 20);

impl StunAddrV6 {
    fn address(&self, xored: bool, magic_cookie: [u8; 4], transaction_id: &[u8; 12]) -> Ipv6Addr {
        let mut addr = self.address;
        if xored {
            for i in 0..16 {
                addr[i] ^= if i < 4 { magic_cookie[i] } else { transaction_id[i - 4] }
            }
        }
        Ipv6Addr::from(addr)
    }

    fn port(&self, xored: bool, magic_cookie: [u8; 4]) -> u16 {
        let mut port = self.port.get();
        if xored {
            port ^= u16::from_be_bytes([magic_cookie[0], magic_cookie[1]])
        }
        port
    }
}

// request

struct StunRequest([u8; 20]);

impl StunRequest {
    fn new(magic_cookie: [u8; 4], random: &[u8; 12]) -> Self {
        let mut request = [0u8; 20];
        request[0] = 0x00; // STUN Binding Request
        request[1] = 0x01; // Message Type
        request[2] = 0x00; // Message Length (high byte)
        request[3] = 0x00; // Message Length (low byte)
        request[4..8].copy_from_slice(&magic_cookie); // Magic Cookie
        request[8..20].copy_from_slice(random); // Transaction ID
        StunRequest(request)
    }

    fn as_bytes(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for StunRequest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target { self.as_bytes() }
}

#[derive(Debug)]
#[allow(unused)]
enum Error {
    UdpBind(io::Error),
    Send(io::Error),
}
