//! USBPcap capture header parser and builder.
//!
//! USBPcap is a USB traffic sniffer for Windows. Captures written with
//! link type 249 (`LINKTYPE_USBPCAP`) carry a 27-byte little-endian header
//! in front of the raw USB data of each packet. It records which bus,
//! device and endpoint the transfer touched and which URB function was
//! involved.
//!
//! This is only relevant for USB capture files — regular network captures
//! never contain these headers.
//!
//! # Header layout (27 bytes, little-endian)
//!
//! ```text
//!  0   header_length   u16
//!  2   irp_id          u64
//!  10  status          u32
//!  14  function        u16
//!  16  info            u8   (bit 0: pdo_to_fdo, bits 1-7 reserved)
//!  17  bus             u16
//!  19  device          u16
//!  21  endpoint        u8   (bit 7: direction, bits 6-4 reserved, bits 3-0 number)
//!  22  transfer        u8
//!  23  data_length     u32
//!  27+ header_payload  header_length - 27 bytes (extra header fields)
//!  ... data            data_length bytes (the USB transfer payload)
//! ```
//!
//! # Examples
//!
//! ```
//! use wireforge_core::usbpcap::{UsbPcapPacket, UsbPcapPacketBuilder, USBPCAP_TRANSFER_BULK};
//! use wireforge_core::util::PacketBuilder;
//!
//! let packet = UsbPcapPacketBuilder::new()
//!     .bus(1)
//!     .device(4)
//!     .direction(true) // IN, device-to-host
//!     .endpoint(1)
//!     .unwrap()
//!     .transfer(USBPCAP_TRANSFER_BULK)
//!     .payload(&[0xDE, 0xAD, 0xBE, 0xEF])
//!     .build();
//!
//! let usb = UsbPcapPacket::new(&packet).unwrap();
//! assert_eq!(usb.bus(), 1);
//! assert_eq!(usb.device(), 4);
//! assert!(usb.direction());
//! assert_eq!(usb.endpoint(), 1);
//! assert_eq!(usb.transfer(), USBPCAP_TRANSFER_BULK);
//! assert_eq!(usb.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
//! ```

use alloc::vec::Vec;

use crate::util::PacketBuilder;

/// Minimum USBPcap header length in bytes.
pub const USBPCAP_HEADER_LEN: usize = 27;

/// pcap link type for USB captures with USBPcap headers
/// (`LINKTYPE_USBPCAP`).
pub const USBPCAP_LINKTYPE: u32 = 249;

/// Info bit 0 — the transfer direction is from the Physical Device Object
/// toward the Functional Device Object (device-to-host side of the stack).
pub const USBPCAP_INFO_PDO_TO_FDO: u8 = 0x01;

/// Endpoint byte bit 7 — endpoint direction (1 = device-to-host, IN).
pub const USBPCAP_ENDPOINT_DIRECTION_IN: u8 = 0x80;

/// Isochronous transfer.
pub const USBPCAP_TRANSFER_ISOCHRONOUS: u8 = 0;
/// Interrupt transfer.
pub const USBPCAP_TRANSFER_INTERRUPT: u8 = 1;
/// Control transfer.
pub const USBPCAP_TRANSFER_CONTROL: u8 = 2;
/// Bulk transfer.
pub const USBPCAP_TRANSFER_BULK: u8 = 3;
/// Unknown transfer type.
pub const USBPCAP_TRANSFER_UNKNOWN: u8 = 0xFE;
/// Invalid transfer type.
pub const USBPCAP_TRANSFER_INVALID: u8 = 0xFF;

/// URB function — select configuration.
pub const URB_FUNCTION_SELECT_CONFIGURATION: u16 = 0x0000;
/// URB function — select interface.
pub const URB_FUNCTION_SELECT_INTERFACE: u16 = 0x0001;
/// URB function — abort pipe.
pub const URB_FUNCTION_ABORT_PIPE: u16 = 0x0002;
/// URB function — take frame length control.
pub const URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL: u16 = 0x0003;
/// URB function — release frame length control.
pub const URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL: u16 = 0x0004;
/// URB function — get frame length.
pub const URB_FUNCTION_GET_FRAME_LENGTH: u16 = 0x0005;
/// URB function — set frame length.
pub const URB_FUNCTION_SET_FRAME_LENGTH: u16 = 0x0006;
/// URB function — get current frame number.
pub const URB_FUNCTION_GET_CURRENT_FRAME_NUMBER: u16 = 0x0007;
/// URB function — synchronous control transfer.
pub const URB_FUNCTION_CONTROL_TRANSFER: u16 = 0x0008;
/// URB function — bulk or interrupt transfer.
pub const URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: u16 = 0x0009;
/// URB function — isochronous transfer.
pub const URB_FUNCTION_ISOCH_TRANSFER: u16 = 0x000A;
/// URB function — get descriptor from device.
pub const URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE: u16 = 0x000B;
/// URB function — set descriptor to device.
pub const URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE: u16 = 0x000C;
/// URB function — set feature to device.
pub const URB_FUNCTION_SET_FEATURE_TO_DEVICE: u16 = 0x000D;
/// URB function — set feature to interface.
pub const URB_FUNCTION_SET_FEATURE_TO_INTERFACE: u16 = 0x000E;
/// URB function — set feature to endpoint.
pub const URB_FUNCTION_SET_FEATURE_TO_ENDPOINT: u16 = 0x000F;
/// URB function — clear feature to device.
pub const URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE: u16 = 0x0010;
/// URB function — clear feature to interface.
pub const URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE: u16 = 0x0011;
/// URB function — clear feature to endpoint.
pub const URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT: u16 = 0x0012;
/// URB function — get status from device.
pub const URB_FUNCTION_GET_STATUS_FROM_DEVICE: u16 = 0x0013;
/// URB function — get status from interface.
pub const URB_FUNCTION_GET_STATUS_FROM_INTERFACE: u16 = 0x0014;
/// URB function — get status from endpoint.
pub const URB_FUNCTION_GET_STATUS_FROM_ENDPOINT: u16 = 0x0015;
/// URB function — vendor request to device.
pub const URB_FUNCTION_VENDOR_DEVICE: u16 = 0x0017;
/// URB function — vendor request to interface.
pub const URB_FUNCTION_VENDOR_INTERFACE: u16 = 0x0018;
/// URB function — vendor request to endpoint.
pub const URB_FUNCTION_VENDOR_ENDPOINT: u16 = 0x0019;
/// URB function — class request to device.
pub const URB_FUNCTION_CLASS_DEVICE: u16 = 0x001A;
/// URB function — class request to interface.
pub const URB_FUNCTION_CLASS_INTERFACE: u16 = 0x001B;
/// URB function — class request to endpoint.
pub const URB_FUNCTION_CLASS_ENDPOINT: u16 = 0x001C;
/// URB function — reset pipe and clear stall.
pub const URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL: u16 = 0x001E;
/// URB function — class request to other target.
pub const URB_FUNCTION_CLASS_OTHER: u16 = 0x001F;
/// URB function — vendor request to other target.
pub const URB_FUNCTION_VENDOR_OTHER: u16 = 0x0020;
/// URB function — get status from other target.
pub const URB_FUNCTION_GET_STATUS_FROM_OTHER: u16 = 0x0021;
/// URB function — clear feature to other target.
pub const URB_FUNCTION_CLEAR_FEATURE_TO_OTHER: u16 = 0x0022;
/// URB function — set feature to other target.
pub const URB_FUNCTION_SET_FEATURE_TO_OTHER: u16 = 0x0023;
/// URB function — get descriptor from endpoint.
pub const URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT: u16 = 0x0024;
/// URB function — set descriptor to endpoint.
pub const URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT: u16 = 0x0025;
/// URB function — get configuration.
pub const URB_FUNCTION_GET_CONFIGURATION: u16 = 0x0026;
/// URB function — get interface.
pub const URB_FUNCTION_GET_INTERFACE: u16 = 0x0027;
/// URB function — get descriptor from interface.
pub const URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE: u16 = 0x0028;
/// URB function — set descriptor to interface.
pub const URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE: u16 = 0x0029;
/// URB function — get Microsoft OS feature descriptor.
pub const URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR: u16 = 0x002A;
/// URB function — asynchronous control transfer.
pub const URB_FUNCTION_CONTROL_TRANSFER_EX: u16 = 0x0031;

/// Zero-copy USBPcap header parser.
///
/// Holds a reference to the bytes starting at the USBPcap header. The
/// USB transfer payload follows the (possibly extended) header.
#[derive(Debug, Clone)]
pub struct UsbPcapPacket<'a> {
    buf: &'a [u8],
}

impl<'a> UsbPcapPacket<'a> {
    crate::parser_new!(USBPCAP_HEADER_LEN);

    /// The declared header length in bytes — 27 for the base header,
    /// larger when extra header fields are present.
    #[inline]
    pub fn header_length(&self) -> u16 {
        u16::from_le_bytes([self.buf[0], self.buf[1]])
    }

    /// The I/O request packet (IRP) identifier.
    #[inline]
    pub fn irp_id(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[2..10]);
        u64::from_le_bytes(bytes)
    }

    /// The USBD status (NTSTATUS) of the request.
    #[inline]
    pub fn status(&self) -> u32 {
        read_u32le(&self.buf[10..14])
    }

    /// The URB function (see the `URB_FUNCTION_*` constants).
    #[inline]
    pub fn function(&self) -> u16 {
        read_u16le(&self.buf[14..16])
    }

    /// The raw info octet.
    #[inline]
    pub fn info(&self) -> u8 {
        self.buf[16]
    }

    /// Whether bit 0 of the info octet (`pdo_to_fdo`) is set.
    #[inline]
    pub fn pdo_to_fdo(&self) -> bool {
        self.buf[16] & USBPCAP_INFO_PDO_TO_FDO != 0
    }

    /// The USB bus number.
    #[inline]
    pub fn bus(&self) -> u16 {
        read_u16le(&self.buf[17..19])
    }

    /// The device address on the bus.
    #[inline]
    pub fn device(&self) -> u16 {
        read_u16le(&self.buf[19..21])
    }

    /// The raw endpoint octet (direction bit + endpoint number).
    #[inline]
    pub fn endpoint_byte(&self) -> u8 {
        self.buf[21]
    }

    /// The endpoint direction — `true` for IN (device-to-host).
    #[inline]
    pub fn direction(&self) -> bool {
        self.buf[21] & USBPCAP_ENDPOINT_DIRECTION_IN != 0
    }

    /// The 4-bit endpoint number (low nibble of the endpoint octet).
    #[inline]
    pub fn endpoint(&self) -> u8 {
        self.buf[21] & 0x0F
    }

    /// The transfer type (see the `USBPCAP_TRANSFER_*` constants).
    #[inline]
    pub fn transfer(&self) -> u8 {
        self.buf[22]
    }

    /// The number of payload bytes that follow the header.
    #[inline]
    pub fn data_length(&self) -> u32 {
        read_u32le(&self.buf[23..27])
    }

    /// Extra header fields (bytes between the 27-byte base header and the
    /// declared `header_length`). Empty when there are none; also empty for
    /// malformed headers declaring a length below 27.
    pub fn header_payload(&self) -> &'a [u8] {
        let end = (self.header_length() as usize).max(USBPCAP_HEADER_LEN).min(self.buf.len());
        &self.buf[USBPCAP_HEADER_LEN..end]
    }

    /// The USB transfer payload (`data_length` bytes after the header),
    /// clamped to the available bytes.
    pub fn payload(&self) -> &'a [u8] {
        let start = (self.header_length() as usize).max(USBPCAP_HEADER_LEN).min(self.buf.len());
        let end = (start + self.data_length() as usize).min(self.buf.len());
        &self.buf[start..end]
    }
}

// Little-endian helpers local to this module (the util module only carries
// big-endian readers, which is what every network protocol needs).
#[inline]
fn read_u16le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

#[inline]
fn read_u32le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Builder for USBPcap capture headers.
///
/// The `header_length` and `data_length` fields are derived automatically
/// from the header payload and transfer payload that are attached.
#[derive(Debug, Clone)]
pub struct UsbPcapPacketBuilder {
    buf: [u8; USBPCAP_HEADER_LEN],
    header_payload: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
}

impl UsbPcapPacketBuilder {
    /// Create a builder with a 27-byte base header and all fields zeroed.
    pub fn new() -> Self {
        let mut buf = [0u8; USBPCAP_HEADER_LEN];
        buf[0..2].copy_from_slice(&(USBPCAP_HEADER_LEN as u16).to_le_bytes());
        Self { buf, header_payload: None, payload: None }
    }

    /// Set the IRP identifier.
    pub fn irp_id(mut self, v: u64) -> Self {
        self.buf[2..10].copy_from_slice(&v.to_le_bytes());
        self
    }

    /// Set the USBD status (NTSTATUS).
    pub fn status(mut self, v: u32) -> Self {
        self.buf[10..14].copy_from_slice(&v.to_le_bytes());
        self
    }

    /// Set the URB function.
    pub fn function(mut self, v: u16) -> Self {
        self.buf[14..16].copy_from_slice(&v.to_le_bytes());
        self
    }

    /// Set the info octet (overrides any individual info bits).
    pub fn info(mut self, v: u8) -> Self {
        self.buf[16] = v;
        self
    }

    /// Set the `pdo_to_fdo` info bit.
    pub fn pdo_to_fdo(mut self, v: bool) -> Self {
        if v {
            self.buf[16] |= USBPCAP_INFO_PDO_TO_FDO;
        } else {
            self.buf[16] &= !USBPCAP_INFO_PDO_TO_FDO;
        }
        self
    }

    /// Set the USB bus number.
    pub fn bus(mut self, v: u16) -> Self {
        self.buf[17..19].copy_from_slice(&v.to_le_bytes());
        self
    }

    /// Set the device address on the bus.
    pub fn device(mut self, v: u16) -> Self {
        self.buf[19..21].copy_from_slice(&v.to_le_bytes());
        self
    }

    /// Set the raw endpoint octet (overrides [`direction`](Self::direction)
    /// and [`endpoint`](Self::endpoint)).
    pub fn endpoint_byte(mut self, v: u8) -> Self {
        self.buf[21] = v;
        self
    }

    /// Set the endpoint direction — `true` for IN (device-to-host).
    pub fn direction(mut self, to_host: bool) -> Self {
        if to_host {
            self.buf[21] |= USBPCAP_ENDPOINT_DIRECTION_IN;
        } else {
            self.buf[21] &= !USBPCAP_ENDPOINT_DIRECTION_IN;
        }
        self
    }

    /// Set the 4-bit endpoint number (values above 15 are rejected).
    pub fn endpoint(mut self, num: u8) -> Result<Self, crate::BuildError> {
        if num > 0x0F {
            return Err(crate::BuildError::InvalidField {
                field: "endpoint",
                reason: "USB endpoint number is a 4-bit value (0-15)",
            });
        }
        self.buf[21] = (self.buf[21] & 0xF0) | num;
        Ok(self)
    }

    /// Set the transfer type (see the `USBPCAP_TRANSFER_*` constants).
    pub fn transfer(mut self, v: u8) -> Self {
        self.buf[22] = v;
        self
    }

    /// Attach extra header fields; the declared `header_length` is extended
    /// to `27 + data.len()`.
    pub fn header_payload(mut self, data: &[u8]) -> Self {
        self.header_payload = Some(data.to_vec());
        self
    }

    /// Attach the USB transfer payload; `data_length` is set accordingly.
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }
}

impl Default for UsbPcapPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder for UsbPcapPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let header_payload = self.header_payload.unwrap_or_default();
        let payload = self.payload.unwrap_or_default();

        let header_len = USBPCAP_HEADER_LEN + header_payload.len();
        let mut packet = Vec::with_capacity(header_len + payload.len());

        let mut buf = self.buf;
        buf[0..2].copy_from_slice(&(header_len as u16).to_le_bytes());
        buf[23..27].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        packet.extend_from_slice(&buf);
        packet.extend_from_slice(&header_payload);
        packet.extend_from_slice(&payload);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known USBPcap sample mirroring libpnet's reference bytes:
    /// bus 60, device 70, endpoint byte 0x8E (IN, ep 14), transfer 80,
    /// payload [90, 100].
    #[test]
    fn parse_known_sample() {
        let data = [
            27, 0, // header length
            0x34, 0x12, 0, 0, 0, 0, 0, 0, // IRP ID = 0x1234
            30, 0, 0, 0, // status = 30
            40, 0, // function = 40
            1, // info: pdo_to_fdo = 1
            60, 0, // bus = 60
            70, 0, // device = 70
            142, // endpoint octet: dir=1, ep=14
            80, // transfer = 80
            2, 0, 0, 0, // data length = 2
            90, 100, // payload
        ];
        let usb = UsbPcapPacket::new(&data).unwrap();
        assert_eq!(usb.header_length(), 27);
        assert_eq!(usb.irp_id(), 0x1234);
        assert_eq!(usb.status(), 30);
        assert_eq!(usb.function(), 40);
        assert!(usb.pdo_to_fdo());
        assert_eq!(usb.info(), 1);
        assert_eq!(usb.bus(), 60);
        assert_eq!(usb.device(), 70);
        assert_eq!(usb.endpoint_byte(), 142);
        assert!(usb.direction());
        assert_eq!(usb.endpoint(), 14);
        assert_eq!(usb.transfer(), 80);
        assert_eq!(usb.data_length(), 2);
        assert!(usb.header_payload().is_empty());
        assert_eq!(usb.payload(), &[90, 100]);
    }

    #[test]
    fn too_short() {
        assert!(UsbPcapPacket::new(&[]).is_none());
        assert!(UsbPcapPacket::new(&[0u8; USBPCAP_HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn builder_roundtrip() {
        let packet = UsbPcapPacketBuilder::new()
            .irp_id(0xFF01_0203_0405_0607)
            .status(0xC000_0004)
            .function(URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER)
            .pdo_to_fdo(true)
            .bus(2)
            .device(9)
            .direction(true)
            .endpoint(3)
            .unwrap()
            .transfer(USBPCAP_TRANSFER_BULK)
            .payload(&[1, 2, 3, 4, 5])
            .build();

        let usb = UsbPcapPacket::new(&packet).unwrap();
        assert_eq!(usb.header_length(), 27);
        assert_eq!(usb.irp_id(), 0xFF01_0203_0405_0607);
        assert_eq!(usb.status(), 0xC000_0004);
        assert_eq!(usb.function(), URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER);
        assert!(usb.pdo_to_fdo());
        assert_eq!(usb.bus(), 2);
        assert_eq!(usb.device(), 9);
        assert!(usb.direction());
        assert_eq!(usb.endpoint(), 3);
        assert_eq!(usb.transfer(), USBPCAP_TRANSFER_BULK);
        assert_eq!(usb.data_length(), 5);
        assert_eq!(usb.payload(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn builder_rejects_oversized_endpoint() {
        assert!(UsbPcapPacketBuilder::new().endpoint(16).is_err());
        assert!(UsbPcapPacketBuilder::new().endpoint(u8::MAX).is_err());
    }

    #[test]
    fn extended_header_length() {
        let packet = UsbPcapPacketBuilder::new()
            .header_payload(&[0xEE])
            .payload(&[0x11])
            .build();

        assert_eq!(packet.len(), 28 + 1);
        let usb = UsbPcapPacket::new(&packet).unwrap();
        assert_eq!(usb.header_length(), 28);
        assert_eq!(usb.header_payload(), &[0xEE]);
        assert_eq!(usb.payload(), &[0x11]);
    }

    #[test]
    fn empty_payload() {
        let packet = UsbPcapPacketBuilder::new().build();
        assert_eq!(packet.len(), USBPCAP_HEADER_LEN);
        let usb = UsbPcapPacket::new(&packet).unwrap();
        assert_eq!(usb.header_length(), 27);
        assert_eq!(usb.data_length(), 0);
        assert!(usb.payload().is_empty());
    }

    #[test]
    fn transfer_constants_match_usbpcap_values() {
        assert_eq!(USBPCAP_TRANSFER_ISOCHRONOUS, 0);
        assert_eq!(USBPCAP_TRANSFER_INTERRUPT, 1);
        assert_eq!(USBPCAP_TRANSFER_CONTROL, 2);
        assert_eq!(USBPCAP_TRANSFER_BULK, 3);
        assert_eq!(USBPCAP_TRANSFER_UNKNOWN, 0xFE);
        assert_eq!(USBPCAP_TRANSFER_INVALID, 0xFF);
    }

    #[test]
    fn debug_format() {
        let packet = UsbPcapPacketBuilder::new().build();
        let usb = UsbPcapPacket::new(&packet).unwrap();
        assert!(alloc::format!("{:?}", usb).contains("UsbPcapPacket"));
    }
}
