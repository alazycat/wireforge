#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RadiusCode {
    AccessRequest = 1, AccessAccept = 2, AccessReject = 3,
    AccountingRequest = 4, AccountingResponse = 5, AccessChallenge = 11,
    Unknown(u8),
}
impl From<u8> for RadiusCode {
    fn from(v: u8) -> Self { match v { 1=>Self::AccessRequest,2=>Self::AccessAccept,3=>Self::AccessReject,4=>Self::AccountingRequest,5=>Self::AccountingResponse,11=>Self::AccessChallenge,_=>Self::Unknown(v) } }
}
