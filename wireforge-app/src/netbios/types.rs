#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum NetbiosNameType { NB, NBSTAT, Unknown(u16) }
impl From<u16> for NetbiosNameType {
    fn from(v:u16)->Self { match v { 0x0020=>Self::NB, 0x0021=>Self::NBSTAT, _=>Self::Unknown(v) } }
}
