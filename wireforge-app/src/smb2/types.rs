#[derive(Debug,Clone,Copy,PartialEq,Eq)]
#[repr(u16)]
pub enum Smb2Command { Negotiate=0,SessionSetup=1,TreeConnect=3,Create=5,Read=8,Write=9,Close=6,Unknown(u16) }
impl From<u16> for Smb2Command {
    fn from(v:u16)->Self{ match v{0=>Self::Negotiate,1=>Self::SessionSetup,3=>Self::TreeConnect,5=>Self::Create,6=>Self::Close,8=>Self::Read,9=>Self::Write,_=>Self::Unknown(v)} }
}
