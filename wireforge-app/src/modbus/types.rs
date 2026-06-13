//! Modbus function code types.

#[derive(Debug, Clone)]
pub enum ModbusFunction<'a> {
    ReadCoils { starting_address: u16, quantity: u16 },
    ReadCoilsResponse { byte_count: u8, coil_status: &'a [u8] },
    ReadDiscreteInputs { starting_address: u16, quantity: u16 },
    ReadDiscreteInputsResponse { byte_count: u8, input_status: &'a [u8] },
    ReadHoldingRegisters { starting_address: u16, quantity: u16 },
    ReadHoldingRegistersResponse { byte_count: u8, registers: Vec<u16> },
    ReadInputRegisters { starting_address: u16, quantity: u16 },
    ReadInputRegistersResponse { byte_count: u8, registers: Vec<u16> },
    WriteSingleCoil { output_address: u16, value: bool },
    WriteSingleRegister { register_address: u16, value: u16 },
    WriteMultipleCoils { starting_address: u16, quantity: u16, byte_count: u8, values: &'a [u8] },
    WriteMultipleRegisters { starting_address: u16, quantity: u16, byte_count: u8, values: &'a [u8] },
    Unknown { function_code: u8, data: &'a [u8] },
}
