
IdtDescriptorGate struct
	DestinationOffsetLow word ?				
	DestinationSelector	 word ?				
	WordCount byte ?			
	SecurityByte byte ?
	DestinationOffsetHigh word ?
IdtDescriptorGate ends

IDTR struct
	Limit word ?
	Base  dword ?
IDTR ends

FindProcAddressByHash proto stdcall :dword, :dword
FindBaseKernelByIDT proto stdcall
FindProcAddressForImportByHash proto stdcall :dword, :dword, :dword