package main

import (
	"fmt"
	"os"
	"bytes"
	"encoding/binary"
	"unicode"
)

type Rsf struct {
	BasicInfo struct { 
		Title string
		CompanyCode string
		ProductCode string
		ContentType string
		Logo string
	}
	RomFs struct { 
		RootPath string
	//	Reject string
	//	Include string
	//	File string
	}
	TitleInfo struct {
		Platform string
		Category string
		UniqueId uint32
		Version uint8
		ContentsIndex uint8
		Variation uint8
		ChildIndex uint8
		DemoIndex uint8
	//	TargetCategory string
	//	CategoryFlags string
	}
	Option struct {
	//	AllowUnalignedSection bool
	//	MediaFootPadding bool
		EnableCrypt bool
		EnableCompress bool
		FreeProductCode bool
		UseOnSD bool
	}
	AccessControlInfo struct {
		DisableDebug bool
		EnableForceDebug bool
		CanWriteSharedPage bool
		CanUsePrivilegedPriority bool
		CanUseNonAlphabetAndNumber bool
		PermitMainFunctionArgument bool
		CanShareDeviceMemory bool
		UseOtherVariationSaveData bool
		RunnableOnSleep bool
		SpecialMemoryArrange bool
		CanAccessCore2 bool
		UseExtSaveData bool
		EnableL2Cache bool

		IdealProcessor byte
		Priority byte
		MemoryType string
		SystemMode string
		SystemModeExt string
		CpuSpeed string
		CoreVersion uint16
		HandleTableSize  uint32
		SystemSaveDataId1 uint32
		SystemSaveDataId2 uint32
		OtherUserSaveDataId1 uint32
		OtherUserSaveDataId2 uint32
		OtherUserSaveDataId3 uint32
		ExtSaveDataId uint32
		AffinityMask byte
		DescVersion uint8
		ResourceLimitCategory string
		ReleaseKernelMajor uint8
		ReleaseKernelMinor uint8
		MaxCpu uint8

		MemoryMapping []string
		IORegisterMapping []string
		FileSystemAccess uint32 // Bitmask handled by output
		IoAccessControl []string
		InterruptNumbers []uint8
		SystemCallAccess []uint32
		ServiceAccessControl []string
		AccessibleSaveDataIds []uint32
	}
	SystemControlInfo struct {
		AppType string
		StackSize uint32
		RemasterVersion uint16
		JumpId uint64
		SaveDataSize uint64
		Dependency []uint64
	}
}

var category = map[uint16]string {
	0x0000: "Application",
	0x0010: "SystemApplication",
	0x0030: "Applet",
	0x0138: "Firmware",
	0x0130: "Base",
	0x0001: "DlpChild",
	0x0002: "Demo",
	0x0003: "Contents",
	0x001B: "SystemContents",
	0x009B: "SharedContents",
	0x008C: "AddOnContents",
	0x000E: "Patch",
	0x00DB: "AutoUpdateContents",
}

var new3dsSystemMode = map[byte]string {
	0: "Legacy",
	1: "124MB",
	2: "178MB",
	3: "124MB",
}

var old3dsSystemMode = map[byte]string {
	0: "64MB",
	2: "96MB",
	3: "80MB",
	4: "72MB",
	5: "32MB",
}

var filesystemAccessInfo = map[byte]string {
	0: "CategorySystemApplication",
	1: "CategoryHardwareCheck",
	2: "CategoryFileSystemTool",
	3: "Debug",
	4: "TwlCardBackup",
	5: "TwlNandData",
	6: "Boss",
	7: "DirectSdmc",
	8: "Core",
	9: "CtrNandRo",
	10: "CtrNandRw",
	11: "CtrNandRoWrite",
	12: "CategorySystemSettings",
	13: "CardBoard",
	14: "ExportImportIvs",
	15: "DirectSdmcWrite",
	16: "SwitchCleanup",
	17: "SaveDataMove",
	18: "Shop",
	19: "Shell",
	20: "CategoryHomeMenu",
	21: "SeedDB",
}

var resourceLimitCategory = map[byte]string {
	0: "application",
	1: "sysapplet",
	2: "libapplet",
	3: "other",
}

var memoryType = map[byte]string {
	1: "Application",
	2: "System",
	3: "Base",
}

var svcs = []string {
	"",                                  // 00
	"ControlMemory",                     // 01
	"QueryMemory",                       // 02
	"ExitProcess",                       // 03
	"GetProcessAffinityMask",            // 04
	"SetProcessAffinityMask",            // 05
	"GetProcessIdealProcessor",          // 06
	"SetProcessIdealProcessor",          // 07
	"CreateThread",                      // 08
	"ExitThread",                        // 09
	"SleepThread",                       // 0A
	"GetThreadPriority",                 // 0B
	"SetThreadPriority",                 // 0C
	"GetThreadAffinityMask",             // 0D
	"SetThreadAffinityMask",             // 0E
	"GetThreadIdealProcessor",           // 0F
	"SetThreadIdealProcessor",           // 10
	"GetCurrentProcessorNumber",         // 11
	"Run",                               // 12
	"CreateMutex",                       // 13
	"ReleaseMutex",                      // 14
	"CreateSemaphore",                   // 15
	"ReleaseSemaphore",                  // 16
	"CreateEvent",                       // 17
	"SignalEvent",                       // 18
	"ClearEvent",                        // 19
	"CreateTimer",                       // 1A
	"SetTimer",                          // 1B
	"CancelTimer",                       // 1C
	"ClearTimer",                        // 1D
	"CreateMemoryBlock",                 // 1E
	"MapMemoryBlock",                    // 1F
	"UnmapMemoryBlock",                  // 20
	"CreateAddressArbiter",              // 21
	"ArbitrateAddress",                  // 22
	"CloseHandle",                       // 23
	"WaitSynchronization1",              // 24
	"WaitSynchronizationN",              // 25
	"SignalAndWait",                     // 26
	"DuplicateHandle",                   // 27
	"GetSystemTick",                     // 28
	"GetHandleInfo",                     // 29
	"GetSystemInfo",                     // 2A
	"GetProcessInfo",                    // 2B
	"GetThreadInfo",                     // 2C
	"ConnectToPort",                     // 2D
	"SendSyncRequest1",                  // 2E
	"SendSyncRequest2",                  // 2F
	"SendSyncRequest3",                  // 30
	"SendSyncRequest4",                  // 31
	"SendSyncRequest",                   // 32
	"OpenProcess",                       // 33
	"OpenThread",                        // 34
	"GetProcessId",                      // 35
	"GetProcessIdOfThread",              // 36
	"GetThreadId",                       // 37
	"GetResourceLimit",                  // 38
	"GetResourceLimitLimitValues",       // 39
	"GetResourceLimitCurrentValues",     // 3A
	"GetThreadContext",                  // 3B
	"Break",                             // 3C
	"OutputDebugString",                 // 3D
	"ControlPerformanceCounter",         // 3E
	"",                                  // 3F
	"",                                  // 40
	"",                                  // 41
	"",                                  // 42
	"",                                  // 43
	"",                                  // 44
	"",                                  // 45
	"",                                  // 46
	"CreatePort",                        // 47
	"CreateSessionToPort",               // 48
	"CreateSession",                     // 49
	"AcceptSession",                     // 4A
	"ReplyAndReceive1",                  // 4B
	"ReplyAndReceive2",                  // 4C
	"ReplyAndReceive3",                  // 4D
	"ReplyAndReceive4",                  // 4E
	"ReplyAndReceive",                   // 4F
	"BindInterrupt",                     // 50
	"UnbindInterrupt",                   // 51
	"InvalidateProcessDataCache",        // 52
	"StoreProcessDataCache",             // 53
	"FlushProcessDataCache",             // 54
	"StartInterProcessDma",              // 55
	"StopDma",                           // 56
	"GetDmaState",                       // 57
	"RestartDma",                        // 58
	"SetGpuProt",                        // 59
	"SetWifiEnabled",                    // 5A
	"",                                  // 5B
	"",                                  // 5C
	"",                                  // 5D
	"",                                  // 5E
	"",                                  // 5F
	"DebugActiveProcess",                // 60
	"BreakDebugProcess",                 // 61
	"TerminateDebugProcess",             // 62
	"GetProcessDebugEvent",              // 63
	"ContinueDebugEvent",                // 64
	"GetProcessList",                    // 65
	"GetThreadList",                     // 66
	"GetDebugThreadContext",             // 67
	"SetDebugThreadContext",             // 68
	"QueryDebugProcessMemory",           // 69
	"ReadProcessMemory",                 // 6A
	"WriteProcessMemory",                // 6B
	"SetHardwareBreakPoint",             // 6C
	"GetDebugThreadParam",               // 6D
	"",                                  // 6E
	"",                                  // 6F
	"ControlProcessMemory",              // 70
	"MapProcessMemory",                  // 71
	"UnmapProcessMemory",                // 72
	"CreateCodeSet",                     // 73
	"",                                  // 74
	"CreateProcess",                     // 75
	"TerminateProcess",                  // 76
	"SetProcessResourceLimits",          // 77
	"CreateResourceLimit",               // 78
	"SetResourceLimitValues",            // 79
	"AddCodeSegment",                    // 7A
	"Backdoor",                          // 7B
	"KernelSetState",                    // 7C
	"QueryProcessMemory",                // 7D
	"",                                  // 7E
	"",                                  // 7F
}

var dependencies = map[uint64]string {
	0x0004013000002402: "ac",
	0x0004013000003802: "act",
	0x0004013000001502: "am",
	0x0004013000003402: "boss",
	0x0004013000001602: "camera",
	0x0004013000002602: "cecd",
	0x0004013000001702: "cfg",
	0x0004013000001802: "codec",
	0x0004013000002702: "csnd",
	0x0004013000002802: "dlp",
	0x0004013000001a02: "dsp",
	0x0004013000003202: "friends",
	0x0004013000001b02: "gpio",
	0x0004013000001c02: "gsp",
	0x0004013000001d02: "hid",
	0x0004013000002902: "http",
	0x0004013000001e02: "i2c",
	0x0004013000003302: "ir",
	0x0004013000001f02: "mcu",
	0x0004013000002002: "mic",
	0x0004013000002b02: "ndm",
	0x0004013000003502: "news",
	0x0004013000004002: "nfc",
	0x0004013000002c02: "nim",
	0x0004013000002d02: "nwm",
	0x0004013000002102: "pdn",
	0x0004013000003102: "ps",
	0x0004013000002202: "ptm",
	0x0004013020004202: "qtm",
	0x0004013000003702: "ro",
	0x0004013000002e02: "socket",
	0x0004013000002302: "spi",
	0x0004013000002f02: "ssl",
}

func check(err error) {
	if (err != nil) {
		fmt.Println(err)
		os.Exit(1)
	}
}

func parseExheader(rsf *Rsf, exheader []byte) {
	sci := exheader[0:0x200]

	basicInfo := &rsf.BasicInfo
	titleInfo := &rsf.TitleInfo
	option := &rsf.Option
	accessControlInfo := &rsf.AccessControlInfo
	systemControlInfo := &rsf.SystemControlInfo

	basicInfo.Title = string(bytes.Trim(sci[0:8], "\x00"))

	option.EnableCompress = (sci[0xD] & (1 << 0)) != 0
	option.UseOnSD = (sci[0xD] & (1 << 1)) != 0

	systemControlInfo.RemasterVersion = binary.LittleEndian.Uint16(sci[0xE:])

	systemControlInfo.StackSize = binary.LittleEndian.Uint32(sci[0x1C:])

	for i := 0; i < 0x30; i++ {
		tid := binary.LittleEndian.Uint64(sci[0x40 + i * 8:])
		if (tid == 0) {
			break
		}
		systemControlInfo.Dependency = append(systemControlInfo.Dependency, tid)
	}

	systemControlInfo.SaveDataSize = binary.LittleEndian.Uint64(sci[0x1C0:])
	systemControlInfo.JumpId = binary.LittleEndian.Uint64(sci[0x1C8:])
	
	aci := exheader[0x200:0x400]

	tid := binary.LittleEndian.Uint64(aci[0:])
	titleInfo.UniqueId = uint32((tid >> 8) & 0xFFFFFF)
	titleInfo.Category = category[uint16(tid >> 32)]
	switch(titleInfo.Category) {
		case "Demo":
			titleInfo.DemoIndex = uint8(tid)
		case "DlpChild":
			titleInfo.ChildIndex = uint8(tid)
		case "AddOnContents":
			titleInfo.Variation = uint8(tid)
		case "IsContents":
			titleInfo.ContentsIndex = uint8(tid)
	}
	titleInfo.Version = uint8(tid)



	accessControlInfo.CoreVersion = binary.LittleEndian.Uint16(aci[8:])
	
	if ((aci[0xC] & 0b10) != 0) {
		accessControlInfo.CpuSpeed = "804MHz"
	} else {
		accessControlInfo.CpuSpeed = "268MHz"
	}

	accessControlInfo.SystemModeExt = new3dsSystemMode[aci[0xC] & 0b1111]
	
	accessControlInfo.EnableL2Cache = (aci[0xC] & 1) != 0

	accessControlInfo.AffinityMask = aci[0xE] >> 2 & 0b11
	
	accessControlInfo.IdealProcessor = aci[0xE] & 0b11

	accessControlInfo.SystemMode = old3dsSystemMode[(aci[0xE] >> 4) & 0b1111]

	accessControlInfo.Priority = aci[0xF]

	accessControlInfo.MaxCpu = uint8(aci[0x10])

	accessControlInfo.UseOtherVariationSaveData = ((binary.LittleEndian.Uint64(aci[0x40:]) >> 60) & 0x1) != 0

	if !((aci[0x4F] & 1) != 0) { // Not use ROMFS
		rsf.RomFs.RootPath = "assets/romfs"
	}

	if ((aci[0x4F] & 0b10) != 0) { // Use Extended savedata access.
		for i := 2; i >= 0; i-- {
			id := (binary.LittleEndian.Uint64(aci[0x40:]) >> (20 * i)) & 0xFFFFF
			if (id == 0) {
				break
			}
			accessControlInfo.AccessibleSaveDataIds = append(accessControlInfo.AccessibleSaveDataIds, uint32(id))
		}
		for i := 2; i >= 0; i-- {
			id := (binary.LittleEndian.Uint64(aci[0x30:]) >> (20 * i)) & 0xFFFFF
			if (id == 0) {
				break
			}
			accessControlInfo.AccessibleSaveDataIds = append(accessControlInfo.AccessibleSaveDataIds, uint32(id))
		}
	} else {
		if (binary.LittleEndian.Uint64(aci[0x30:]) != 0) {
			accessControlInfo.UseExtSaveData = true
			accessControlInfo.ExtSaveDataId = binary.LittleEndian.Uint32(aci[0x30:])
		}
		for i := 2; i >= 0; i-- {
			value := uint32((binary.LittleEndian.Uint64(aci[0x40:]) >> (i * 20)) & 0xFFFFF)
			if (value != 0) {
				if (accessControlInfo.OtherUserSaveDataId1 == 0) {
					accessControlInfo.OtherUserSaveDataId1 = value
				} else if (accessControlInfo.OtherUserSaveDataId2 == 0) {
					accessControlInfo.OtherUserSaveDataId2 = value
				} else {
					accessControlInfo.OtherUserSaveDataId3 = value
				}
			}
		}
	}

	accessControlInfo.SystemSaveDataId1 = binary.LittleEndian.Uint32(aci[0x38:])
	accessControlInfo.SystemSaveDataId2 = binary.LittleEndian.Uint32(aci[0x3C:])

	accessControlInfo.FileSystemAccess = binary.LittleEndian.Uint32(aci[0x48:])

	for i := 0; i < 34; i++ {
		serviceName := string(bytes.Trim(aci[0x50 + i * 8:0x58 + i * 8], "\x00"))
		if (serviceName == "") {
			break
		}
		accessControlInfo.ServiceAccessControl = append(accessControlInfo.ServiceAccessControl, serviceName)
	}

	accessControlInfo.ResourceLimitCategory = resourceLimitCategory[aci[0x16F]]
	if (accessControlInfo.ResourceLimitCategory == "application") {
		accessControlInfo.Priority -= 32
		systemControlInfo.AppType = "application"
	} else {
		systemControlInfo.AppType = "system"
	}

	arm11KernelCapabilities := aci[0x170:]
	for i := 0; i < 28; i++ {
		descriptor := binary.LittleEndian.Uint32(arm11KernelCapabilities[i * 4:])
		var descriptorType uint32
		for j := 31; j >= 0; j-- {
			k := descriptor & (1 << j)
			if (k == 0) {
				break
			}
			descriptorType |= k
		}

		switch (descriptorType) {
			case 0xE0000000: // Interrupt
				for j := 3; j >= 0; j-- {
					interrupt := (descriptor >> (j * 7)) & 0b1111111
					if (interrupt != 0) {
						accessControlInfo.InterruptNumbers = append(accessControlInfo.InterruptNumbers, uint8(interrupt))
					}
				}
			case 0xF0000000: // System Call Access
				index := (descriptor >> 24) & 0b111
				for j := 0; j < 24; j++ {
					if ((descriptor >> j) & 1 != 0) {
						accessControlInfo.SystemCallAccess = append(accessControlInfo.SystemCallAccess, uint32(j) + 24 * index)
					}
				}
 			case 0xFC000000: // Kernel Version
				accessControlInfo.ReleaseKernelMajor = uint8((descriptor >> 8) & 0xFF)
				accessControlInfo.ReleaseKernelMinor = uint8(descriptor & 0xFF )
			case 0xFE000000: // Handle Table Size
				accessControlInfo.HandleTableSize = descriptor & 0x7FFFF
			case 0xFF000000: // Other Capabilities
				accessControlInfo.DisableDebug = !((descriptor & (1 << 0)) != 0)
				accessControlInfo.EnableForceDebug = ((descriptor & (1 << 1)) != 0)
				accessControlInfo.CanUseNonAlphabetAndNumber = ((descriptor & (1 << 2)) != 0)
				accessControlInfo.CanWriteSharedPage = ((descriptor & (1 << 3)) != 0)
				accessControlInfo.CanUsePrivilegedPriority = ((descriptor & (1 << 4)) != 0)
				accessControlInfo.PermitMainFunctionArgument = ((descriptor & (1 << 5)) != 0)
				accessControlInfo.CanShareDeviceMemory = ((descriptor & (1 << 6)) != 0)
				accessControlInfo.RunnableOnSleep = ((descriptor & (1 << 7)) != 0)
				accessControlInfo.MemoryType = memoryType[byte((descriptor >> 8) & 0b1111)]
				accessControlInfo.SpecialMemoryArrange = ((descriptor & (1 << 12)) != 0)
				accessControlInfo.CanAccessCore2 = ((descriptor & (1 << 13)) != 0)
			case 0xFF800000: // Memory Mapping
				start := descriptor & 0xFFFFF
				i += 1
				end := binary.LittleEndian.Uint32(arm11KernelCapabilities[i * 4:])
				staticMap := (end & (1 << 20)) != 0 
				end &= 0xFFFFF
				start <<= 12
				end <<= 12
				end -= 0x1

				if (staticMap) { // MemoryMapping
					if ((descriptor & (1 << 20)) != 0) { // :r
						accessControlInfo.MemoryMapping = append(accessControlInfo.MemoryMapping, fmt.Sprintf("%x-%x:r", start, end))
					} else {
						accessControlInfo.MemoryMapping = append(accessControlInfo.MemoryMapping, fmt.Sprintf("%x-%x", start, end))
					}
				} else { // IORegisterMapping
					accessControlInfo.IORegisterMapping = append(accessControlInfo.IORegisterMapping, fmt.Sprintf("%x-%x", start, end))
				}
			case 0xFFC00000:
		}
	}
 
	arm9AccessControl := aci[0x1F0:]

	descriptors := binary.LittleEndian.Uint32(arm9AccessControl)

	if ((descriptors & (1 << 0)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "FsMountNand")
	}
	if ((descriptors & (1 << 1)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "FsMountNandRoWrite")
	}
	if ((descriptors & (1 << 2)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "FsMountTwln")
	}
	if ((descriptors & (1 << 3)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "FsMountWnand")
	}
	if ((descriptors & (1 << 4)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "FsMountCardSpi")
	}
	if ((descriptors & (1 << 5)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "UseSdif3")
	}
	if ((descriptors & (1 << 6)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "CreateSeed")
	}
	if ((descriptors & (1 << 7)) != 0) {
		accessControlInfo.IoAccessControl = append(accessControlInfo.IoAccessControl, "UseCardSpi")
	}
	if ((descriptors & (1 << 8)) != 0) {
		option.UseOnSD = true;
	}

	accessControlInfo.DescVersion = arm9AccessControl[0xF]
}

func parseNcchHeader(rsf *Rsf, header []byte) {
	basicInfo := &rsf.BasicInfo
	titleInfo := &rsf.TitleInfo
	option := &rsf.Option

	option.EnableCrypt = !((header[0x18F] & 4) != 0)

	option.FreeProductCode = false
	productCode := header[0x150:0x160]
	basicInfo.ProductCode = string(bytes.Trim(productCode, "\x00"))
	if (string(productCode[0:3]) != "CTR" && string(productCode[0:3]) != "KTR") {
		option.FreeProductCode = true
	} else {
		for i := 3; i < 10; i++ {
			if (i == 3 || i == 5) {
				if (rune(productCode[i]) != '-') {
					option.FreeProductCode = true
					break
				}
			} else {
				if (!unicode.IsDigit(rune(productCode[i])) && !unicode.IsLetter(rune(productCode[i]))) {
					option.FreeProductCode = true
					break
				}
			}
		}
	}

	basicInfo.CompanyCode = string(header[0x110:0x112])

	if (header[0x18C] == 1) {
		titleInfo.Platform = "CTR"
	} else if (header[0x18C] == 2) {
		titleInfo.Platform = "snake"
	}

	switch(header[0x18D] >> 2) {
		case 0:
			basicInfo.ContentType = "Application"
		case 1:
			basicInfo.ContentType = "SystemUpdate"
		case 2:
			basicInfo.ContentType = "Manual"
		case 3:
			basicInfo.ContentType = "Child"
		case 4:
			basicInfo.ContentType = "Trial"
		case 5:
			basicInfo.ContentType = "ExtendedSystemUpdate"
	}

	if (binary.LittleEndian.Uint32(header[0x19c:]) != 0) { // Could probably check hash to determine actual logo, but I don't want to.
		basicInfo.Logo = "Homebrew"
	} else {
		basicInfo.Logo = "None"
	}
}

type OutFile struct {
	*os.File
}

func (out *OutFile) WriteTitle(title string, level int) {
	for i := 0; i < level; i++ {
		out.WriteString("  ")
	}
	out.WriteString(title + ":\n")
}

func (out *OutFile) WriteInfo(title string, value string, level int) {
	for i := 0; i < level; i++ {
		out.WriteString("  ")
	}
	out.WriteString(title + " : " + value + "\n")
}

func (out *OutFile) WriteItem(value string, level int) {
	for i := 0; i < level; i++ {
		out.WriteString("  ")
	}
	out.WriteString(" - " + value + "\n")
}

func quotes(in string)(out string) {
	out = fmt.Sprintf("\"%s\"", in)
	return
}

func hex(in interface{})(out string) {
	out = fmt.Sprintf("0x%x", in)
	return
}

func hexFill(in interface{}, length int)(out string) {
	out = fmt.Sprintf("0x%0*x", length, in)
	return
}

func dec(in interface{})(out string) {
	out = fmt.Sprintf("%d", in)
	return
}

func truth(in bool)(out string) {
	if (in) {
		out = "true"
	} else {
		out = "false"
	}
	return
}

func output(rsf *Rsf, out *OutFile) {
	var comment string

	basicInfo := &rsf.BasicInfo
	romFs := &rsf.RomFs
	titleInfo := &rsf.TitleInfo
	option := &rsf.Option
	accessControlInfo := &rsf.AccessControlInfo
	systemControlInfo := &rsf.SystemControlInfo

	out.WriteTitle("BasicInfo", 0)
	out.WriteInfo("Title", quotes(basicInfo.Title), 1)
	out.WriteInfo("CompanyCode", quotes(basicInfo.CompanyCode), 1)
	out.WriteInfo("ProductCode", quotes(basicInfo.ProductCode), 1)
	out.WriteInfo("ContentType", quotes(basicInfo.ContentType), 1)
	comment = " # Nintendo / Licensed / Distributed / iQue / iQueForSystem"
	out.WriteInfo("Logo", basicInfo.Logo + comment, 1)

	out.WriteString("\n")

	out.WriteTitle("RomFs", 0)
	rootPathString := "RootPath"
	if (romFs.RootPath == "") {
		rootPathString = "#" + rootPathString
	}
	out.WriteInfo(rootPathString, romFs.RootPath, 1)

	out.WriteString("\n")

	out.WriteTitle("TitleInfo", 0)
	out.WriteInfo("Platform", titleInfo.Platform, 1)
	out.WriteInfo("Category", titleInfo.Category, 1)
	out.WriteInfo("UniqueId", hexFill(titleInfo.UniqueId, 6), 1)
	if (titleInfo.ContentsIndex != 0) {
		out.WriteInfo("ContentsIndex", hexFill(titleInfo.ContentsIndex, 2), 1)
	} else if (titleInfo.Variation != 0) {
		out.WriteInfo("Variation", hexFill(titleInfo.Variation, 2), 1)
	} else if (titleInfo.ChildIndex != 0) {
		out.WriteInfo("ChildIndex", hexFill(titleInfo.ChildIndex, 2), 1)
	} else if (titleInfo.DemoIndex != 0) {
		out.WriteInfo("DemoIndex", hexFill(titleInfo.DemoIndex, 2), 1)
	} else {
		out.WriteInfo("Version", hexFill(titleInfo.Version, 2), 1)
	}

	out.WriteString("\n")

	out.WriteTitle("Option", 0)
	out.WriteInfo("EnableCrypt", truth(option.EnableCrypt), 1)
	out.WriteInfo("EnableCompress", truth(option.EnableCompress), 1)
	out.WriteInfo("FreeProductCode", truth(option.FreeProductCode), 1)
	out.WriteInfo("UseOnSD", truth(option.UseOnSD), 1)

	out.WriteString("\n")

	out.WriteTitle("AccessControlInfo", 0)
	out.WriteInfo("CoreVersion", dec(accessControlInfo.CoreVersion), 1)

	out.WriteString("\n")

	out.WriteString("  # Exheader Format Version\n")
	out.WriteInfo("DescVersion", dec(accessControlInfo.DescVersion), 1)

	out.WriteString("\n")

	out.WriteString("  # Minimum Required Kernel Version\n")
	out.WriteInfo("ReleaseKernelMajor", quotes(dec(accessControlInfo.ReleaseKernelMajor)), 1)
	out.WriteInfo("ReleaseKernelMinor", quotes(dec(accessControlInfo.ReleaseKernelMinor)), 1)

	out.WriteString("\n")

	out.WriteString("  # ExtData\n")
	out.WriteInfo("UseExtSaveData", truth(accessControlInfo.UseExtSaveData), 1)
	str := "ExtSaveDataId"
	if (!accessControlInfo.UseExtSaveData) {
		str = "#" + str
	}
	out.WriteInfo(str, hex(accessControlInfo.ExtSaveDataId), 1)

	out.WriteString("\n")

	newline := false
	if (accessControlInfo.SystemSaveDataId1 != 0) {
		newline = true
		out.WriteInfo("SystemSaveDataId1", hex(accessControlInfo.SystemSaveDataId1), 1)
		if (accessControlInfo.SystemSaveDataId2 != 0) {
			out.WriteInfo("SystemSaveDataId2", hex(accessControlInfo.SystemSaveDataId2), 1)
		}
	}
	if (accessControlInfo.OtherUserSaveDataId1 != 0) {
		newline = true
		out.WriteInfo("OtherUserSaveDataId1", hex(accessControlInfo.OtherUserSaveDataId1), 1)
		if (accessControlInfo.OtherUserSaveDataId2 != 0) {
			out.WriteInfo("OtherUserSaveDataId2", hex(accessControlInfo.OtherUserSaveDataId2), 1)
			if (accessControlInfo.OtherUserSaveDataId3 != 0) {
				out.WriteInfo("OtherUserSaveDataId3", hex(accessControlInfo.OtherUserSaveDataId3), 1)
			}
		}
	}
	if (len(accessControlInfo.AccessibleSaveDataIds) > 0) {
		out.WriteTitle("AccessibleSaveDataIds", 1)
		newline = true
		for i := 0; i < len(accessControlInfo.AccessibleSaveDataIds); i++ {
			out.WriteItem(hex(accessControlInfo.AccessibleSaveDataIds[i]), 2)
		}
	}


	if (newline) {
		out.WriteString("\n")
	}
		
	out.WriteString("  # FS:USER Archive Access Permissions\n")
	out.WriteString("  # Uncomment as required\n")
	out.WriteTitle("FileSystemAccess", 1)
	for i := 0; i <= 21; i++ {
		if ((accessControlInfo.FileSystemAccess & (1 << i)) == 0) {
			out.WriteString("#")
		}
		out.WriteItem(filesystemAccessInfo[byte(i)], 2)

	}
	
	out.WriteString("\n")

	if (len(accessControlInfo.IoAccessControl) > 0) {
		out.WriteTitle("IoAccessControl", 1)
		for i := 0; i < len(accessControlInfo.IoAccessControl); i++ {
			out.WriteItem(accessControlInfo.IoAccessControl[i], 2)
		}
		out.WriteString("\n")
	}

	out.WriteString("  # Process Settings\n")
	comment = " # Application/System/Base"
	out.WriteInfo("MemoryType", accessControlInfo.MemoryType + comment, 1)
	comment = " # Application/Sysapplet/Libapplet/Other"
	out.WriteInfo("ResourceLimitCategory", accessControlInfo.ResourceLimitCategory, 1)
	comment = " # 64MB(Default)/96MB/80MB/72MB/32MB"
	out.WriteInfo("SystemMode", accessControlInfo.SystemMode + comment, 1)
	out.WriteInfo("IdealProcessor", dec(accessControlInfo.IdealProcessor), 1)
	out.WriteInfo("AffinityMask", dec(accessControlInfo.AffinityMask), 1)
	out.WriteInfo("Priority", dec(accessControlInfo.Priority), 1)
	out.WriteInfo("MaxCpu", hex(accessControlInfo.MaxCpu), 1)
	out.WriteInfo("HandleTableSize", hex(accessControlInfo.HandleTableSize), 1)

	out.WriteInfo("DisableDebug", truth(accessControlInfo.DisableDebug), 1)
	out.WriteInfo("EnableForceDebug", truth(accessControlInfo.EnableForceDebug), 1)
	out.WriteInfo("CanWriteSharedPage", truth(accessControlInfo.CanWriteSharedPage), 1)
	out.WriteInfo("CanUsePrivilegedPriority", truth(accessControlInfo.CanUsePrivilegedPriority), 1)
	out.WriteInfo("CanUseNonAlphabetAndNumber", truth(accessControlInfo.CanUseNonAlphabetAndNumber), 1)
	out.WriteInfo("PermitMainFunctionArgument", truth(accessControlInfo.PermitMainFunctionArgument), 1)
	out.WriteInfo("CanShareDeviceMemory", truth(accessControlInfo.CanShareDeviceMemory), 1)
	out.WriteInfo("UseOtherVariationSaveData", truth(accessControlInfo.UseOtherVariationSaveData), 1)
	out.WriteInfo("RunnableOnSleep", truth(accessControlInfo.RunnableOnSleep), 1)
	out.WriteInfo("SpecialMemoryArrange", truth(accessControlInfo.SpecialMemoryArrange), 1)

	out.WriteString("\n")

	comment = " # Legacy(Default)/124MB/178MB  Legacy:Use Old3DS SystemMode"
	out.WriteInfo("SystemModeExt", accessControlInfo.SystemModeExt + comment, 1)
	comment = " # 256MHz(Default)/804MHz"
	out.WriteInfo("CpuSpeed", accessControlInfo.CpuSpeed + comment, 1)
	comment = " # false(default)/true"
	out.WriteInfo("EnableL2Cache", truth(accessControlInfo.EnableL2Cache) + comment, 1)
	out.WriteInfo("CanAccessCore2", truth(accessControlInfo.CanAccessCore2), 1)

	out.WriteString("\n")

	out.WriteTitle("IORegisterMapping", 1)
	for i := 0; i < len(accessControlInfo.IORegisterMapping); i++ {
		out.WriteItem(accessControlInfo.IORegisterMapping[i], 2)
	}
	out.WriteTitle("MemoryMapping", 1)
	for i := 0; i < len(accessControlInfo.MemoryMapping); i++ {
		out.WriteItem(accessControlInfo.MemoryMapping[i], 2)
	}

	out.WriteString("\n")

	out.WriteString("  # Accessible SVCs, <Name>:<ID>\n")
	out.WriteTitle("SystemCallAccess", 1)
	for i := 0; i < len(accessControlInfo.SystemCallAccess); i++ {
		id := accessControlInfo.SystemCallAccess[i]
		if (svcs[id] != "") {
			out.WriteString("    " + svcs[id] + ": " + dec(id) + "\n")
		}
	}
	
	out.WriteString("\n")

	if (len(accessControlInfo.InterruptNumbers) > 0) {
		out.WriteTitle("InterruptNumbers", 1)
		for i := 0; i < len(accessControlInfo.InterruptNumbers); i++ {
			out.WriteItem(hexFill(accessControlInfo.InterruptNumbers, 2), 2)
		}
		out.WriteString("\n")
	}

	out.WriteString("  # Service List\n")
	out.WriteString("  # Maximum 34 services (32 if firmware is prior to 9.6.0)\n")
	out.WriteTitle("ServiceAccessControl", 1)
	for i := 0; i < len(accessControlInfo.ServiceAccessControl); i++ {
		out.WriteItem(accessControlInfo.ServiceAccessControl[i], 2)
	}

	out.WriteString("\n")

	out.WriteTitle("SystemControlInfo", 0)
	out.WriteInfo("AppType", systemControlInfo.AppType, 1)
	out.WriteInfo("StackSize", hex(systemControlInfo.StackSize), 1)
	out.WriteInfo("RemasterVersion", hex(systemControlInfo.RemasterVersion), 1)
	out.WriteInfo("JumpId", hexFill(systemControlInfo.JumpId, 6), 1)
	out.WriteInfo("SaveDataSize", dec(systemControlInfo.SaveDataSize) + "KB", 1)

	out.WriteString("\n")

	out.WriteString("  # Modules that run services listed above should be included below\n")
	out.WriteString("  # Maximum 48 dependencies\n")
	out.WriteString("  # <module name>:<module titleid>\n")
	out.WriteTitle("Dependency", 1)
	for i := 0; i < len(systemControlInfo.Dependency); i++ {
		id := systemControlInfo.Dependency[i]
		out.WriteString("    " + dependencies[id] + ": " + hex(id) + "\n")
	}
}

func main() {
	in, err := os.Open(os.Args[1])
	check(err)
	cxi := make([]byte, 0x600)
	n, err := in.Read(cxi)
	check(err)
	in.Close()

	if (n != 0x600) {
		fmt.Println("Invalid .cxi file.")
		os.Exit(1)
	}

	file, err := os.Create(os.Args[2])
	check(err)

	rsf := Rsf{}
	
	parseExheader(&rsf, cxi[0x200:])
	
	parseNcchHeader(&rsf, cxi[0:])

	output(&rsf, &OutFile{file})

	file.Close()

	check(err)
}
