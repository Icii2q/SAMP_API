; #######################################################################################################
; # Memory Functions:                                                                                   #
; # --------------------------------------------------------------------------------------------------- #
; #######################################################################################################

global datatypes := {"Int64" : 8, "Double" : 8, "UInt" : 4, "Int" : 4, "Float" : 4, "Ptr" : 4, "UPtr" : 4, "UShort" : 2, "Short" : 2, "Char" : 1, "UChar" : 1, "Byte" : 1}

getPID(windowName) {
	WinGet, processID, PID, %windowName%
	return processID
}

openProcess(processID, privileges := 0x1F0FFF) {
	return DllCall("OpenProcess", "UInt", privileges, "UInt", 0, "UInt", processID, "UInt")
}

closeProcess(process) {
	return !process ? false : DllCall("CloseHandle", "UInt", process, "UInt")
}

getModuleBaseAddress(sModule, hProcess) {
	if (!sModule || !hProcess)
		return false
	
	dwSize = 4096
	VarSetCapacity(hMods, dwSize)
	VarSetCapacity(cbNeeded, 4)
	dwRet := DllCall("Psapi.dll\EnumProcessModules", "UInt", hProcess, "UInt", &hMods, "UInt", dwSize, "UInt*", cbNeeded, "UInt")
	if (!dwRet)
		return false
	
	dwMods := cbNeeded / 4
	i := 0
	VarSetCapacity(hModule, 4)
	dwNameSize := 260 * (A_IsUnicode ? 2 : 1)
	VarSetCapacity(sCurModule, dwNameSize)
	while (i < dwMods) {
		hModule := NumGet(hMods, i * 4)
		DllCall("Psapi.dll\GetModuleFileNameEx", "UInt", hProcess, "UInt", hModule, "Str", sCurModule, "UInt", dwNameSize)
		SplitPath, sCurModule, sFilename
		if (sModule == sFilename)
			return hModule

		i += 1
	}
	
	return false
}

__READSTRING(hProcess, dwAddress, oOffsets, dwLen) {
	if (!hProcess || !dwAddress)
		return ""

	VarSetCapacity(dwRead, dwLen)
	for i, o in oOffsets {
		if (i == oOffsets.MaxIndex()) {
			dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", dwRead, "UInt", dwLen, "UInt*", 0, "UInt")
			return !dwRet ? "" : (A_IsUnicode ? __ansiToUnicode(dwRead) : dwRead)
		}

		dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", dwRead, "UInt", 4, "UInt*", 0)
		if (!dwRet)
			return ""

		dwAddress := NumGet(dwRead, 0, "UInt")
	}
}

__DWORD(hProcess, dwAddress, offsets) {
	if (!hProcess || !dwAddress)
		return ""

	VarSetCapacity(dwRead, 4)
	for i, o in offsets {
		dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", dwRead, "UInt", 4, "UInt*", 0)
		if (!dwRet)
			return ""

		dwAddress := NumGet(dwRead, 0, "UInt")
	}

	return dwAddress
}

readDWORD(hProcess, dwAddress) {
	if(!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(dwRead, 4)    ; DWORD = 4
	dwRet := DllCall(    "ReadProcessMemory"
						, "UInt",  hProcess
						, "UInt",  dwAddress
						, "Str",   dwRead
						, "UInt",  4
						, "UInt*", 0)
	if(dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return NumGet(dwRead, 0, "UInt")
}


readMem(hProcess, dwAddress, dwLen=4, type="UInt") {
	if(!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(dwRead, dwLen)
	dwRet := DllCall(    "ReadProcessMemory"
						, "UInt",  hProcess
						, "UInt",  dwAddress
						, "Str",   dwRead
						, "UInt",  dwLen
						, "UInt*", 0)
	if(dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return NumGet(dwRead, 0, type)
}

__READMEM(hProcess, dwAddress, oOffsets, sDatatype = "Int") {
	if (!hProcess || !dwAddress)
		return ""

	VarSetCapacity(dwRead, 4)
	for i, o in oOffsets {
		dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", dwRead, "UInt", 4, "UInt*", 0)
		if (!dwRet)
			return ""

		if (i == oOffsets.MaxIndex())
			return NumGet(dwRead, 0, sDatatype)

		dwAddress := NumGet(dwRead, 0, "UInt")
	}
}

__WRITESTRING(hProcess, dwAddress, oOffsets, wString) {
	if (!hProcess || !dwAddress)
		return false
	
	if A_IsUnicode
		wString := __unicodeToAnsi(wString)

	requiredSize := StrPut(wString)
	VarSetCapacity(buffer, requiredSize)
	for i, o in oOffsets {
		if (i == oOffsets.MaxIndex()) {
			StrPut(wString, &buffer, StrLen(wString) + 1)
			return DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", buffer, "UInt", requiredSize, "UInt", 0, "UInt")
		}

		dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", buffer, "UInt", 4, "UInt*", 0)
		if (!dwRet)
			return false

		dwAddress := NumGet(buffer, 0, "UInt")
	}
}

__WRITEMEM(hProcess, dwAddress, oOffsets, value, sDatatype = "Int") {
	dwLen := datatypes[sDatatype]
	if (dwLen < 1 || !hProcess || !dwAddress)
		return false

	VarSetCapacity(dwRead, 4)
	for i, o in oOffsets {
		if (i == oOffsets.MaxIndex()) {
			NumPut(value, dwRead, 0, sDatatype)
			return DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "UInt", &dwRead, "UInt", dwLen, "UInt", 0) 
		}

		dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress + o, "Str", dwRead, "UInt", 4, "UInt*", 0)
		if (!dwRet)
			return false

		dwAddress := NumGet(dwRead, 0, "UInt")
	}
}

__WRITERAW(hProcess, dwAddress, pBuffer, dwLen) {
	return (!hProcess || !dwAddress || !pBuffer || dwLen < 1) ? false : DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress, "UInt", pBuffer, "UInt", dwLen, "UInt", 0, "UInt")
}

__CALL(hProcess, dwFunc, aParams, bCleanupStack = true, bThisCall = false, bReturn = false, sDatatype = "Char") {
	if (!hProcess || !dwFunc)
		return ""

	dataOffset := 0
	i := aParams.MaxIndex()
	bytesUsed := 0
	bytesMax := 5120
	dwLen := i * 5 + bCleanupStack * 3 + bReturn * 5 + 6
	VarSetCapacity(injectData, dwLen, 0)

	while (i > 0) {
		if (aParams[i][1] == "i" || aParams[i][1] == "p" || aParams[i][1] == "f")
			value := aParams[i][2]
		else if (aParams[i][1] == "s") {
			if (bytesMax - bytesUsed < StrLen(aParams[i][2]))
				return ""

			value := pMemory + bytesUsed
			__WRITESTRING(hProcess, value, [0x0], aParams[i][2])

			bytesUsed += StrLen(aParams[i][2]) + 1
			if (ErrorLevel)
				return ""
		}
		else
			return ""

		NumPut((bThisCall && i == 1 ? 0xB9 : 0x68), injectData, dataOffset, "UChar")
		NumPut(value, injectData, ++dataOffset, aParams[i][1] == "f" ? "Float" : "Int")
		dataOffset += 4
		i--
	}

	offset := dwFunc - (pInjectFunc + dataOffset + 5)
	NumPut(0xE8, injectData, dataOffset, "UChar")
	NumPut(offset, injectData, ++dataOffset, "Int")
	dataOffset += 4
	if (bReturn) {
		NumPut(sDatatype = "Char" || sDatatype = "UChar" ? 0xA2 : 0xA3, injectData, dataOffset, "UChar")
		NumPut(pMemory, injectData, ++dataOffset, "UInt")
		dataOffset += 4 
	}
	if (bCleanupStack) {
		NumPut(0xC483, injectData, dataOffset, "UShort")
		dataOffset += 2
		NumPut((aParams.MaxIndex() - bThisCall) * 4, injectData, dataOffset, "UChar")
		dataOffset++
	}
	NumPut(0xC3, injectData, dataOffset, "UChar")

	__WRITERAW(hGTA, pInjectFunc, &injectData, dwLen)
	if (ErrorLevel)
		return ""

	hThread := createRemoteThread(hGTA, 0, 0, pInjectFunc, 0, 0, 0)
	if (ErrorLevel)
		return ""

	waitForSingleObject(hThread, 0xFFFFFFFF)
	closeProcess(hThread)
	if (bReturn)
		return __READMEM(hGTA, pMemory, [0x0], sDatatype)

	return true
}

virtualAllocEx(hProcess, dwSize, flAllocationType, flProtect) {
	return (!hProcess || !dwSize) ? false : DllCall("VirtualAllocEx", "UInt", hProcess, "UInt", 0, "UInt", dwSize, "UInt", flAllocationType, "UInt", flProtect, "UInt")
}

virtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType) {
	return (!hProcess || !lpAddress || !dwSize) ? false : DllCall("VirtualFreeEx", "UInt", hProcess, "UInt", lpAddress, "UInt", dwSize, "UInt", dwFreeType, "UInt")
}

createRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) {
	return (!hProcess) ? false : DllCall("CreateRemoteThread", "UInt", hProcess, "UInt", lpThreadAttributes, "UInt", dwStackSize, "UInt", lpStartAddress, "UInt"
		, lpParameter, "UInt", dwCreationFlags, "UInt", lpThreadId, "UInt")
}

waitForSingleObject(hThread, dwMilliseconds) {
	return !hThread ? false : !(DllCall("WaitForSingleObject", "UInt", hThread, "UInt", dwMilliseconds, "UInt") == 0xFFFFFFFF)
}

__ansiToUnicode(sString, nLen = 0) {
	if (!nLen)
		nLen := DllCall("MultiByteToWideChar", "UInt", 0, "UInt", 0, "UInt", &sString, "Int",  -1, "UInt", 0, "Int",  0)

	VarSetCapacity(wString, nLen * 2)
	DllCall("MultiByteToWideChar", "UInt", 0, "UInt", 0, "UInt", &sString, "Int",  -1, "UInt", &wString, "Int",  nLen)

	return wString
}

__ansiToGTA(sString) {
	VarSetCapacity(newString, (len := StrLen(sString)))
	Loop, % len
	{
		char := NumGet(sString, A_Index - 1, "UChar")
		msgbox % char
		NumPut((char == 252 ? 168 : char), &newString, A_Index - 1, "UChar")
		StringTrimLeft, sString, sString, 1
	}

	return newString
}

__unicodeToAnsi(wString, nLen = 0) {
	pString := wString + 1 > 65536 ? wString : &wString

	if (!nLen)
		nLen := DllCall("WideCharToMultiByte", "UInt", 0, "UInt", 0, "UInt", pString, "Int",  -1, "UInt", 0, "Int",  0, "UInt", 0, "UInt", 0)

	VarSetCapacity(sString, nLen)
	DllCall("WideCharToMultiByte", "UInt", 0, "UInt", 0, "UInt", pString, "Int",  -1, "Str",  sString, "Int",  nLen, "UInt", 0, "UInt", 0)

	return sString
}

IntToHex(value, prefix := true) {
	CurrentFormat := A_FormatInteger
	SetFormat, Integer, hex
	value += 0
	SetFormat, Integer, %CurrentFormat%
	Int2 := SubStr(value, 3)
	StringUpper value, Int2
	return (prefix ? "0x" : "") . value
}

NOP(hProcess, dwAddress, dwLen) {
	if (dwLen < 1 || !hProcess || !dwAddress)
		return false

	VarSetCapacity(byteCode, dwLen)
	Loop % dwLen
		NumPut(0x90, &byteCode, A_Index - 1, "UChar")
	
	return __WRITERAW(hProcess, dwAddress, &byteCode, dwLen)
}

__WRITEBYTES(hProcess, dwAddress, byteArray) {
	if (!hProcess || !dwAddress || !byteArray)
		return false

	dwLen := byteArray.MaxIndex()
	VarSetCapacity(byteCode, dwLen)
	for i, o in byteArray
		NumPut(o, &byteCode, i - 1, "UChar")
	
	return __WRITERAW(hProcess, dwAddress, &byteCode, dwLen)
}

__READBYTE(hProcess, dwAddress) {
	if (!checkHandles())
		return false

	VarSetCapacity(value, 1, 0)
	DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", value, "UInt", 1, "UInt *", 0)
	return NumGet(value, 0, "Byte")
}

increaseValue(dwAddress, value, sDatatype := "UInt") {
	return !checkHandles() ? false : __WRITEMEM(hGTA, dwAddress, [0x0], __READMEM(hGTA, dwAddress, [0x0], sDatatype) + value, sDatatype)
}

isInteger(arg) {
	if arg is integer
		return true

	return false
}

isFloat(arg) {
	if arg is float
		return true

	return false
}

fileCountLines(path) {
	FileRead, text, % path
	StringReplace, text, text, `r, `n, All UseErrorLevel
	return ErrorLevel + 1
}

evaluateString(string) {
	static sc := ComObjCreate("ScriptControl")
	sc.Language := "JScript"
	string := "a = " string ";"
	try {
		sc.ExecuteStatement(string)
		new := sc.Eval("a")
	}
	catch e
		return "ERROR"
		
	return new
}

getByteSize(number) {
	return number <= 0xFF ? 1 : number <= 0xFFFF ? 2 : 4
}

__INJECT(hProcess, aInstructions) {
	aOpcodes := { "mov edi" : 0x3D8B, "NOP" : 0x90, "mov ecx" : 0xB9, "mov dword" : 0x05C7, "push" : 0x68, "call" : 0xE8, "mov byte" : 0x05C6
				, "ret" : 0xC3, "add esp" : 0xC483, "xor edi, edi" : 0xFF33, "xor eax, eax" : 0xC033, "mov edi, eax" : 0xF88B, "push edi" : 0x57, "push eax" : 0x50
				, "mov address, eax" : 0xA3, "mov [address], eax" : 0x0589, "test eax, eax" : 0xC085, "jz" : 0x74, "mov ecx, eax" : 0xC88B, "jmp" : 0xEB
				, "mov edx" : 0xBA, "fstp" : 0x1DD9}

	dwLen := 0
	for i, o in aInstructions
		dwLen += getByteSize(aOpcodes[o[1]]) + ((datatypes[o[2][2]] == null) ? 0 : datatypes[o[2][2]]) + ((datatypes[o[3][2]] == null ? 0 : datatypes[o[3][2]]))

	VarSetCapacity(injectData, dwLen, 0)
	dwDataOffset := 0

	for i, o in aInstructions {
		NumPut(aOpcodes[o[1]], injectData, dwDataOffset, getByteSize(aOpcodes[o[1]]) == 1 ? "UChar" : "UShort")
		dwDataOffset += getByteSize(aOpcodes[o[1]])

		if (o[2][1] != null) {
			NumPut(o[2][1] - (o[1] = "call" ? (pInjectFunc + 4 + dwDataOffset) : 0), injectData, dwDataOffset, o[2][2])
			dwDataOffset += datatypes[o[2][2]]
		}
		else
			continue

		if (o[3][1] != null) {
			NumPut(o[3][1], injectData, dwDataOffset, o[3][2])
			dwDataOffset += datatypes[o[3][2]]
		}
	}

	__WRITERAW(hGTA, pInjectFunc, &injectData, dwLen)

	hThread := createRemoteThread(hGTA, 0, 0, pInjectFunc, 0, 0, 0)
	if (ErrorLevel)
		return false

	waitForSingleObject(hThread, 0xFFFFFFFF)
	closeProcess(hThread)

	return ErrorLevel ? false : __READMEM(hGTA, pMemory, [0x0], "Int")
}

global SERVER_SPEED_KOEFF := 1.425

global DIALOG_STYLE_MSGBOX			:= 0
global DIALOG_STYLE_INPUT 			:= 1
global DIALOG_STYLE_LIST			:= 2
global DIALOG_STYLE_PASSWORD		:= 3
global DIALOG_STYLE_TABLIST			:= 4
global DIALOG_STYLE_TABLIST_HEADERS	:= 5

global GAMESTATE_WAIT_CONNECT 		:= 9
global GAMESTATE_CONNECTING 		:= 13
global GAMESTATE_AWAIT_JOIN 		:= 15
global GAMESTATE_CONNECTED 			:= 14
global GAMESTATE_RESTARTING 		:= 18

global FIGHT_STYLE_NORMAL 			:= 4
global FIGHT_STYLE_BOXING 			:= 5
global FIGHT_STYLE_KUNGFU 			:= 6
global FIGHT_STYLE_KNEEHEAD 		:= 7
global FIGHT_STYLE_GRABKICK 		:= 15
global FIGHT_STYLE_ELBOW 			:= 16

global VEHICLE_TYPE_CAR				:= 1
global VEHICLE_TYPE_BIKE			:= 2
global VEHICLE_TYPE_HELI			:= 3
global VEHICLE_TYPE_BOAT			:= 4
global VEHICLE_TYPE_PLANE			:= 5

global nZone						:= 1
global nCity						:= 1

global OBJECT_MATERIAL_TEXT_ALIGN_LEFT   	:= 0
global OBJECT_MATERIAL_TEXT_ALIGN_CENTER 	:= 1
global OBJECT_MATERIAL_TEXT_ALIGN_RIGHT  	:= 2

global OBJECT_MATERIAL_SIZE_32x32  			:= 10
global OBJECT_MATERIAL_SIZE_64x32			:= 20
global OBJECT_MATERIAL_SIZE_64x64			:= 30
global OBJECT_MATERIAL_SIZE_128x32			:= 40
global OBJECT_MATERIAL_SIZE_128x64			:= 50
global OBJECT_MATERIAL_SIZE_128x128			:= 60
global OBJECT_MATERIAL_SIZE_256x32			:= 70
global OBJECT_MATERIAL_SIZE_256x64			:= 80
global OBJECT_MATERIAL_SIZE_256x128			:= 90
global OBJECT_MATERIAL_SIZE_256x256			:= 100
global OBJECT_MATERIAL_SIZE_512x64			:= 110
global OBJECT_MATERIAL_SIZE_512x128			:= 120
global OBJECT_MATERIAL_SIZE_512x256			:= 130
global OBJECT_MATERIAL_SIZE_512x512			:= 140

global oWeaponNames := ["Fist","Brass Knuckles","Golf Club","Nightstick","Knife","Baseball Bat","Shovel","Pool Cue","Katana","Chainsaw","Purple Dildo","Dildo"
	,"Vibrator","Silver Vibrator","Flowers","Cane","Grenade","Tear Gas","Molotov Cocktail", "", "", "", "9mm","Silenced 9mm","Desert Eagle","Shotgun","Sawnoff Shotgun"
	,"Combat Shotgun","Micro SMG/Uzi","MP5","AK-47","M4","Tec-9","Country Rifle","Sniper Rifle","RPG","HS Rocket","Flamethrower","Minigun","Satchel Charge","Detonator"
	,"Spraycan","Fire Extinguisher","Camera","Night Vis Goggles","Thermal Goggles","Parachute"]

global oVehicleNames := ["Landstalker", "Bravura", "Buffalo", "Linerunner", "Perenniel", "Sentinel", "Dumper", "Firetruck", "Trashmaster", "Stretch", "Manana"
	, "Infernus", "Voodoo", "Pony", "Mule", "Cheetah", "Ambulance", "Leviathan", "Moonbeam", "Esperanto", "Taxi", "Washington", "Bobcat", "Mr. Whoopee", "BF Injection"
	, "Hunter", "Premier", "Enforcer", "Securicar", "Banshee", "Predator", "Bus", "Rhino", "Barracks", "Hotknife", "Article Trailer", "Previon", "Coach", "Cabbie"
	, "Stallion", "Rumpo", "RC Bandit", "Romero", "Packer", "Monster", "Admiral", "Squallo", "Seasparrow", "Pizzaboy", "Tram", "Article Trailer 2", "Turismo", "Speeder"
	, "Reefer", "Tropic", "Flatbed", "Yankee", "Caddy", "Solair", "Topfun Van (Berkley's RC)", "Skimmer", "PCJ-600", "Faggio", "Freeway", "RC Baron", "RC Raider"
	, "Glendale", "Oceanic", "Sanchez", "Sparrow", "Patriot", "Quad", "Coastguard", "Dinghy", "Hermes", "Sabre", "Rustler", "ZR-350", "Walton", "Regina", "Comet"
	, "BMX", "Burrito", "Camper", "Marquis", "Baggage", "Dozer", "Maverick", "SAN News Maverick", "Rancher", "FBI Rancher", "Virgo", "Greenwood", "Jetmax", "Hotring Racer"
	, "Sandking", "Blista Compact", "Police Maverick", "Boxville", "Benson", "Mesa", "RC Goblin", "Hotring Racer A", "Hotring Racer B", "Bloodring Banger", "Rancher Lure"
	, "Super GT", "Elegant", "Journey", "Bike", "Mountain Bike", "Beagle", "Cropduster", "Stuntplane", "Tanker", "Roadtrain", "Nebula", "Majestic", "Buccaneer", "Shamal"
	, "Hydra", "FCR-900", "NRG-500", "HPV1000", "Cement Truck", "Towtruck", "Fortune", "Cadrona", "FBI Truck", "Willard", "Forklift", "Tractor", "Combine Harvester"
	, "Feltzer", "Remington", "Slamvan", "Blade", "Freight (Train)", "Brownstreak (Train)", "Vortex", "Vincent", "Bullet", "Clover", "Sadler", "Firetruck LA", "Hustler"
	, "Intruder", "Primo", "Cargobob", "Tampa", "Sunrise", "Merit", "Utility Van", "Nevada", "Yosemite", "Windsor", "Monster A", "Monster B", "Uranus", "Jester", "Sultan"
	, "Stratum", "Elegy", "Raindance", "RC Tiger", "Flash", "Tahoma", "Savanna", "Bandito", "Freight Flat Trailer (Train)", "Streak Trailer (Train)", "Kart", "Mower", "Dune"
	, "Sweeper", "Broadway", "Tornado", "AT400", "DFT-30", "Huntley", "Stafford", "BF-400", "Newsvan", "Tug", "Petrol Trailer", "Emperor", "Wayfarer", "Euros", "Hotdog"
	, "Club", "Freight Box Trailer (Train)", "Article Trailer 3", "Andromada", "Dodo", "RC Cam", "Launch", "Police Car (LSPD)", "Police Car (SFPD)", "Police Car (LVPD)"
	, "Police Ranger", "Picador", "S.W.A.T.", "Alpha", "Phoenix", "Glendale Shit", "Sadler Shit", "Baggage Trailer A", "Baggage Trailer B", "Tug Stairs Trailer", "Boxville"
	, "Farm Trailer", "Utility Trailer"]

global GTA_CPED_PTR							:= 0xB6F5F0
global GTA_VEHICLE_PTR						:= 0xBA18FC

global GTA_BLIP_POOL						:= 0xBA86F0
	global GTA_BLIP_COUNT						:= 0xAF
	global GTA_BLIP_ELEMENT_SIZE				:= 0x28
	global GTA_BLIP_COLOR_OFFSET				:= 0x0
	global GTA_BLIP_ID_OFFSET					:= 0x24
	global GTA_BLIP_STYLE_OFFSET				:= 0x25
	global GTA_BLIP_X_OFFSET					:= 0x8
	global GTA_BLIP_Y_OFFSET					:= 0xC
	global GTA_BLIP_Z_OFFSET					:= 0x10

global SAMP_MAX_PLAYERTEXTDRAWS				:= 256
global SAMP_MAX_TEXTDRAWS					:= 2048
global SAMP_MAX_TEXTLABELS					:= 2048
global SAMP_MAX_GANGZONES					:= 1024
global SAMP_MAX_PICKUPS						:= 4096
global SAMP_MAX_OBJECTS						:= 1000
global SAMP_MAX_PLAYERS						:= 1004
global SAMP_MAX_VEHICLES					:= 2000

global SAMP_SCOREBOARD_INFO_PTR				:= 0x21A0B4
global SAMP_CHAT_INFO_PTR					:= 0x21A0E4
global SAMP_KILL_INFO_PTR					:= 0x21A0EC
global SAMP_INFO_PTR						:= 0x21A0F8
global SAMP_MISC_INFO_PTR					:= 0x21A10C
global SAMP_INPUT_INFO_PTR					:= 0x21A0E8
global SAMP_DIALOG_INFO_PTR					:= 0x21A0B8

global SAMP_RAKCLIENT						:= 0x3C9
global SAMP_POOLS							:= 0x3CD
	global SAMP_POOL_ACTOR						:= 0x0
	global SAMP_POOL_OBJECT						:= 0x4
	global SAMP_POOL_GANGZONE					:= 0x8
	global SAMP_POOL_TEXTLABEL					:= 0xC
	global SAMP_POOL_TEXTDRAW					:= 0x10
		global SAMP_TEXTDRAW_LETTERWIDTH			:= 0x963
		global SAMP_TEXTDRAW_LETTERHEIGHT			:= 0x967
		global SAMP_TEXTDRAW_PROPORTIONAL			:= 0x97E
		global SAMP_TEXTDRAW_RIGHT 					:= 0x986
		global SAMP_TEXTDRAW_FONT 					:= 0x987
		global SAMP_TEXTDRAW_XPOS 					:= 0x98B
		global SAMP_TEXTDRAW_YPOS 					:= 0x98F
	global SAMP_POOL_PLAYERLABEL				:= 0x14
	global SAMP_POOL_PLAYER						:= 0x18
		global SAMP_REMOTEPLAYERS					:= 0x2E
		global SAMP_LOCALPLAYER						:= 0x22
	global SAMP_POOL_PICKUP							:= 0x20
	global SAMP_POOL_VEHICLE						:= 0x1C

global FUNC_SAMP_SEND_CMD					:= 0x65C60
global FUNC_SAMP_SEND_SAY					:= 0x57F0

global gangZoneTick 						:= 0
global oGangzones 							:= []
global textLabelTick						:= 0
global oTextLabels							:= []
global textDrawTick							:= 0
global oTextDraws							:= []
global pickupTick							:= 0
global oPickups								:= []
global objectTick							:= 0
global oObjects								:= []
global playerTick							:= 0
global oPlayers								:= ""
global vehicleTick							:= 0
global oVehicles							:= ""

global hGTA									:= 0x0
global dwGTAPID								:= 0x0
global dwSAMP								:= 0x0
global pMemory								:= 0x0
global pInjectFunc							:= 0x0
global pDetours								:= 0x0
global iRefreshHandles						:= 0

; // ###### SAMP FUNCTIONS ######

; // ############################## Dialog Functions ##############################

sendDialogResponse(dialogID, buttonID, listIndex := 0xFFFF, inputResponse := "") {
	if ((inputLen := StrLen(inputResponse)) > 128 || !checkHandles())
		return false

	VarSetCapacity(buf, (bufLen := 0x17 + inputLen), 0)
	NumPut(48 + inputLen * 8, buf, 0, "UInt")
	NumPut(2048, buf, 4, "UInt")
	NumPut(pMemory + 1024 + 0x11, buf, 0xC, "UInt")
	NumPut(1, buf, 0x10, "UChar")
	NumPut(dialogID, buf, 0x11, "UShort")
	NumPut(buttonID, buf, 0x13, "UChar")
	NumPut(listIndex, buf, 0x14, "UShort")
	NumPut(inputLen, buf, 0x16, "UChar")
	if (inputLen > 0)
		StrPut(inputResponse, &buf + 0x17, inputLen, "")

	if (!__WRITERAW(hGTA, pMemory + 1024, &buf, bufLen))
		return false

	return __CALL(hGTA, dwSAMP + 0x30B30, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_RAKCLIENT])], ["i", dwSAMP + 0xD7FA8], ["i", pMemory + 1024], ["i", 1]
		, ["i", 9], ["i", 0], ["i", 0]], false, true)
}

closeDialog() {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x6B210, [["i", __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR])]], false, true)
}

isDialogOpen() {
	return checkHandles() && __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x28])
}

getDialogTextPos() {
	return !checkHandles() ? false : [__DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x4]), __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x8])]
}

getDialogStyle() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x2C])
}

getDialogID() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x30])
}

setDialogID(id) {
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x30], id, "UInt")
}

getDialogIndex() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [0x12E350, 0x143]) + 1
}

getDialogCaption() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x40], 64)
}

getDialogText() {
	return !checkHandles() ? "" : ((dialogText := __READSTRING(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR, 0x34])), [0x0], 4096)) == "" ? __READSTRING(hGTA, dwAddress, [0x0], getDialogTextSize(dwAddress)) : dialogText)
}

getDialogTextSize(dwAddress) {
	Loop, 4096 {
		if (!__READBYTE(hGTA, dwAddress + (i := A_Index - 1)))
			break
	}

	return i
}

getDialogLine(index) {
	return index > (lines := getDialogLineCount()).Length() ? "" : lines[getDialogStyle() == DIALOG_STYLE_TABLIST_HEADERS ? ++index : index]
}

getDialogLineCount() {
	return (text := getDialogText()) == "" ? -1 : StrSplit(text, "`n")
}

getDialogSelectedUI() {
	if (!checkHandles() || !(uiAddress := __DWORD(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [0x21A190])), [0xF])))
		return 0

	dwAddress := __DWORD(hGTA, dwAddress, [0x15E])
	Loop, 3 {
		if (__DWORD(hGTA, dwAddress, [(A_Index - 1) * 4]) == uiAddress)
			return A_Index
	}

	return 0
}

showDialog(style, caption, text, button1, button2 := "", id := 1) {
	if (id < 0 || id > 32767 || style < 0 || style > 5 || StrLen(caption) > 64 || StrLen(text) > 4095 || StrLen(button1) > 10 || StrLen(button2) > 10 || !checkHandles())
		return false

	return __CALL(hGTA, dwSAMP + 0x6B9C0, [["i", __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR])], ["i", id], ["i", style], ["s", caption], ["s", text], ["s", button1], ["s", button2], ["i", 0]], false, true)
}

pressDialogButton(button) {
	return !checkHandles() || button < 0 || button > 1 ? false : __CALL(hGTA, dwSAMP + 0x6C040, [["i", __DWORD(hGTA, dwSAMP, [SAMP_DIALOG_INFO_PTR])], ["i", button]], false, true)
}

blockDialog() {
	return checkHandles() && NOP(hGTA, dwSAMP + 0x6C014, 7)	
}

unblockDialog() {
	return checkHandles() && __WRITEBYTES(hGTA, dwSAMP + 0x6C014, [0xC7, 0x46, 0x28, 0x1, 0x0, 0x0, 0x0])
}

setVehicleLightStatus(frontLeft, frontRight, rearBoth) {
	return !checkHandles() || !isPlayerDriver() || getVehicleType() != 1 ? false : __WRITEMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x5B0]
		, (~frontLeft & 1) + ((~frontRight & 1) << 2) + ((~rearBoth & 1) << 6), "UChar")
}

isChatOpen() {
	return checkHandles() && __READMEM(hGTA, dwSAMP, [SAMP_INPUT_INFO_PTR, 0x8, 0x4], "UChar")
}

isInMenu() {
	return checkHandles() && __READMEM(hGTA, 0xB6B964, [0x0], "UChar")
}

isScoreboardOpen() {
	return checkHandles() && __READMEM(hGTA, dwSAMP, [SAMP_SCOREBOARD_INFO_PTR, 0x0], "UChar")
}

sendChat(text) {
	return checkHandles() && __CALL(hGTA, dwSAMP + (SubStr(text, 1, 1) == "/" ? FUNC_SAMP_SEND_CMD : FUNC_SAMP_SEND_SAY), [["s", text]], false)
}

addChatMessage(text, color := 0xFFFFFFFF, timestamp := true) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x64010, [["i", __DWORD(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR])], ["i", timestamp ? 4 : 2], ["s", text], ["i", 0], ["i", color], ["i", 0]], false, true)
}

addChatMessages(text, color := 0xFFFFFFFF, timestamp := true, count := 1) {
	if (StrLen(text) > 128 || !checkHandles())
		return false

	dwFunc := dwSAMP + 0x64010
	dwLen := 46
	VarSetCapacity(injectData, dwLen, 0)
	NumPut(0xB9, injectData, 0, "UChar") ; mov ecx, count
	NumPut(count, injectData, 1, "UInt")

	NumPut(0x51, injectData, 5, "UChar") ; push ecx

	; // actual function call
	NumPut(0x68, injectData, 6, "UChar") ; push
	NumPut(0, injectData, 7, "UInt") ; push
	NumPut(0x68, injectData, 11, "UChar") ; push
	NumPut(color, injectData, 12, "UInt") ; push
	NumPut(0x68, injectData, 16, "UChar") ; push
	NumPut(0, injectData, 17, "UInt") ; push

	__WRITESTRING(hGTA, pMemory, [0x0], text)
	NumPut(0x68, injectData, 21, "UChar") ; push
	NumPut(pMemory, injectData, 22, "UInt") ; push

	NumPut(0x68, injectData, 26, "UChar") ; push
	NumPut(timestamp ? 4 : 2, injectData, 27, "UInt") ; push

	NumPut(0xB9, injectData, 31, "UChar") ; mov ecx, pointer (thiscall)
	NumPut(__DWORD(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR]), injectData, 32, "UInt")

	NumPut(0xE8, injectData, 36, "UChar") ; call
	offset := dwFunc - (pInjectFunc + 41)
	NumPut(offset, injectData, 37, "Int")

	NumPut(0x59, injectData, 41, "UChar") ; pop ecx
	NumPut(0x49, injectData, 42, "UChar") ; dec ecx
	NumPut(0x75, injectData, 43, "UChar") ; JNZ SHORT
	NumPut(0xD8, injectData, 44, "UChar") ; JNZ SHORT

	NumPut(0xC3, injectData, 45, "UChar")
	__WRITERAW(hGTA, pInjectFunc, &injectData, dwLen)
	if (ErrorLevel)
		return false

	hThread := createRemoteThread(hGTA, 0, 0, pInjectFunc, 0, 0, 0)
	if (ErrorLevel)
		return false

	waitForSingleObject(hThread, 0xFFFFFFFF)
	closeProcess(hThread)
	return true
}

getPageSize() {
	return !checkHandles() ? false : __READMEM(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR, 0x0], "UChar")
}

setPageSize(pageSize) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x636D0, [["i", __DWORD(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR])], ["i", pageSize]], false, true)
}

getMoney() {
	return !checkHandles() ? "" : __READMEM(hGTA, 0xB7CE50, [0x0], "Int")
}

getPlayerAnim() {
	return !checkHandles() ? false : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_LOCALPLAYER, 0x4], "Short")
}

getPing() {
	if (!checkHandles() || !__CALL(hGTA, dwSAMP + 0x8A10, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR])]], false, true))
		return 0

	return  __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, 0x26])
}

getScore() {
	return !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, 0x2A])
}

; // ############################## RemotePlayer Functions ##############################

getVehicleIDByNumberPlate(numberPlate) {
	if (!checkHandles() || (len := StrLen(numberPlate)) <= 0 || len > 32 || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE])))
		return false

	count := __DWORD(hGTA, dwAddress, [0x0])
	Loop % SAMP_MAX_VEHICLES {
		if (!__DWORD(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x3074]))
			continue

		if (numberPlate == __READSTRING(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x1134, 0x93], len))
			return A_Index - 1

		if (--count <= 0)
			break
	}

	return false
}

getVehicleNumberPlates() {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE])))
		return ""

	vehicles := []
	count := __DWORD(hGTA, dwAddress, [0x0])
	Loop % SAMP_MAX_VEHICLES {
		if (!__DWORD(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x3074]))
			continue

		vehicles[A_Index - 1] := __READSTRING(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x1134, 0x93], 32)

		if (--count <= 0)
			break
	}

	return vehicles
}

getVehicleIDsByNumberPlate(numberPlate) {
	if (!checkHandles() || (len := StrLen(numberPlate)) <= 0 || len > 32 || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE])))
		return ""

	vehicles := []
	count := __DWORD(hGTA, dwAddress, [0x0])
	Loop % SAMP_MAX_VEHICLES {
		if (!__DWORD(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x3074]))
			continue

		if (InStr(__READSTRING(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x1134, 0x93], 32), numberPlate))
			vehicles.Push(A_Index - 1)

		if (--count <= 0)
			break
	}

	return vehicles
}

getVehiclePosition(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : [__READMEM(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, vehicleID * 4 + 0x1134, 0x40, 0x14])), [0x30], "Float"), __READMEM(hGTA, dwAddress, [0x34], "Float"), __READMEM(hGTA, dwAddress, [0x38], "Float")]
}

getVehicleNumberPlate(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, vehicleID * 4 + 0x1134, 0x93], 32)
}

getVehicleID() {
	if (!checkHandles() || !isPlayerInAnyVehicle())
		return false

	return __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_LOCALPLAYER, isPlayerDriver() ? 0xAA : 0x5C], "UShort")
}

getPlayerScore(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x24])
}

isPlayerUsingCell(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0])
}

isPlayerUrinating(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x2B6])
}

isPlayerDancing(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x28A])
}

getPlayerDanceStyle(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x28E])
}

getPlayerDanceMove(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x292])
}

getPlayerDrunkLevel(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x281])
}

getPlayerSpecialAction(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0xBB], "UChar")
}

getPlayerVehicleID(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0xAD], "UShort")
}

getPlayerVehiclePos(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : [__READMEM(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0])), [0x93], "Float"), __READMEM(hGTA, dwAddress, [0x97], "Float"), __READMEM(hGTA, dwAddress, [0x9B], "Float")]
}

getPlayerTeamID(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x8], "UChar")
}

getPlayerState(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x9], "UChar")
}

getPlayerSeatID(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0xA], "UChar")
}

getPlayerPing(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x28])
}

isNPC(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x4])
}

getAFKState(playerID) {
	return !checkHandles() || playerID < 0 || playerID >= SAMP_MAX_PLAYERS ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x1D1])
}

getPlayerWeaponID(playerID, slot) {
	return (slot < 0 || slot > 12 || playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles()) ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0, 0x2A4, 0x5A0 + slot * 0x1C])

}

getPlayerAmmo(playerID, slot) {
	return (slot < 0 || slot > 12 || playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles()) ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0, 0x2A4, 0x5AC + slot * 0x1C])
}

getPlayerColor(playerID) {
	return !checkHandles() ? -1 : (((color := __DWORD(hGTA, dwSAMP, [0x216378 + playerID * 4])) >> 8) & 0xFF) + ((color >> 16) & 0xFF) * 0x100 + ((color >> 24) & 0xFF) * 0x10000
}

getPlayerColor1(playerID) {
	return !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [0x103078 + playerID * 4])
}

getChatBubbleText(playerID) {
	return playerID < 0 || playerID > SAMP_MAX_PLAYERS - 1 || !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [0x21A0DC, playerID * 0x118 + 0x4], 256)
}

isChatBubbleShown(playerID) {
	return playerID < 0 || playerID > SAMP_MAX_PLAYERS - 1 || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [0x21A0DC, playerID * 0x118], "Int")
}

getPlayerID(playerName, exact := 0) {
	if (!updatePlayers())
		return ""

	for i, o in oPlayers {
		if (exact) {
			if (o = playerName)
				return i
		}
		else {
			if (InStr(o, playerName) == 1)
				return i
		}
	}

	return ""
}

getPlayerName(playerID) {
	if (playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() || getPlayerScore(playerID) == "")
		return ""

	if (__DWORD(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4])), [0x1C]) > 15)
		return __READSTRING(hGTA, dwAddress, [0xC, 0x0], 25)

	return __READSTRING(hGTA, dwAddress, [0xC], 16)
}

; // ############################## LocalPlayer Functions ##############################

getUsername() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [0x219A6F], 25)
}

getArmor() {
	return !checkHandles() ? "" : __READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x548], "Float")
}

getID() {
	return !checkHandles() ? -1 : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, 0x4], "UShort")
}

getChatlogPath() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR, 0x11], 256)
}

showGameText(text, time, style) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x9C2C0, [["s", text], ["i", time], ["i", style]], false)
}

getGameText() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [0x13BEFC], 128)
}

getGameTextByStyle(style) {
	return !checkHandles() ? "" : __READSTRING(hGTA, 0xBAACC0, [style * 0x80], 128)
}

toggleChatShown(shown := true) {
	return !checkHandles() ? -1 : __WRITEMEM(hGTA, dwSAMP, [0x64230], shown ? 0x56 : 0xC3, "UChar")
}

isChatShown() {
	return checkHandles() && __READMEM(hGTA, dwSAMP, [0x64230], "UChar") == 0x56
}

isCheckpointSet() {
	return checkHandles() && __READMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x24], "UChar")
}

toggleCheckpoint(toggle := true) {
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x24], toggle ? 1 : 0 ,"UChar")
}

getCheckpointSize() {
	return !checkHandles() ? false : __READMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x18], "Float")
}

getCheckpointPos() {
	if (!checkhandles())
		return ""

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR])
	for i, o in [0xC, 0x10, 0x14]
		pos%i% := __READMEM(hGTA, dwAddress, [o], "Float")

	return [pos1, pos2, pos3]
}

setCheckpointPos(cpPos) {
	if (!checkhandles())
		return ""

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR])
	for i, o in [0xC, 0x10, 0x14]
		pos%i% := __WRITEMEM(hGTA, dwAddress, [o], cpPos[A_Index], "Float")

	return [pos1, pos2, pos3]
}

setCheckpoint(fX, fY, fZ, fSize := 3.0) {
	if (!checkHandles())
		return false

	VarSetCapacity(buf, 16, 0)
	NumPut(fX, buf, 0, "Float")
	NumPut(fY, buf, 4, "Float")
	NumPut(fZ, buf, 8, "Float")
	NumPut(fSize, buf, 12, "Float")
	if (!__WRITERAW(hGTA, pMemory + 20, &buf, 16))
		return false

	return __CALL(hGTA, dwSAMP + 0x9D340, [["i", __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR])], ["i", pMemory + 20], ["i", pMemory + 32]], false, true) && toggleCheckpoint()
}

isRaceCheckpointSet() {
	return checkHandles() && __READMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x49], "UChar")
}

toggleRaceCheckpoint(toggle := true) {
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x49], toggle ? 1 : 0 ,"UChar")
}

getRaceCheckpointType() {
	return !checkHandles() ? false : __READMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x48], "UChar")
}

getRaceCheckpointSize() {
	return !checkHandles() ? false : __READMEM(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x44], "Float")
}

getRaceCheckpointPos() {
	if (!checkhandles())
		return ""

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR])
	Loop, 6
		pos%A_Index% := __READMEM(hGTA, dwAddress, [0x2C + (A_Index - 1) * 4], "Float")

	return [pos1, pos2, pos3, pos4, pos5, pos6]
}

setRaceCheckpoint(type, fX, fY, fZ, fXNext, fYNext, fZNext, fSize := 3.0) {
	if (!checkHandles())
		return false

	VarSetCapacity(buf, 28, 0)
	NumPut(fX, buf, 0, "Float")
	NumPut(fY, buf, 4, "Float")
	NumPut(fZ, buf, 8, "Float")
	NumPut(fXNext, buf, 12, "Float")
	NumPut(fYNext, buf, 16, "Float")
	NumPut(fZNext, buf, 20, "Float")

	if (!__WRITERAW(hGTA, pMemory + 24, &buf, 28))
		return false

	return __CALL(hGTA, dwSAMP + 0x9D660, [["i", __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR])], ["i", type], ["i", pMemory + 24], ["i", pMemory + 36]
		, ["f", fSize]], false, true) && toggleRaceCheckpoint()
}

getLastSentMsg() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_INPUT_INFO_PTR, 0x1565], 128)
}

setLastSentMsg(text) {
	return checkHandles() && __WRITESTRING(hGTA, dwSAMP, [SAMP_INPUT_INFO_PTR, 0x1565], text)
}

pushSentMsg(text) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x65930, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INPUT_INFO_PTR])], ["s", text]], false, true)
}

patchWanteds() {
	return !checkHandles() ? false : __WRITEBYTES(hGTA, dwSAMP + 0x9C9C0, [0xC2, 0x04, 0x0, 0x0])
}

unpatchWanteds() {
	return !checkHandles() ? false : __WRITEBYTES(hGTA, dwSAMP + 0x9C9C0, [0x8A, 0x44, 0x24,04])
}

checkSendCMDNOP() {
	return checkHandles() && NOP(hGTA, dwSAMP + 0x65DF8, 5) && NOP(hGTA, dwSAMP + 0x65E45, 5)
}

unpatchSendCMD() {
	return !checkHandles() ? false : __WRITEBYTES(hGTA, dwSAMP + 0x65DF8, [0xE8, 0x63, 0xFE, 0xFF, 0xFF]) && __WRITEBYTES(hGTA, dwSAMP + 0x65E45, [0xE8, 0x16, 0xFE, 0xFF, 0xFF])
}

getChatRenderMode() {
	return !checkHandles() ? -1 : __READMEM(hGTA, [SAMP_CHAT_INFO_PTR, 0x8], "UChar")
}

toggleScoreboard(toggle) {
	return checkHandles() && (toggle ? __CALL(hGTA, dwSAMP + 0x6AD30, [["i", __DWORD(hGTA, dwSAMP, [SAMP_SCOREBOARD_INFO_PTR])]], false, true) : __CALL(hGTA, dwSAMP + 0x6A320, [["i", __DWORD(hGTA, dwSAMP, [SAMP_SCOREBOARD_INFO_PTR])], ["i", 1]], false, true))
}

toggleChatInput(toggle) {	
	return checkHandles() && __CALL(hGTA, dwSAMP + (toggle ? 0x657E0 : 0x658E0), [["i", __DWORD(hGTA, dwSAMP, [SAMP_INPUT_INFO_PTR])]], false, true)
}

setGameState(state) {
	return !checkHandles() ? false : __WRITEMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x3BD], state)
}

getGameState() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x3BD])
}

isLineOfSightClear(fX1, fY1, fZ1, fX2, fY2, fZ2) {
	if (!checkHandles())
		return false

	__WRITEMEM(hGTA, pMemory, [0x0], fX1, "Float")
	__WRITEMEM(hGTA, pMemory + 4, [0x0], fY1, "Float")
	__WRITEMEM(hGTA, pMemory + 8, [0x0], fZ1, "Float")
	__WRITEMEM(hGTA, pMemory + 12, [0x0], fX2, "Float")
	__WRITEMEM(hGTA, pMemory + 16, [0x0], fY2, "Float")
	__WRITEMEM(hGTA, pMemory + 20, [0x0], fZ2, "Float")

	return __CALL(hGTA, 0x56A490, [["i", pMemory], ["i", pMemory + 12], ["i", 1], ["i", 0], ["i", 0], ["i", 1], ["i", 0], ["i", 0], ["i", 0]], true, false, true)
}

takeScreenshot() {
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [0x119CBC], "UChar")
}

getPlayerFightingStyle() {
	return !checkHandles() ? false : __READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x72D], "UChar")
}

getMaxPlayerID() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, 0x0])
}

getWeatherID() {
	return !checkHandles() ? "" : __READMEM(hGTA, 0xC81320, [0x0], "UShort")
}

getAmmo(slot) {
	return (slot < 0 || slot > 12 || !checkHandles()) ? "" : __DWORD(hGTA, GTA_CPED_PTR, [0x0, 0x5AC + slot * 0x1C])
}

getWeaponID(slot) {
	return (slot < 0 || slot > 12 || !checkHandles()) ? "" : __DWORD(hGTA, GTA_CPED_PTR, [0x0, 0x5A0 + slot * 0x1C])
}

getActiveWeaponSlot() {
	return !checkHandles() ? -1 : __READMEM(hGTA, 0xB7CDBC, [0x0], "UChar")
}

cameraRestoreWithJumpcut() {
	return checkHandles() && __CALL(hGTA, 0x50BAB0, [["i", 0xB6F028]], false, true)
}

calcAngle(xActor, yActor, xPoint, yPoint) {
	fX := xActor - xPoint
	fY := yActor - yPoint
	return atan2(fX, fY)
}

atan2(x, y) {
	return DllCall("msvcrt\atan2", "Double", y, "Double", x, "CDECL Double")
}

getPlayerZAngle() {
	return !checkHandles() ? "" : __READMEM(hGTA, 0xB6F5F0, [0x0, 0x558], "Float")
}

setCameraPosX(fAngle) {
	return checkHandles() && __WRITEMEM(hGTA, 0xB6F258, [0x0], "Float")
}

isPlayerFrozen() {
	return checkHandles() && __READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x42], "UChar")
}

isPlayerInRangeOfPoint(fX, fY, fZ, r) {
	return checkHandles() && getDistance(getPlayerPos(), [fX, fY, fZ]) <= r
}

getMapQuadrant(pos) {
	return pos[1] <= 0 ? (pos[2] <= 0 ? 3 : 1) : (pos[2] <= 0 ? 4 : 2)
}

getWeaponIDByName(weaponName) {
	for i, o in oWeaponNames {
		if (o = weaponName)
			return i - 1
	}

	return -1
}

getWeaponName(weaponID) {
	return weaponID < 0 || weaponID > oWeaponNames.MaxIndex() ? "" : oWeaponNames[weaponID + 1]
}

getPlayerPed(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? 0x0 : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0, 0x2A4])
}

getIFPAnimationName1(playerID) {
	if (!(ped := getPlayerPed(playerID)))
		return ""

	if (!(dwAddress := isTaskActive(ped, 401)))
		dwAddress := __DWORD(hGTA, ped, [0x47C])

	return __READSTRING(hGTA, dwAddress, [0x28], 10) . " , " . __READSTRING(hGTA, dwAddress, [0x10], 20)
}

getIFPAnimationName(playerID) {
	if (!(ped := getPlayerPed(playerID)))
		return ""

	if (!(dwAddress := isTaskActive(ped, 401)))
		dwAddress := __DWORD(hGTA, ped, [0x47C])

	return __READSTRING(hGTA, dwAddress, [0x10], 20)
}

isTaskActive(ped, taskID) {
	return !checkHandles() ? false : __CALL(hGTA, 0x681740, [["i", __DWORD(hGTA, ped, [0x47C]) + 0x4], ["i", taskID]], false, true, true, "UInt")
}

getVehicleColor1() {
	return !checkHandles() ? false : __READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x434], "UChar")
}

getVehicleColor2() {
	return !checkHandles() ? false : __READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x435], "UChar")
}

getVehicleSpeed() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : sqrt(((fSpeedX := __READMEM(hGTA, (dwAddress := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])), [0x44], "Float")) * fSpeedX) + ((fSpeedY := __READMEM(hGTA, dwAddress, [0x48], "Float")) * fSpeedY) + ((fSpeedZ := __READMEM(hGTA, dwAddress, [0x4C], "Float")) * fSpeedZ)) * 100 * SERVER_SPEED_KOEFF
}

getVehicleMaxSpeed(modelID) {
	if (!checkHandles())
		return false

	return __READMEM(hGTA, 0xC2BA60, [(modelID - 400) * 0xE0], "Float")
}

getVehicleBootAngle() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : __READMEM(hGTA, GTA_VEHICLE_PTR, [0x5DC], "Float")
}

getVehicleBonnetAngle() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : __READMEM(hGTA, GTA_VEHICLE_PTR, [0x5C4], "Float")
}

getVehicleType() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? false : __CALL(hGTA, 0x6D1080, [["i", __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])]], false, true, true, "Char")
}

getInteriorID() {
	return !checkHandles() ? false : __DWORD(hGTA, 0xA4ACE8, [0x0])
}

isPlayerInAnyVehicle() {
	return checkHandles() && __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0]) > 0
}

isPlayerDriver() {
	return checkHandles() && __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0, 0x460]) == __DWORD(hGTA, GTA_CPED_PTR, [0x0])
}

getPlayerHealth() {
	return !checkHandles() ? -1 : Round(__READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x540], "Float"))
}

getPlayerArmor() {
	return !checkHandles() ? -1 : Round(__READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x548], "Float"))
}

getVehicleHealth() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : Round(__READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x4C0], "Float"))
}

getVehicleRotation() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : [__READMEM(hGTA, (dwAddress := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0, 0x14])), [0x0], "Float"), __READMEM(hGTA, dwAddress, [0x4], "Float"), __READMEM(hGTA, dwAddress, [0x8], "Float")]
}

getVehiclePos() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : [__READMEM(hGTA, (dwAddress := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0, 0x14])), [0x30], "Float"), __READMEM(hGTA, dwAddress, [0x34], "Float"), __READMEM(hGTA, dwAddress, [0x38], "Float")]
}

getPlayerVehicleModelID() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : __READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x22], "UShort")
}

getVehicleModelName(modelID) {
	return modelID < 400 || modelID > 611 ? "" : oVehicleNames[modelID - 399]
}

getPlayerVehicleEngineState() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : (__READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x428], "UChar") & 16 ? true : false)
}

getPlayerVehicleLightState() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : (__READMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x428], "UChar") & 64 ? true : false)
}

getPlayerVehicleLockState() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : (__DWORD(hGTA, GTA_VEHICLE_PTR, [0x0, 0x4F8]) == 2)
}

getPlayerVehicleSirenState() {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0, 0x1F7])
}

setVehicleSirenState(toggle := true) {
	return !checkHandles() || !isPlayerInAnyVehicle() ? "" : __WRITEMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x42D], toggle ? 208 : 80, "UChar")
}

toggleVision(type, toggle := true) {
	return (type != 0 && type != 1) || !checkHandles() ? false : __WRITEMEM(hGTA, 0xC402B8, [type], toggle, "UChar")
}

toggleCursor(toggle) {
	return checkHandles() && __WRITEMEM(hGTA, __DWORD(hGTA, dwSAMP + 0x21A0CC, [0x0]), [0x0], toggle ? true : false, "UChar") && __CALL(hGTA, dwSAMP + 0x9BD30, [["i", (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR]))], ["i", 0], ["i", 0]], false, true) && (toggle ? __CALL(hGTA, dwSAMP + 0x9BC10, [["i", dwAddress]], false, true) : true)
}

getDrunkLevel() {
	return !checkHandles() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8, 0x2C9])
}

setPlayerAttachedObject(slot, modelID, bone, xPos, yPos, zPos, xRot, yRot, zRot, xScale := 1, yScale := 1, zScale := 1, color1 := 0x0, color2 := 0x0) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])))
		return false

	VarSetCapacity(struct, 52, 0)
	NumPut(modelID, &struct, 0, "UInt")
	NumPut(bone, &struct, 4, "UInt")

	NumPut(xPos, &struct, 8, "Float")
	NumPut(yPos, &struct, 12, "Float")
	NumPut(zPos, &struct, 16, "Float")

	NumPut(xRot, &struct, 20, "Float")
	NumPut(yRot, &struct, 24, "Float")
	NumPut(zRot, &struct, 28, "Float")

	NumPut(xScale, &struct, 32, "Float")
	NumPut(yScale, &struct, 36, "Float")
	NumPut(zScale, &struct, 40, "Float")

	NumPut(color1, &struct, 44, "UInt")
	NumPut(color2, &struct, 48, "UInt")

	return !__WRITERAW(hGTA, pMemory + 1024, &struct, 52) ? false : __CALL(hGTA, dwSAMP + 0xAB3E0, [["i", dwAddress], ["i", slot], ["i", pMemory + 1024]], false, true)
}

setRemotePlayerAttachedObject(playerID, slot, modelID, bone, xPos, yPos, zPos, xRot, yRot, zRot, xScale := 1, yScale := 1, zScale := 1, color1 := 0x0, color2 := 0x0) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0])))
		return false

	if (!(dwAddress := __DWORD(hGTA, dwAddress, [0x0])))
		return false

	VarSetCapacity(struct, 52, 0)
	NumPut(modelID, &struct, 0, "UInt")
	NumPut(bone, &struct, 4, "UInt")

	NumPut(xPos, &struct, 8, "Float")
	NumPut(yPos, &struct, 12, "Float")
	NumPut(zPos, &struct, 16, "Float")

	NumPut(xRot, &struct, 20, "Float")
	NumPut(yRot, &struct, 24, "Float")
	NumPut(zRot, &struct, 28, "Float")

	NumPut(xScale, &struct, 32, "Float")
	NumPut(yScale, &struct, 36, "Float")
	NumPut(zScale, &struct, 40, "Float")

	NumPut(color1, &struct, 44, "UInt")
	NumPut(color2, &struct, 48, "UInt")

	return !__WRITERAW(hGTA, pMemory + 1024, &struct, 52) ? false : __CALL(hGTA, dwSAMP + 0xAB3E0, [["i", dwAddress], ["i", slot], ["i", pMemory + 1024]], false, true)
}

printRemotePlayerAttachedObjects(playerID) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0])))
		return false

	if (!(dwAddress := __DWORD(hGTA, dwAddress, [0x0])))
		return false

	Loop, 10 {
		if (!(objectID := __DWORD(hGTA, dwAddress, [0x74 + (A_Index - 1) * 0x34])))
			continue

		AddChatMessage("SLOT: " A_Index - 1 ", OBJECTID: " objectID)
	}

	return true
}

getPlayerAttachedObjects() {
	if (!checkHandles() || !(dwLocalPlayerPED := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])))
		return ""

	oPlayerObjects := []
	Loop, 10 {
		if (!(objectID := __DWORD(hGTA, dwLocalPlayerPED, [0x74 + (A_Index - 1) * 0x34])))
			continue

		oPlayerObjects.Push(Object("SLOT", A_Index - 1, "OBJECTID", objectID))
	}

	return oPlayerObjects
}

getPlayerAttachedObjectPos(slot) {
	if (!checkHandles() || !(dwLocalPlayerPED := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])))
		return ""

	posMatrix := []
	Loop, 9
		posMatrix[A_Index] := __READMEM(hGTA, dwLocalPlayerPED, [0x7C + slot * 0x34 + (A_Index - 1) * 0x4], "Float")
	
	return posMatrix
}

printPlayerAttachedObjectPos(slot) {
	if ((posMatrix := getPlayerAttachedObjectPos(slot)) == "")
		return AddChatMessage("Slot not in use.")

	string := ""
	for i, o in posMatrix
		string .= o ", "

	StringTrimRight, string, string, 2
	return AddChatMessage("Slot " slot ": " string)
}

printPlayerAttachedObjects() {
	if (!checkHandles() || !(dwLocalPlayerPED := __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])))
		return ""

	oPlayerObjects := []
	Loop, 10 {
		if (!(objectID := __DWORD(hGTA, dwLocalPlayerPED, [0x74 + (A_Index - 1) * 0x34])))
			continue

		AddChatMessage("SLOT: " A_Index - 1 ", OBJECTID: " objectID)
	}

	return oPlayerObjects
}

clearPlayerAttachedObject(slot) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0xA96F0, [["i", __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])], ["i", slot]], false, true)
}

quitGame() {
	return checkHandles() && __CALL(hGTA, 0x619B60, [["i", 0x1E], ["i", 0]])
}

getServerName() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x121], 259)
}

getServerIP() {
	return !checkHandles() ? "" : __READSTRING(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x20], 257)
}

getServerPort() {
	return !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x225], "UInt")
}

isPlayerSwimming() {
	return !checkHandles() ? "" : __CALL(hGTA, 0x601070, [["i", __DWORD(hGTA, GTA_CPED_PTR, [0x0, 0x47C])]], false, true, true, "UInt") > 0
}

getTargetPlayerID() {
	return !checkHandles() ? 0xFFFF : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_LOCALPLAYER, 0x161], "UShort")
}

isPlayerSpawned() {
	return checkHandles() && __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_LOCALPLAYER, 0x136])
}

updatePlayers() {
	if (!checkHandles())
		return false

	if (playerTick + 1000 > A_TickCount)
		return true

	oPlayers := []
	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	
	Loop, % getMaxPlayerID() + 1
	{
		if (!(dwRemoteplayer := __DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + (A_Index - 1) * 4])))
			continue
		
		oPlayers[A_Index - 1] := (__DWORD(hGTA, dwRemoteplayer, [0x1C]) > 15 ? __READSTRING(hGTA, dwRemoteplayer, [0xC, 0x0], 25) : __READSTRING(hGTA, dwRemoteplayer, [0xC], 16))
	}

	playerTick := A_TickCount
	return true
}

printPlayers() {
	if (!updatePlayers())
		return false

	playerCount := 1
	for i, o in oPlayers {
		playerCount++
		addChatMessage("ID: " i ", Name: " o)
	}

	addChatMessage("Player Count: " playerCount)
	return true
}

getPlayerCount() {
	if (!updatePlayers())
		return false

	playerCount := 1
	for i, o in oPlayers
		playerCount++

	return playerCount
}

updateGangzones() {
	if (!checkHandles())
		return false

	if (gangZoneTick + 1000 > A_TickCount)
		return true

	oGangzones := []

	if (!(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_GANGZONE])))
		return false

	Loop % SAMP_MAX_GANGZONES {
		if (!__DWORD(hGTA, dwAddress, [(A_Index - 1) * 4 + 4 * SAMP_MAX_GANGZONES]))
			continue

		oGangzones.Push(Object("ID", A_Index - 1, "XMIN", __READMEM(hGTA, (dwGangzone := __DWORD(hGTA, dwAddress, [(A_Index - 1) * 4])), [0x0], "Float"), "YMIN", __READMEM(hGTA, dwGangzone, [0x4], "Float"), "XMAX", __READMEM(hGTA, dwGangzone, [0x8], "Float"), "YMAX", __READMEM(hGTA, dwGangzone, [0xC], "Float"), "COLOR1", __DWORD(hGTA, dwGangzone, [0x10]), "COLOR2", __DWORD(hGTA, dwGangzone, [0x14])))
	}

	gangZoneTick := A_TickCount
	return true
}

printGangzones() {
	if (!updateGangzones())
		return false

	for i, o in oGangzones
		AddChatMessage("ID: " o.ID ", X: " o.XMIN " - " o.XMAX ", Y: " o.YMIN " - " o.YMAX ", Colors: " intToHex(o.COLOR1) " - " intToHex(o.COLOR2))

	return true
}

checkLyDTextDraws() {
	if (!checkHandles())
		return false

	dwSAMPTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])
	; // Player 0 Label (Status, Wantedlevels)
	dwAddress := __DWORD(hGTA, dwSAMPTextDraws, [0x4400])
	if (__READMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], "UInt") == 3)
		return false

	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], 3, "UInt")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERWIDTH], 0.28, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERHEIGHT], 1.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_XPOS], 15.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_YPOS], 315.0, "Float")

	; // Player 20 Label (Payday)
	dwAddress := __DWORD(hGTA, dwSAMPTextDraws, [0x4450])
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], 3, "UInt")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERWIDTH], 0.28, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERHEIGHT], 1.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_XPOS], 540.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_YPOS], 12.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_RIGHT], 1, "UChar")

	return true
}

changeLyDTextDraws() {
	if (!checkHandles())
		return false

	dwSAMPTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])
	; // Player 0 Label (Status, Wantedlevels)
	dwAddress := __DWORD(hGTA, dwSAMPTextDraws, [0x4400])
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], 3, "UInt")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERWIDTH], 0.28, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERHEIGHT], 1.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_XPOS], 15.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_YPOS], 315.0, "Float")

	; // Player 20 Label (Payday)
	dwAddress := __DWORD(hGTA, dwSAMPTextDraws, [0x4450])
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], 3, "UInt")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERWIDTH], 0.28, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERHEIGHT], 1.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_XPOS], 540.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_YPOS], 12.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_RIGHT], 1, "UChar")

	; // Global 10 Label (Forum)
	dwAddress := __DWORD(hGTA, dwSAMPTextDraws, [0x2428])
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_FONT], 3, "UInt")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERWIDTH], 0.28, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_LETTERHEIGHT], 1.0, "Float")
	__WRITEMEM(hGTA, dwAddress, [SAMP_TEXTDRAW_XPOS], 15.0, "Float")

	setHUDValue("RadarX", 15.0)
	setHUDValue("ArmorColor", 11)
	setHUDValue("BreathColor", 14)
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 0], 0xFF1F1FE0, "UInt")
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 1], 0xFF009933, "UInt")
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 2], 0xFFFF901E, "UInt")
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 4], 0xFFFFFFFF, "UInt")
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 6], 0xFF00D7FF, "UInt")
	__WRITEMEM(hGTA, 0xBAB22C, [4 * 11], 0xFF00D7FF, "UInt")

	return true
}

updateTextDraws() {
	if (!checkHandles())
		return false

	if (textDrawTick + 1000 > A_TickCount)
		return true

	oTextDraws := []
	if (!(dwTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])))
		return false

	Loop, % SAMP_MAX_TEXTDRAWS {
		if (!__DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4]) || !(dwAddress := __DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4 + (4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS))])))
			continue

		oTextDraws.Push(Object("TYPE", "Global", "ID", A_Index - 1, "TEXT", __READSTRING(hGTA, dwAddress, [0x0], 800)))
	}

	Loop, % SAMP_MAX_PLAYERTEXTDRAWS {
		if (!__DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4 + SAMP_MAX_TEXTDRAWS * 4]) || !(dwAddress := __DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4 + (4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS * 2))])))
			continue

		oTextDraws.Push(Object("TYPE", "Player", "ID", A_Index - 1, "TEXT", __READSTRING(hGTA, dwAddress, [0x0], 800)))
	}

	textDrawTick := A_TickCount
	return true
}

getLYDWantedLevel() {
	if (!checkHandles() || !(dwTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])))
		return ""

	Loop, % SAMP_MAX_PLAYERTEXTDRAWS {
		if (!__DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4 + SAMP_MAX_TEXTDRAWS * 4]) || !(dwAddress := __DWORD(hGTA, dwTextDraws, [(A_Index - 1) * 4 + (4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS * 2))])) || !InStr((string := __READSTRING(hGTA, dwAddress, [0x0], 800)), "Wantedlevel"))
			continue

		RegExMatch(string, "Wantedlevel: ~w~(\d+)", wantedlevel)
		return wantedlevel1
	}

	return ""
}

printTextDraws() {
	if (!updateTextDraws())
		return false

	for i, o in oTextDraws
		AddChatMessage("Type: " o.TYPE ", ID: " o.ID ", Text: " o.TEXT)

	AddChatMessage("TextDraw Count: " i)
	return true
}

getTextDrawBySubstring(substring) {
	if (!updateTextDraws())
		return ""

	for i, o in oTextDraws {
		if (InStr(o.TEXT, substring))
			return o.TEXT
	}

	return ""
}

deleteTextDraw(ByRef textDrawID) {
	if (textDrawID < 0 || textDrawID > SAMP_MAX_TEXTDRAWS - 1 || !checkHandles()) {
		textDrawID := -1
		return -1
	}

	if (__CALL(hGTA, dwSAMP + 0x1AD00, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])], ["i", textDrawID]], false, true)) {
		textDrawID := -1
		return -1
	}

	AddChatMessage("Could not be deleted: " textDrawID)
	return textDrawID
}

createTextDraw(text, xPos, yPos, letterColor := 0xFFFFFFFF, font := 3, letterWidth := 0.4, letterHeight := 1, shadowSize := 0, outline := 1
	, shadowColor := 0xFF000000, box := 0, boxColor := 0xFFFFFFFF, boxSizeX := 0.0, boxSizeY := 0.0, left := 0, right := 0, center := 1
	, proportional := 1, modelID := 0, xRot := 0.0, yRot := 0.0, zRot := 0.0, zoom := 1.0, color1 := 0xFFFF, color2 := 0xFFFF) {

	if (font > 5 || StrLen(text) > 800 || !checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])))
		return -1

	Loop, 2048 {
		i := 2048 - A_Index
		if (__DWORD(hGTA, dwAddress, [i * 4]))
			continue

		VarSetCapacity(struct, 63, 0)
		NumPut((box ? 1 : 0) + (left ? 2 : 0) + (right ? 4 : 0) + (center ? 8 : 0) + (proportional ? 16 : 0), &struct, 0, "UChar")
		NumPut(letterWidth, &struct, 1, "Float")
		NumPut(letterHeight, &struct, 5, "Float")
		NumPut(letterColor, &struct, 9, "UInt")
		NumPut(boxSizeX, &struct, 0xD, "Float")
		NumPut(boxSizeY, &struct, 0x11, "Float")
		NumPut(boxColor, &struct, 0x15, "UInt")
		NumPut(shadowSize, &struct, 0x19, "UChar")
		NumPut(outline, &struct, 0x1A, "UChar")
		NumPut(shadowColor, &struct, 0x1B, "UInt")
		NumPut(font, &struct, 0x1F, "UChar")
		NumPut(1, &struct, 0x20, "UChar")
		NumPut(xPos, &struct, 0x21, "Float")
		NumPut(yPos, &struct, 0x25, "Float")
		NumPut(modelID, &struct, 0x29, "Short")
		NumPut(xRot, &struct, 0x2B, "Float")
		NumPut(yRot, &struct, 0x2F, "Float")
		NumPut(zRot, &struct, 0x33, "Float")
		NumPut(zoom, &struct, 0x37, "Float")
		NumPut(color1, &struct, 0x3B, "Short")
		NumPut(color2, &struct, 0x3D, "Short")
		return !__WRITERAW(hGTA, pMemory + 1024, &struct, 63) ? -1 : __CALL(hGTA, dwSAMP + 0x1AE20, [["i", dwAddress], ["i", i], ["i", pMemory + 1024], ["s", text]], false, true) ? i : -1
	}

	return -1
}

getTextDrawPos(textDrawID) {
	return textDrawID < 0 || textDrawID > 2047 || !checkHandles() ? "" : [__READMEM(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW, textDrawID * 4 + 4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS)])), [0x98B], "Float"), __READMEM(hGTA, dwAddress, [0x98F], "Float")]
}

moveTextDraw(textDrawID, xPos, yPos) {
	return textDrawID < 0 || textDrawID > 2047 || checkHandles() && __WRITEMEM(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW, textDrawID * 4 + 4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS)])), [0x98B], xPos, "Float") && __WRITEMEM(hGTA, dwAddress, [0x98F], yPos, "Float")
}

updateTextDraw(textDrawID, text) {
	if (textDrawID < 0 || textDrawID > 2047 || StrLen(text) > 800 || !checkHandles())
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW, textDrawID * 4 + 4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS)])
	return __WRITESTRING(hGTA, dwAddress, [0x0], text) 
}

destroyObject(ByRef objectID) {
	if (objectID < 0 || objectID > SAMP_MAX_OBJECTS - 1 || !checkHandles()) {
		objectID := -1
		return false
	}

	if (__CALL(hGTA, dwSAMP + 0xF3F0, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])], ["i", objectID]], false, true)) {
		objectID := -1
		return true
	}

	return false
}

attachObjectToPlayerVehicle(objectID) {
	if (!checkHandles())
		return false

	vehPtr := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])
	if (vehPtr == "" || !vehPtr)
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	if (!dwAddress)
		return false
		
	if (!__DWORD(hGTA, dwAddress, [objectID * 4 + 0x4]))
		return false

	if (__WRITEMEM(hGTA, dwAddress, [objectID * 0x4 + 0xFA4, 0x40, 0xFC], vehPtr, "UInt"))
		return true

	return false
}

createObject(modelID, xPos, yPos, zPos, xRot, yRot, zRot, drawDistance := 0) {
	if (!(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])) || __DWORD(hGTA, dwAddress, [0x0]) == SAMP_MAX_OBJECTS)
		return -1

	Loop, % SAMP_MAX_OBJECTS - 1 {
		i := SAMP_MAX_OBJECTS - A_Index
		if (__DWORD(hGTA, dwAddress, [i * 4 + 0x4]))
			continue

		return __CALL(hGTA, dwSAMP + 0xF470, [["i", dwAddress], ["i", i], ["i", modelID], ["f", xPos], ["f", yPos], ["f", zPos], ["f", xRot]
			, ["f", yRot], ["f", zRot], ["f", drawDistance]], false, true) ? i : -1
	}

	return -1
}

setObjectMaterialText(objectID, text, matIndex := 0, matSize := 90, font := "Arial", fontSize := 24, bold := 1, fontColor := 0xFFFFFFFF, backColor := 0xFF000000, align := 1) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])) || !__DWORD(hGTA, dwAddress, [objectID * 4 + 0x4]))
		return false

	return __CALL(hGTA, dwSAMP + 0xA3050, [["i", __DWORD(hGTA, dwAddress, [objectID * 0x4 + 0xFA4])], ["i", matIndex], ["s", text], ["i", matSize], ["s", font]
		, ["i", fontSize], ["i", bold], ["i", fontColor], ["i", backColor], ["i", align]], false, true)
}

editObject(objectID) {
	return __CALL(hGTA, dwSAMP + 0x6DE40, [["i", __DWORD(hGTA, dwSAMP, [0x21A0C4])], ["i", objectID], ["i", 1]], false, true)
}

editAttachedObject(slot) {
	return __CALL(hGTA, dwSAMP + 0x6DF00, [["i", __DWORD(hGTA, dwSAMP, [0x21A0C4])], ["i", slot]], false, true)
}

getObjectPos(objectID) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])) || !__DWORD(hGTA, dwAddress, [objectID * 4 + 0x4]))
		return false

	dwAddress := __DWORD(hGTA, dwAddress, [objectID * 0x4 + 0xFA4])
	xPos := __READMEM(hGTA, dwAddress, [0x10B], "Float")
	yPos := __READMEM(hGTA, dwAddress, [0x10F], "Float")
	zPos := __READMEM(hGTA, dwAddress, [0x113], "Float")

	xRot := __READMEM(hGTA, dwAddress, [0xAD], "Float")
	yRot := __READMEM(hGTA, dwAddress, [0xB1], "Float")
	zRot := __READMEM(hGTA, dwAddress, [0xB5], "Float")
	return [xPos, yPos, zPos, xRot, yRot, zRot]
}

printObjectPos(objectID) {
	pos := getObjectPos(objectID)
	if (pos == false)
		return AddChatMessage("Object not found.")

	AddChatMessage(pos[1] ", " pos[2] ", " pos[3] ", " pos[4] ", " pos[5] ", " pos[6])
	return true
}

getClosestObjectByModel(modelID) {
	if (!updateObjects())
		return ""

	dist := -1
	obj := ""
	pPos := getPlayerPos()

	for i, o in oObjects {
		if (o.MODELID != modelID)
			continue

		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			obj := o
			dist := newDist
		}
	}

	return obj
}

getClosestObjectModel() {
	if (!updateObjects())
		return ""

	dist := -1
	model := ""
	pPos := getPlayerPos()

	for i, o in oObjects {
		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			dist := newDist
			model := o.MODELID
		}
	}

	return model
}

printObjects() {
	if (!updateObjects())
		return false

	for i, o in oObjects
		AddChatMessage("Index: " o.ID ", Model: " o.MODELID ", xPos: " o.XPOS ", yPos: " o.YPOS ", zPos: " o.ZPOS)

	AddChatMessage("Object Count: " i)

	return true
}

printObjectsByModelID(modelID) {
	if (!updateObjects())
		return false

	count := 0
	for i, o in oObjects {
		if (o.MODELID == modelID) {
			count++
			AddChatMessage("ID: " o.ID ", Model: " o.MODELID ", xPos: " o.XPOS ", yPos: " o.YPOS ", zPos: " o.ZPOS)
		}
	}

	AddChatMessage("Object Count: " count)

	return true
}

isSirenAttached() {
	if (!checkHandles())
		return false

	vehPtr := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])
	if (vehPtr == "" || !vehPtr)
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	if (!dwAddress)
		return false
		
	count := __DWORD(hGTA, dwAddress, [0x0])
	Loop, % SAMP_MAX_OBJECTS {
		i := A_Index - 1
		
		if (!__DWORD(hGTA, dwAddress, [i * 4 + 0x4]))
			continue

		dwObject := __DWORD(hGTA, dwAddress, [i * 0x4 + 0xFA4])
		if (__DWORD(hGTA, dwObject, [0x4E]) == 18646 && __DWORD(hGTA, dwObject, [0x40, 0xFC]) == vehPtr)
			return true

		count--
		if (count <= 0)
			break
	}

	return false
}

createPickup(modelID, type, xPos, yPos, zPos) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PICKUP])))
		return -1

	Loop, % SAMP_MAX_PICKUPS {
		if (__READMEM(hGTA, dwAddress, [(A_Index - 1) * 4 + 0x4004], "Int") > 0)
			continue

		VarSetCapacity(struct, 20, 0)
		NumPut(modelID, &struct, 0, "UInt")
		NumPut(type, &struct, 4, "UInt")
		NumPut(xPos, &struct, 8, "Float")
		NumPut(yPos, &struct, 12, "Float")
		NumPut(zPos, &struct, 16, "Float")
		return !__WRITERAW(hGTA, pMemory + 1024, &struct, 20) ? -1 : __CALL(hGTA, dwSAMP + 0xFDC0, [["i", dwAddress], ["i", pMemory + 1024], ["i", A_Index - 1]] , false, true) ? A_Index - 1 : -1
	}

	return -1
}

getConnectionTicks() {
	return !checkHandles() ? 0 : DllCall("GetTickCount") - __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, 0x3C1], "UInt")
}

getRunningTime() {
	return !checkHandles() ? 0 : __READMEM(hGTA, 0xB610E1, [0x0], "UInt") / 4
}

deletePickup(ByRef pickupID) {
	if (pickupID < 0 || pickupID > SAMP_MAX_PICKUPS - 1 || !checkHandles())
		return false

	if (__CALL(hGTA, dwSAMP + 0xFE70, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PICKUP])], ["i", pickupID]], false, true)) {
		pickupID := -1
		return true
	}

	return false
}

getPickupModel(modelID) {
	if (!updatePickups())
		return ""

	for i, o in oPickups {
		if (o.MODELID == modelID)
			return o
	}

	return ""
}

getClosestPickupModel() {
	if (!updatePickups())
		return -1

	dist := -1
	model := 0
	pPos := getPlayerPos()

	for i, o in oPickups {
		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			dist := newDist
			model := o.MODELID
		}
	}

	return model
}

getPickupModelsInDistance(distance) {
	if (!updatePickups())
		return ""

	array := []
	pPos := getPlayerPos()

	for i, o in oPickups {
		if (getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos) < distance)
			array.Push(o.MODELID)
	}

	return array
}

isPlayerDead(playerID) {
	if (!checkHandles())
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	dwAddress2 := __DWORD(hGTA, dwAddress, [SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0, 0x2A4])
	if (!dwAddress2 || dwAddress2 == "")
		return false

	if (!(dwAddress3 := isTaskActive(dwAddress2, 401)))
		dwAddress3 := __DWORD(hGTA, dwAddress2, [0x47C])

	if (__READSTRING(hGTA, dwAddress3, [0x10], 20) == "crckdeth2")
		return true

	return false
}

getClosestDeadPlayer() {
	if (!checkHandles())
		return [-1, 0]

	dist := 0
	playerID := -1
	pos1 := getPlayerPos()

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	Loop % getMaxPlayerID() + 1 {
		dwAddress2 := __DWORD(hGTA, dwAddress, [SAMP_REMOTEPLAYERS + (A_Index - 1) * 4, 0x0, 0x0, 0x2A4])
		if (!dwAddress2 || dwAddress2 == "")
			continue

		if (!(dwAddress3 := isTaskActive(dwAddress2, 401)))
			dwAddress3 := __DWORD(hGTA, dwAddress2, [0x47C])

		if (__READSTRING(hGTA, dwAddress3, [0x10], 20) != "crckdeth2")
			continue

		dwAddress2 := __DWORD(hGTA, dwAddress2, [0x14])
		dist2 := getDistance([__READMEM(hGTA, dwAddress2, [0x30], "Float"), __READMEM(hGTA, dwAddress2, [0x34], "Float"), __READMEM(hGTA, dwAddress2, [0x38], "Float")], pos1)
		if (dist == 0 || dist2 < dist) {
			playerID := A_Index - 1
			dist := dist2
		}
	}

	return [playerID, dist]
}

getClosestPlayer() {
	if (!checkHandles())
		return [-1, 0]

	dist := 0
	playerID := -1
	pos1 := getPlayerPos()

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	Loop % getMaxPlayerID() + 1 {
		dwAddress2 := __DWORD(hGTA, dwAddress, [SAMP_REMOTEPLAYERS + (A_Index - 1) * 4, 0x0, 0x0])
		if (!dwAddress2 || dwAddress2 == "")
			continue

		dwAddress2 := __DWORD(hGTA, dwAddress2, [0x2A4, 0x14])
		if (!dwAddress2 || dwAddress2 == "")
			continue

		dist2 := getDistance([__READMEM(hGTA, dwAddress2, [0x30], "Float"), __READMEM(hGTA, dwAddress2, [0x34], "Float"), __READMEM(hGTA, dwAddress2, [0x38], "Float")], pos1)
		if (dist == 0 || dist2 < dist) {
			playerID := A_Index - 1
			dist := dist2
		}
	}

	return [playerID, dist]
}

saveGTASettings() {
	return checkHandles() && __CALL(hGTA, 0x57C660, [["i", 0xBA6748]], false, true)
}

getLyDRadioStatus() {
	return !checkHandles()? false : __READMEM(hGTA, dwSAMP + 0x11A610, [0x0], "UChar")
}

getLyDRadioText() {
	return !checkHandles()? false : __READSTRING(hGTA, dwSAMP + 0x11A400, [0x0], 256)
}

getLyDRadioStation() {
	return !checkHandles()? false : __READSTRING(hGTA, dwSAMP + 0x11A1F0, [0x0], 256)
}

setRadioVolume(volume) {
	return (volume < 0 || volume > 16 || !checkHandles()) ? false : __CALL(hGTA, 0x506DE0, [["i", 0xB6BC90], ["i", volume * 4]], false, true) && __WRITEMEM(hGTA, 0xBA6798, [0x0], volume * 4, "UChar") && saveGTASettings()
}

getRadioVolume() {
	return !checkHandles() ? false : __READMEM(hGTA, 0xBA6798, [0x0], "UChar")
}

setSFXVolume(volume) {
	return (volume < 0 || volume > 16 || !checkHandles()) ? false : __CALL(hGTA, 0x506E10, [["i", 0xB6BC90], ["i", volume * 4]], false, true) && __WRITEMEM(hGTA, 0xBA6797, [0x0], volume * 4, "UChar") && saveGTASettings()
}

getSFXVolume() {
	return !checkHandles() ? false : __READMEM(hGTA, 0xBA6797, [0x0], "UChar")
}

getDistanceToPickup(modelID) {
	if (!updatePickups())
		return -1

	dist := -1
	pPos := getPlayerPos()

	for i, o in oPickups {
		if (o.MODELID != modelID)
			continue

		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1)
			dist := newDist
	}

	return dist
}

printPickups() {
	if (!updatePickups())
		return false

	for i, o in oPickups
		AddChatMessage("ID: " o.ID ", Model: " o.MODELID ", Type: " o.TYPE ", xPos: " o.XPOS ", yPos: " o.YPOS ", zPos: " o.ZPOS)

	AddChatMessage("Pickup Count: " i)
	return true
}

updatePickups() {
	if (pickupTick + 200 > A_TickCount)
		return true

	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PICKUP])) || (pickupCount := __DWORD(hGTA, dwAddress, [0x0])) <= 0)
		return false

	oPickups := []
	Loop, % SAMP_MAX_PICKUPS {
		pickupID := __READMEM(hGTA, dwAddress, [(i := A_Index - 1) * 4 + 0x4004], "Int")
		if (pickupID < 0)
			continue

		pickupCount--
		oPickups.Push(Object("ID", pickupID, "MODELID", __READMEM(hGTA, dwAddress, [i * 0x14 + 0xF004], "Int"), "TYPE", __READMEM(hGTA, dwAddress, [i * 0x14 + 0xF008], "Int"), "XPOS", __READMEM(hGTA, dwAddress, [i * 0x14 + 0xF00C], "Float"), "YPOS", __READMEM(hGTA, dwAddress, [i * 0x14 + 0xF010], "Float"), "ZPOS", __READMEM(hGTA, dwAddress, [i * 0x14 + 0xF014], "Float")))
		if (pickupCount <= 0)
			break
	}

	pickupTick := A_TickCount
	return true
}

updateObjects() {
	if (!checkHandles())
		return false

	if (objectTick + 1000 > A_TickCount)
		return true

	oObjects := []
	objectTick := A_TickCount

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	if (!dwAddress)
		return false
	
	count := __DWORD(hGTA, dwAddress, [0x0])

	Loop, % SAMP_MAX_OBJECTS {
		i := A_Index - 1
		
		if (!__DWORD(hGTA, dwAddress, [i * 4 + 0x4]))
			continue

		dwObject := __DWORD(hGTA, dwAddress, [i * 0x4 + 0xFA4])
		oObjects.Push(Object("ID", i, "MODELID", __DWORD(hGTA, dwObject, [0x4E]), "XPOS", __READMEM(hGTA, dwObject, [0x5C], "Float"), "YPOS"
			, __READMEM(hGTA, dwObject, [0x60], "Float"), "ZPOS", __READMEM(hGTA, dwObject, [0x64], "Float")))

		count--
		if (count <= 0)
			break
	}

	return true
}

_getChatline(dwIndex) {
	if (dwIndex < 0 || dwIndex > 99 || !checkHandles())
		return false

	return __READSTRING(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR, 0x152 + 0xFC * (99 - dwIndex)], 144)
}

printObjectTexts() {
	if (!checkHandles())
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	if (!dwAddress)
		return false
	
	count := __DWORD(hGTA, dwAddress, [0x0])

	Loop, % SAMP_MAX_OBJECTS {
		i := A_Index - 1
		
		if (!__DWORD(hGTA, dwAddress, [i * 4 + 0x4]))
			continue

		dwObject := __DWORD(hGTA, dwAddress, [i * 0x4 + 0xFA4])
		string := __READSTRING(hGTA, dwObject, [0x10CB, 0x0], 256)
		if (string != "")
			AddChatMessage("ID: " i ", " string ", X: " __READMEM(hGTA, dwObject, [0x5C], "Float") ", Y: " __READMEM(hGTA, dwObject, [0x60], "Float"))

		count--
		if (count <= 0)
			break
	}

	return true
}

getTextLabelBySubstring(string) {
	if (!updateTextLabels())
		return ""

	for i, o in oTextLabels {
		if (InStr(o.TEXT, string))
			return o.TEXT
	}

	return ""
}

updateTextLabels() {
	if (!checkHandles())
		return false
	
	if (textLabelTick + 200 > A_TickCount)
		return true
	
	oTextLabels := []
	dwTextLabels := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTLABEL])
	if (!dwTextLabels)
		return false

	Loop, % SAMP_MAX_TEXTLABELS {
		i := A_Index - 1

		if (!__DWORD(hGTA, dwTextLabels, [0xE800 + i * 4]))
			continue
		
		dwAddress := __DWORD(hGTA, dwTextLabels, [i * 0x1D])
		if (!dwAddress)
			continue

		fX := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x8], "Float")
		fY := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0xC], "Float")
		fZ := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x10], "Float")
		wVehicleID := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x1B], "UShort")
		wPlayerID := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x19], "UShort")
		
		oTextLabels.Push(Object("ID", i, "TEXT", __READSTRING(hGTA, dwAddress, [0x0], 256), "XPOS", fX, "YPOS", fY, "ZPOS", fZ, "VEHICLEID", wVehicleID, "PLAYERID"
			, wPlayerID, "VISIBLE", __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x18], "UChar"), "DISTANCE", __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x14], "Float")))
	}

	textLabelTick := A_TickCount
	return true
}

updateTextLabel(textLabelID, text) {
	if (textLabelID < 0 || textLabelID > 2047 || !checkHandles())
		return false

	return __WRITESTRING(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTLABEL, textLabelID * 0x1D, 0x0], text)
}

createTextLabel(text, color, xPos, yPos, zPos, drawDistance := 46.0, testLOS := 0, playerID := 0xFFFF, vehicleID := 0xFFFF) {
	if (!checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTLABEL])))
		return -1

	Loop, % SAMP_MAX_TEXTLABELS {
		if (__DWORD(hGTA, dwAddress, [0xE800 + (SAMP_MAX_TEXTLABELS - A_Index) * 4]))
			continue

		return __CALL(hGTA, dwSAMP + 0x11C0, [["i", dwAddress], ["i", SAMP_MAX_TEXTLABELS - A_Index], ["s", text], ["i", color], ["f", xPos], ["f", yPos], ["f", zPos]
			, ["f", drawDistance], ["i", testLOS], ["i", playerID], ["i", vehicleID]], false, true) ? SAMP_MAX_TEXTLABELS - A_Index : -1
	}

	return -1
}

deleteTextLabel(ByRef textLabelID) {
	if (textLabelID < 0 || !checkHandles()) {
		textLabelID := -1
		return -1
	}

	if (__CALL(hGTA, dwSAMP + 0x12D0, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTLABEL])], ["i", textLabelID]], false, true)) {
		textLabelID := -1
		return -1
	}

	return textLabelID
}

printPlayerTextLabels() {
	if (!updateTextLabels())
		return false

	for i, o in oTextLabels {
		if (o.TEXT != "" && o.TEXT != " " && o.PLAYERID != 0xFFFF)
			addChatMessage("{FFFF00}ID: " o.ID ", Text: " o.TEXT ", " o.PLAYERID)
	}

	return true
}

printTextLabels() {
	if (!updateTextLabels())
		return false

	for i, o in oTextLabels
		AddChatMessage("{FFFF00}ID: " o.ID ", Text: " o.TEXT ", " o.XPOS ", " o.YPOS ", " o.ZPOS ", ")

	AddChatMessage("TextLabel Count: " i)
	return true
}

countLabels() {
	return !updateTextLabels() ? -1 : oTextLabels.Length()
}

getPlayerAttachedTextLabel(playerID) {
	if (!checkHandles() || !updateTextLabels())
		return false

	for i, o in oTextLabels {
		if (playerID == o.PLAYERID)
			return o
	}

	return false
}

getPlayerAttachedTextLabels(playerID) {
	if (!checkHandles() || !updateTextLabels())
		return false

	labels := []

	for i, o in oTextLabels {
		if (playerID == o.PLAYERID)
			labels.Push(o)
	}

	return labels
}

getLabelBySubstring(text := "") {
	if (!updateTextLabels())
		return 0
	
	for i, o in oTextLabels {
		if (text != "" && InStr(o.TEXT, text) == 0)
			continue

		return o
	}

	return ""
}

getNearestLabel2(text := "") {
	if (!updateTextLabels())
		return 0
	
	nearest := ""
	dist := -1
	pos1 := getPlayerPos()

	for i, o in oTextLabels {
		if (text != "" && !InStr(o.TEXT, text))
			continue

		newDist := getDistance(pos1, [o.XPOS, o.YPOS, o.ZPOS])
		if (dist == -1 || newDist < dist) {
			dist := newDist
			nearest := o
		}
	}

	return [nearest, dist]
}

getNearestLabel(text := "") {
	if (!updateTextLabels())
		return 0
	
	nearest := 0
	dist := -1
	pos1 := getPlayerPos()

	for i, o in oTextLabels {
		if (text != "" && o.TEXT != text)
			continue

		newDist := getDistance(pos1, [o.XPOS, o.YPOS, o.ZPOS])
		if (dist == -1 || newDist < dist) {
			dist := newDist
			nearest := o
		}
	}

	return nearest
}

getNearestLabelDistance(text := "") {
	if(!updateTextLabels())
		return 0
	
	nearest := 0
	dist := 5000
	pos1 := getPlayerPos()

	For i, o in oTextLabels
	{
		if (text != "" && !InStr(o.TEXT, text))
			continue

		pos2 := [o.XPOS, o.YPOS, o.ZPOS]

		dist2 := getDistance(pos1, pos2)

		if (dist2 < dist) {
			dist := dist2
			nearest := o
		}
	}

	return [nearest, dist]
}

createBlip(dwIcon, fX, fY) {
	if (!checkHandles())
		return ""

	dwReturn := __INJECT(hGTA, [["NOP"]
		, ["push", [3, "Int"]]
		, ["push", [0, "Int"]]
		, ["push", [0.0, "Float"]]
		, ["push", [fY, "Float"]]
		, ["push", [fX, "Float"]]
		, ["push", [4, "Int"]]
		, ["call", [0x583820, "Int"]]
		, ["mov address, eax", [pMemory, "Int"]]
		, ["push", [dwIcon, "Int"]]
		, ["push eax"]
		, ["call", [0x583D70, "Int"]]
		, ["add esp", [0x20, "UChar"]]
		, ["ret"]])

	return dwReturn
}

clearBlip(dwBlip) {
	if (!checkHandles() || !dwBlip)
		return false

	return __CALL(hGTA, 0x587CE0, [["i", dwBlip]])
}

getBlipPosByIconID(iconID) {
	if (!checkHandles())
		return Object("ID", -1)

	Loop % GTA_BLIP_COUNT {
		currentElement := GTA_BLIP_POOL + (A_Index - 1) * GTA_BLIP_ELEMENT_SIZE
		if (__READMEM(hGTA, currentElement + GTA_BLIP_ID_OFFSET, [0x0], "UChar") != iconID)
			continue

		xPos := __READMEM(hGTA, currentElement + GTA_BLIP_X_OFFSET, [0x0], "Float")
		yPos := __READMEM(hGTA, currentElement + GTA_BLIP_Y_OFFSET, [0x0], "Float")
		zPos := __READMEM(hGTA, currentElement + GTA_BLIP_Z_OFFSET, [0x0], "Float")
		return Object("ID", A_Index - 1, "XPOS", xpos, "YPOS", yPos, "ZPOS", zPos)
	}

	return Object("ID", -1)
}

printMapIcons() {
	if (!checkHandles())
		return false

	Loop % GTA_BLIP_COUNT {
		currentElement := GTA_BLIP_POOL + (A_Index - 1) * GTA_BLIP_ELEMENT_SIZE

		style := __READMEM(hGTA, currentElement + GTA_BLIP_STYLE_OFFSET, [0x0], "UChar")
		id := __READMEM(hGTA, currentElement + GTA_BLIP_ID_OFFSET, [0x0], "UChar")
		xPos := __READMEM(hGTA, currentElement + GTA_BLIP_X_OFFSET, [0x0], "Float")
		yPos := __READMEM(hGTA, currentElement + GTA_BLIP_Y_OFFSET, [0x0], "Float")
		zPos := __READMEM(hGTA, currentElement + GTA_BLIP_Z_OFFSET, [0x0], "Float")
		color := intToHex(__READMEM(hGTA, currentElement + GTA_BLIP_COLOR_OFFSET, [0x0], "UInt"))

		if (id != 0)
			AddChatMessage("Icon ID: " id ", Style: " style ", Pos: " xPos " " yPos " " zPos ", Color: " color)
	}

	return true
}

getVehicleAddress(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4])
}

getVehicleModelID(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? false : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x22], "UShort")
}

getVehicleLockState(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x4F8], "UShort") == 2
}

getVehicleEngineState(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x428], "UShort") & 16 ? true : false
}

getVehicleLightState(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x428], "UShort") & 64 ? true : false
}

getVehicleSirenState(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x1F7], "UShort")
}

getVehicleDriver(vehicleID) {
	if (vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES || !checkHandles() || !updatePlayers())
		return ""

	dwPed := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4, 0x460])
	if (dwPed == 0x0 || dwPed == "")
		return ""

	if (dwPed == __DWORD(hGTA, GTA_CPED_PTR, [0x0]))
		return Object("ID", getID(), "NAME", getUserName())

	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])

	for i, o in oPlayers {
		if (__DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + i * 4, 0x0, 0x0, 0x2A4]) == dwPed)
			return Object("ID", i, "NAME", o)
	}

	return ""
}

getVehicleDriverByPtr(dwVehiclePtr) {
	if (dwVehiclePtr == 0x0 || dwVehiclePtr == "" | !checkHandles() || !updatePlayers())
		return ""

	dwPed := __DWORD(hGTA, dwVehiclePtr, [0x460])
	if (dwPed == 0x0 || dwPed == "")
		return ""

	if (dwPed == __DWORD(hGTA, GTA_CPED_PTR, [0x0]))
		return Object("ID", getID(), "NAME", getUserName())

	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])

	for i, o in oPlayers {
		if (__DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + i * 4, 0x0, 0x0, 0x2A4]) == dwPed)
			return Object("ID", i, "NAME", o)
	}

	return ""
}

getPlayerPosition(playerID) {
	if (playerID < 0 || !checkHandles() || playerID > getMaxPlayerID() || playerID == getID())
		return ""

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x0])
	if (!dwAddress || dwAddress == "")
		return ""

	dwAddress := __DWORD(hGTA, dwAddress, [0x2A4, 0x14])
	return [__READMEM(hGTA, dwAddress, [0x30], "Float"), __READMEM(hGTA, dwAddress, [0x34], "Float"), __READMEM(hGTA, dwAddress, [0x38], "Float")]
}

getClosestVehicleDriver(modelID := -1, skipOwn := 1) {
	if ((modelID < 400 && modelID != -1) || modelID > 611 || !checkHandles() || !updateVehicles())
		return ""

	nearest := ""
	dist := 10000.0
	pos1 := getPlayerPos()
	vehPTR := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])
	closestDriver := ""

	playerID := getID()
	for i, o in oVehicles {
		if (modelID != -1 && modelID != o.MODELID || (skipOwn == 1 && o.PTR == vehPTR))
			continue

		dist2 := getDistance(pos1, getVehiclePosByPtr(o.PTR))
		if (dist2 < dist && (driver := getVehicleDriverByPtr(o.PTR)) != "") {
			if (skipOwn == 2 && driver.ID == playerID)
				continue

			dist := dist2
			nearest := o
			closestDriver := driver
		}
	}
	
	return [closestDriver, dist]
}

getVehiclePassengers(vehicleID) {
	if (vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES || !checkHandles() || !updatePlayers())
		return ""

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x4FB4 + vehicleID * 0x4])
	if (dwAddress == 0x0 || dwAddress == "")
		return ""

	dwCPedPtr := __DWORD(hGTA, GTA_CPED_PTR, [0x0])
	passengers := []
	Loop, 10 {
		if ((dwPED := __DWORD(hGTA, dwAddress + 0x45C, [4 * A_Index])) == 0x0)
			continue

		if (dwCPedPtr == dwPED)
			passengers.Push(Object("SEAT", A_Index - 1, "PED", dwPED, "ID", getID(), "NAME", getUsername()))
		else
			passengers.Push(Object("SEAT", A_Index - 1, "PED", dwPED, "ID", 0xFFFF, "NAME", ""))
	}

	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	for i, o in oPlayers {
		for j, k in passengers {
			if (__DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + i * 4, 0x0, 0x0, 0x2A4]) != k.PED)
				continue

			k.ID := i
			k.NAME := o
		}
	}

	return passengers
}

getMyVehiclePassengers() {
	if (!checkHandles() || !updatePlayers())
		return ""

	dwAddress := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])
	if (!dwAddress)
		return ""

	dwCPedPtr := __DWORD(hGTA, GTA_CPED_PTR, [0x0])
	passengers := []
	Loop, 10 {
		if ((dwPED := __DWORD(hGTA, dwAddress + 0x45C, [4 * A_Index])) == 0x0)
			continue

		if (dwCPedPtr == dwPED)
			passengers.Push(Object("SEAT", A_Index - 1, "PED", dwPED, "ID", getID(), "NAME", getUsername()))
		else
			passengers.Push(Object("SEAT", A_Index - 1, "PED", dwPED, "ID", 0xFFFF, "NAME", ""))
	}

	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	for i, o in oPlayers {
		for j, k in passengers {
			if (__DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + i * 4, 0x0, 0x0, 0x2A4]) != k.PED)
				continue

			k.ID := i
			k.NAME := o
		}
	}

	return passengers
}

updateVehicles() {
	if (!checkHandles())
		return false

	if (vehicleTick + 1000 > A_TickCount)
		return true

	oVehicles := []
	stVehiclePool := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE])
	if (!stVehiclePool)
		return false

	vehicleCount := __DWORD(hGTA, stVehiclePool, [0x0])
	Loop, % SAMP_MAX_VEHICLES {
		if (!__DWORD(hGTA, stVehiclePool, [0x3074 + (A_Index - 1) * 0x4]))
			continue

		vehPtr := __DWORD(hGTA, stVehiclePool, [0x4FB4 + (A_Index - 1) * 0x4])
		if (!vehPtr)
			continue

		oVehicles.Push(Object("ID", A_Index - 1, "PTR", vehPTR, "MODELID", __READMEM(hGTA, vehPtr, [0x22], "UShort")))

		vehicleCount--
		if (vehicleCount < 1)
			break
	}

	vehicleTick := A_TickCount
	return true
}

getVehiclePosByPtr(dwVehPtr) {
	if (!dwVehPtr || !checkHandles())
		return false

	dwAddress := __DWORD(hGTA, dwVehPtr, [0x14])
	if (!dwAddress)
		return false

	return [__READMEM(hGTA, dwAddress, [0x30], "Float"), __READMEM(hGTA, dwAddress, [0x34], "Float"), __READMEM(hGTA, dwAddress, [0x38], "Float")]
}

getClosestVehicle(modelID := -1, skipOwn := true) {
	if ((modelID < 400 && modelID != -1) || modelID > 611 || !checkHandles() || !updateVehicles())
		return ""

	nearest := ""
	dist := 10000.0
	pos1 := getPlayerPos()
	vehPTR := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])

	for i, o in oVehicles {
		if (modelID != -1 && modelID != o.MODELID || (skipOwn && o.PTR == vehPTR))
			continue

		dist2 := getDistance(pos1, getVehiclePosByPtr(o.PTR))
		if (dist2 < dist) {
			dist := dist2
			nearest := o
		}
	}
	
	return nearest
}

getPlayerSkin() {
	return !checkHandles() ? false : __READMEM(hGTA, GTA_CPED_PTR, [0x0, 0x22], "UShort")
}

getSkinID(dwID) {
	if (!checkHandles() || dwID > SAMP_MAX_PLAYERS || dwID < 0)
		return -1

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + dwID * 4])
	if (!dwAddress)
		return -1

	dwAddress := __DWORD(hGTA, dwAddress, [0x0])
	if (!dwAddress)
		return -1

	dwAddress := __DWORD(hGTA, dwAddress, [0x0])
	if (!dwAddress)
		return -1

	dwAddress := __DWORD(hGTA, dwAddress, [0x2A4])
	if (!dwAddress)
		return -1

	skin := __READMEM(hGTA, dwAddress, [0x22], "UShort")
	if (ErrorLevel)
		return -1

	return skin
}

setPlayerSkin(skinID) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x9A590, [["i", __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8])], ["i", skinID]], false, true)
}

getPlayerPos() {
	return !checkHandles() ? "" : [__READMEM(hGTA, 0xB6F2E4, [0x0], "Float"), __READMEM(hGTA, 0xB6F2E8, [0x0], "Float"), __READMEM(hGTA, 0xB6F2EC, [0x0], "Float")]
}

getDistance(pos1, pos2) {
	return !pos1 || pos1 == "" || !pos2 || pos2 == "" ? -1 : Sqrt((pos1[1] - pos2[1]) * (pos1[1] - pos2[1]) + (pos1[2] - pos2[2]) * (pos1[2] - pos2[2]) + (pos1[3] - pos2[3]) * (pos1[3] - pos2[3]))
}

isKillInfoEnabled() {
	return checkHandles() && __DWORD(hGTA, dwSAMP, [SAMP_KILL_INFO_PTR, 0x0])
}

toggleKillInfoEnabled(toggle := true) {
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [SAMP_KILL_INFO_PTR, 0x0], toggle ? 1 : 0, "UInt")
}

getKilledPlayers(bReset := false) {
	if (!checkHandles())
		return ""

	kills := []

	dwPlayers := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER])
	dwLocalPED := __DWORD(hGTA, GTA_CPED_PTR, [0x0])

	Loop % getMaxPlayerID() + 1
	{
		dwRemoteplayer := __DWORD(hGTA, dwPlayers, [SAMP_REMOTEPLAYERS + (A_Index - 1) * 4])
		if (!dwRemoteplayer)
			continue

		fHealth := __READMEM(hGTA, dwRemoteplayer, [0x0, 0x1BC], "Float")
		if (fHealth > 0)
			continue

		dwSAMPActor := __DWORD(hGTA, dwRemoteplayer, [0x0, 0x0])
		if (!dwSAMPActor)
			continue

		dwPED := __DWORD(hGTA, dwSAMPActor, [0x2A4])
		if (!dwPED)
			continue

		dwMurderer := __DWORD(hGTA, dwPED, [0x764])
		if (!dwMurderer || dwLocalPED != dwMurderer)
			continue
		
		if (bReset)
			__WRITEMEM(hGTA, dwPED, [0x764], 0, "UInt")

		kills.Push(Object("ID", A_Index - 1, "WEAPON", __DWORD(hGTA, dwPED, [0x760])))
	}

	return kills
}

getKillEntry(index) {
	if (index < 0 || index > 4 || !checkHandles())
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_KILL_INFO_PTR]) + 0x4
	sVictim := __READSTRING(hGTA, dwAddress, [index * 0x3B], 25)
	sKiller := __READSTRING(hGTA, dwAddress, [index * 0x3B + 0x19], 25)
	dwVictimColor := __READMEM(hGTA, dwAddress, [index * 0x3B + 0x32], "UInt")
	dwKillerColor := __READMEM(hGTA, dwAddress, [index * 0x3B + 0x36], "UInt")
	bReason := __READMEM(hGTA, dwAddress, [index * 0x3B + 0x3A], "UChar")

	return Object("VICTIM", sVictim, "KILLER", sKiller, "VCOLOR", dwVictimColor, "KCOLOR", dwKillerColor, "REASON", bReason)
}

addKillEntry(victimName := " ", killerName := " ", victimColor := 0xFFFFFFFF, killerColor := 0xFFFFFFFF, reason := 255) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x66930, [["i", __DWORD(hGTA, dwSAMP, [SAMP_KILL_INFO_PTR])], ["s", victimName], ["s", killerName], ["i", victimColor], ["i", killerColor], ["i", reason]], false, true)
}

playAudioStream(url) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x62DA0, [["s", url], ["i", 0], ["i", 0], ["i", 0], ["i", 0], ["i", 0]], false)
}

stopAudioStream() {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x629A0, [["i", 1]], false)
}

playSound(soundID) {
	return checkHandles() && __CALL(hGTA, 0x506EA0, [["i", 0xB6BC90], ["i", soundID], ["i", 0], ["f", 1.0]], false, true)
}

playAudioEvent(eventID) {
	if (!checkHandles())
		return false

	VarSetCapacity(buf, 12, 0)
	NumPut(0, buf, 0, "Float")
	NumPut(0, buf, 4, "Float")
	NumPut(0, buf, 8, "Float")
	if (!__WRITERAW(hGTA, pMemory + 20, &buf, 12))
		return false

	return __CALL(hGTA, 0x507340, [["i", pMemory + 20], ["i", eventID]], false, false)
}

addDelimiters(value, delimiter := ".") {
	return RegExReplace(Round(value), "\G\d+?(?=(\d{3})+(?:\D|$))", "$0" delimiter)
}

; // ###### MEMORY FUNCTIONS ######

checkHandles() {
	return !refreshGTA() || !refreshSAMP() || !refreshMemory() ? false : true
}

refreshGTA() {
	if (!(newPID := getPID("GTA:SA:MP"))) {
		if (hGTA) {
			virtualFreeEx(hGTA, pMemory, 0, 0x8000)
			closeProcess(hGTA)
		}

		dwGTAPID := 0, hGTA := 0x0, dwSAMP := 0x0, pMemory := 0x0
		return false
	}
	
	if (!hGTA || dwGTAPID != newPID) {
		if (!(hGTA := openProcess(newPID))) {
			dwGTAPID := 0, hGTA := 0x0, dwSAMP := 0x0, pMemory := 0x0
			return false
		}

		dwGTAPID := newPID, dwSAMP := 0x0, pMemory := 0x0
	}

	return true
}

refreshSAMP() {
	return dwSAMP ? true : (dwSAMP := getModuleBaseAddress("samp.dll", hGTA))
}

refreshMemory() {
	if (!pMemory) {
		pMemory := virtualAllocEx(hGTA, 6384, 0x1000 | 0x2000, 0x40)
		if (ErrorLevel) {
			pMemory := 0x0
			return false
		}

		pInjectFunc := pMemory + 5120
		pDetours	:= pInjectFunc + 1024
	}

	return true
}

queryPerformance() {
    Static QPCLAST, QPCNOW, QPCFREQ 

    if not QPCFREQ 
        if not DllCall("QueryPerformanceFrequency", "Int64 *", QPCFREQ) 
            return "Fail QPF" 

    QPCLAST=%QPCNOW% 
    if not DllCall("QueryPerformanceCounter", "Int64 *", QPCNOW) 
        return "Fail QPC" 

    return (QPCNOW-QPCLAST)/QPCFREQ 
}

AddZone(sName, x1, y1, z1, x2, y2, z2) {
	global
	zone%nZone%_name := sName
	zone%nZone%_x1 := x1
	zone%nZone%_y1 := y1
	zone%nZone%_z1 := z1
	zone%nZone%_x2 := x2
	zone%nZone%_y2 := y2
	zone%nZone%_z2 := z2
	nZone := nZone + 1
}

getTownNumber() {
	if (!checkHandles())
		return false

	pos := getPlayerPos()
	VarSetCapacity(struct, 12, 0)
	NumPut(pos[1], &struct, 0, "Float")
	NumPut(pos[2], &struct, 4, "Float")
	NumPut(pos[3], &struct, 8, "Float")

	return !__WRITERAW(hGTA, pMemory + 1024, &struct, 63) ? -1 : __CALL(hGTA, 0x572300, [["i", pMemory + 1024]], true, false, true)
}

AddCity(sName, x1, y1, z1, x2, y2, z2) {
	global
	city%nCity%_name := sName
	city%nCity%_x1 := x1
	city%nCity%_y1 := y1
	city%nCity%_z1 := z1
	city%nCity%_x2 := x2
	city%nCity%_y2 := y2
	city%nCity%_z2 := z2
	nCity := nCity + 1
}

initZonesAndCities() {
	AddCity("Las Venturas", 685.0, 476.093, -500.0, 3000.0, 3000.0, 500.0)
	AddCity("San Fierro", -3000.0, -742.306, -500.0, -1270.53, 1530.24, 500.0)
	AddCity("San Fierro", -1270.53, -402.481, -500.0, -1038.45, 832.495, 500.0)
	AddCity("San Fierro", -1038.45, -145.539, -500.0, -897.546, 376.632, 500.0)
	AddCity("Los Santos", 480.0, -3000.0, -500.0, 3000.0, -850.0, 500.0)
	AddCity("Los Santos", 80.0, -2101.61, -500.0, 1075.0, -1239.61, 500.0)
	AddCity("Tierra Robada", -1213.91, 596.349, -242.99, -480.539, 1659.68, 900.0)
	AddCity("Red County", -1213.91, -768.027, -242.99, 2997.06, 596.349, 900.0)
	AddCity("Flint County", -1213.91, -2892.97, -242.99, 44.6147, -768.027, 900.0)
	AddCity("Whetstone", -2997.47, -2892.97, -242.99, -1213.91, -1115.58, 900.0)
	
	AddZone("Avispa Country Club", -2667.810, -302.135, -28.831, -2646.400, -262.320, 71.169)
	AddZone("Easter Bay Airport", -1315.420, -405.388, 15.406, -1264.400, -209.543, 25.406)
	AddZone("Avispa Country Club", -2550.040, -355.493, 0.000, -2470.040, -318.493, 39.700)
	AddZone("Easter Bay Airport", -1490.330, -209.543, 15.406, -1264.400, -148.388, 25.406)
	AddZone("Garcia", -2395.140, -222.589, -5.3, -2354.090, -204.792, 200.000)
	AddZone("Shady Cabin", -1632.830, -2263.440, -3.0, -1601.330, -2231.790, 200.000)
	AddZone("East Los Santos", 2381.680, -1494.030, -89.084, 2421.030, -1454.350, 110.916)
	AddZone("LVA Freight Depot", 1236.630, 1163.410, -89.084, 1277.050, 1203.280, 110.916)
	AddZone("Blackfield Intersection", 1277.050, 1044.690, -89.084, 1315.350, 1087.630, 110.916)
	AddZone("Avispa Country Club", -2470.040, -355.493, 0.000, -2270.040, -318.493, 46.100)
	AddZone("Temple", 1252.330, -926.999, -89.084, 1357.000, -910.170, 110.916)
	AddZone("Unity Station", 1692.620, -1971.800, -20.492, 1812.620, -1932.800, 79.508)
	AddZone("LVA Freight Depot", 1315.350, 1044.690, -89.084, 1375.600, 1087.630, 110.916)
	AddZone("Los Flores", 2581.730, -1454.350, -89.084, 2632.830, -1393.420, 110.916)
	AddZone("Starfish Casino", 2437.390, 1858.100, -39.084, 2495.090, 1970.850, 60.916)
	AddZone("Easter Bay Chemicals", -1132.820, -787.391, 0.000, -956.476, -768.027, 200.000)
	AddZone("Downtown Los Santos", 1370.850, -1170.870, -89.084, 1463.900, -1130.850, 110.916)
	AddZone("Esplanade East", -1620.300, 1176.520, -4.5, -1580.010, 1274.260, 200.000)
	AddZone("Market Station", 787.461, -1410.930, -34.126, 866.009, -1310.210, 65.874)
	AddZone("Linden Station", 2811.250, 1229.590, -39.594, 2861.250, 1407.590, 60.406)
	AddZone("Montgomery Intersection", 1582.440, 347.457, 0.000, 1664.620, 401.750, 200.000)
	AddZone("Frederick Bridge", 2759.250, 296.501, 0.000, 2774.250, 594.757, 200.000)
	AddZone("Yellow Bell Station", 1377.480, 2600.430, -21.926, 1492.450, 2687.360, 78.074)
	AddZone("Downtown Los Santos", 1507.510, -1385.210, 110.916, 1582.550, -1325.310, 335.916)
	AddZone("Jefferson", 2185.330, -1210.740, -89.084, 2281.450, -1154.590, 110.916)
	AddZone("Mulholland", 1318.130, -910.170, -89.084, 1357.000, -768.027, 110.916)
	AddZone("Avispa Country Club", -2361.510, -417.199, 0.000, -2270.040, -355.493, 200.000)
	AddZone("Jefferson", 1996.910, -1449.670, -89.084, 2056.860, -1350.720, 110.916)
	AddZone("Julius Thruway West", 1236.630, 2142.860, -89.084, 1297.470, 2243.230, 110.916)
	AddZone("Jefferson", 2124.660, -1494.030, -89.084, 2266.210, -1449.670, 110.916)
	AddZone("Julius Thruway North", 1848.400, 2478.490, -89.084, 1938.800, 2553.490, 110.916)
	AddZone("Rodeo", 422.680, -1570.200, -89.084, 466.223, -1406.050, 110.916)
	AddZone("Cranberry Station", -2007.830, 56.306, 0.000, -1922.000, 224.782, 100.000)
	AddZone("Downtown Los Santos", 1391.050, -1026.330, -89.084, 1463.900, -926.999, 110.916)
	AddZone("Redsands West", 1704.590, 2243.230, -89.084, 1777.390, 2342.830, 110.916)
	AddZone("Little Mexico", 1758.900, -1722.260, -89.084, 1812.620, -1577.590, 110.916)
	AddZone("Blackfield Intersection", 1375.600, 823.228, -89.084, 1457.390, 919.447, 110.916)
	AddZone("Los Santos International", 1974.630, -2394.330, -39.084, 2089.000, -2256.590, 60.916)
	AddZone("Beacon Hill", -399.633, -1075.520, -1.489, -319.033, -977.516, 198.511)
	AddZone("Rodeo", 334.503, -1501.950, -89.084, 422.680, -1406.050, 110.916)
	AddZone("Richman", 225.165, -1369.620, -89.084, 334.503, -1292.070, 110.916)
	AddZone("Downtown Los Santos", 1724.760, -1250.900, -89.084, 1812.620, -1150.870, 110.916)
	AddZone("The Strip", 2027.400, 1703.230, -89.084, 2137.400, 1783.230, 110.916)
	AddZone("Downtown Los Santos", 1378.330, -1130.850, -89.084, 1463.900, -1026.330, 110.916)
	AddZone("Blackfield Intersection", 1197.390, 1044.690, -89.084, 1277.050, 1163.390, 110.916)
	AddZone("Conference Center", 1073.220, -1842.270, -89.084, 1323.900, -1804.210, 110.916)
	AddZone("Montgomery", 1451.400, 347.457, -6.1, 1582.440, 420.802, 200.000)
	AddZone("Foster Valley", -2270.040, -430.276, -1.2, -2178.690, -324.114, 200.000)
	AddZone("Blackfield Chapel", 1325.600, 596.349, -89.084, 1375.600, 795.010, 110.916)
	AddZone("Los Santos International", 2051.630, -2597.260, -39.084, 2152.450, -2394.330, 60.916)
	AddZone("Mulholland", 1096.470, -910.170, -89.084, 1169.130, -768.027, 110.916)
	AddZone("Yellow Bell Gol Course", 1457.460, 2723.230, -89.084, 1534.560, 2863.230, 110.916)
	AddZone("The Strip", 2027.400, 1783.230, -89.084, 2162.390, 1863.230, 110.916)
	AddZone("Jefferson", 2056.860, -1210.740, -89.084, 2185.330, -1126.320, 110.916)
	AddZone("Mulholland", 952.604, -937.184, -89.084, 1096.470, -860.619, 110.916)
	AddZone("Aldea Malvada", -1372.140, 2498.520, 0.000, -1277.590, 2615.350, 200.000)
	AddZone("Las Colinas", 2126.860, -1126.320, -89.084, 2185.330, -934.489, 110.916)
	AddZone("Las Colinas", 1994.330, -1100.820, -89.084, 2056.860, -920.815, 110.916)
	AddZone("Richman", 647.557, -954.662, -89.084, 768.694, -860.619, 110.916)
	AddZone("LVA Freight Depot", 1277.050, 1087.630, -89.084, 1375.600, 1203.280, 110.916)
	AddZone("Julius Thruway North", 1377.390, 2433.230, -89.084, 1534.560, 2507.230, 110.916)
	AddZone("Willowfield", 2201.820, -2095.000, -89.084, 2324.000, -1989.900, 110.916)
	AddZone("Julius Thruway North", 1704.590, 2342.830, -89.084, 1848.400, 2433.230, 110.916)
	AddZone("Temple", 1252.330, -1130.850, -89.084, 1378.330, -1026.330, 110.916)
	AddZone("Little Mexico", 1701.900, -1842.270, -89.084, 1812.620, -1722.260, 110.916)
	AddZone("Queens", -2411.220, 373.539, 0.000, -2253.540, 458.411, 200.000)
	AddZone("Las Venturas Airport", 1515.810, 1586.400, -12.500, 1729.950, 1714.560, 87.500)
	AddZone("Richman", 225.165, -1292.070, -89.084, 466.223, -1235.070, 110.916)
	AddZone("Temple", 1252.330, -1026.330, -89.084, 1391.050, -926.999, 110.916)
	AddZone("East Los Santos", 2266.260, -1494.030, -89.084, 2381.680, -1372.040, 110.916)
	AddZone("Julius Thruway East", 2623.180, 943.235, -89.084, 2749.900, 1055.960, 110.916)
	AddZone("Willowfield", 2541.700, -1941.400, -89.084, 2703.580, -1852.870, 110.916)
	AddZone("Las Colinas", 2056.860, -1126.320, -89.084, 2126.860, -920.815, 110.916)
	AddZone("Julius Thruway East", 2625.160, 2202.760, -89.084, 2685.160, 2442.550, 110.916)
	AddZone("Rodeo", 225.165, -1501.950, -89.084, 334.503, -1369.620, 110.916)
	AddZone("Las Brujas", -365.167, 2123.010, -3.0, -208.570, 2217.680, 200.000)
	AddZone("Julius Thruway East", 2536.430, 2442.550, -89.084, 2685.160, 2542.550, 110.916)
	AddZone("Rodeo", 334.503, -1406.050, -89.084, 466.223, -1292.070, 110.916)
	AddZone("Vinewood", 647.557, -1227.280, -89.084, 787.461, -1118.280, 110.916)
	AddZone("Rodeo", 422.680, -1684.650, -89.084, 558.099, -1570.200, 110.916)
	AddZone("Julius Thruway North", 2498.210, 2542.550, -89.084, 2685.160, 2626.550, 110.916)
	AddZone("Downtown Los Santos", 1724.760, -1430.870, -89.084, 1812.620, -1250.900, 110.916)
	AddZone("Rodeo", 225.165, -1684.650, -89.084, 312.803, -1501.950, 110.916)
	AddZone("Jefferson", 2056.860, -1449.670, -89.084, 2266.210, -1372.040, 110.916)
	AddZone("Hampton Barns", 603.035, 264.312, 0.000, 761.994, 366.572, 200.000)
	AddZone("Temple", 1096.470, -1130.840, -89.084, 1252.330, -1026.330, 110.916)
	AddZone("Kincaid Bridge", -1087.930, 855.370, -89.084, -961.950, 986.281, 110.916)
	AddZone("Verona Beach", 1046.150, -1722.260, -89.084, 1161.520, -1577.590, 110.916)
	AddZone("Commerce", 1323.900, -1722.260, -89.084, 1440.900, -1577.590, 110.916)
	AddZone("Mulholland", 1357.000, -926.999, -89.084, 1463.900, -768.027, 110.916)
	AddZone("Rodeo", 466.223, -1570.200, -89.084, 558.099, -1385.070, 110.916)
	AddZone("Mulholland", 911.802, -860.619, -89.084, 1096.470, -768.027, 110.916)
	AddZone("Mulholland", 768.694, -954.662, -89.084, 952.604, -860.619, 110.916)
	AddZone("Julius Thruway South", 2377.390, 788.894, -89.084, 2537.390, 897.901, 110.916)
	AddZone("Idlewood", 1812.620, -1852.870, -89.084, 1971.660, -1742.310, 110.916)
	AddZone("Ocean Docks", 2089.000, -2394.330, -89.084, 2201.820, -2235.840, 110.916)
	AddZone("Commerce", 1370.850, -1577.590, -89.084, 1463.900, -1384.950, 110.916)
	AddZone("Julius Thruway North", 2121.400, 2508.230, -89.084, 2237.400, 2663.170, 110.916)
	AddZone("Temple", 1096.470, -1026.330, -89.084, 1252.330, -910.170, 110.916)
	AddZone("Glen Park", 1812.620, -1449.670, -89.084, 1996.910, -1350.720, 110.916)
	AddZone("Easter Bay Airport", -1242.980, -50.096, 0.000, -1213.910, 578.396, 200.000)
	AddZone("Martin Bridge", -222.179, 293.324, 0.000, -122.126, 476.465, 200.000)
	AddZone("The Strip", 2106.700, 1863.230, -89.084, 2162.390, 2202.760, 110.916)
	AddZone("Willowfield", 2541.700, -2059.230, -89.084, 2703.580, -1941.400, 110.916)
	AddZone("Marina", 807.922, -1577.590, -89.084, 926.922, -1416.250, 110.916)
	AddZone("Las Venturas Airport", 1457.370, 1143.210, -89.084, 1777.400, 1203.280, 110.916)
	AddZone("Idlewood", 1812.620, -1742.310, -89.084, 1951.660, -1602.310, 110.916)
	AddZone("Esplanade East", -1580.010, 1025.980, -6.1, -1499.890, 1274.260, 200.000)
	AddZone("Downtown Los Santos", 1370.850, -1384.950, -89.084, 1463.900, -1170.870, 110.916)
	AddZone("The Mako Span", 1664.620, 401.750, 0.000, 1785.140, 567.203, 200.000)
	AddZone("Rodeo", 312.803, -1684.650, -89.084, 422.680, -1501.950, 110.916)
	AddZone("Pershing Square", 1440.900, -1722.260, -89.084, 1583.500, -1577.590, 110.916)
	AddZone("Mulholland", 687.802, -860.619, -89.084, 911.802, -768.027, 110.916)
	AddZone("Gant Bridge", -2741.070, 1490.470, -6.1, -2616.400, 1659.680, 200.000)
	AddZone("Las Colinas", 2185.330, -1154.590, -89.084, 2281.450, -934.489, 110.916)
	AddZone("Mulholland", 1169.130, -910.170, -89.084, 1318.130, -768.027, 110.916)
	AddZone("Julius Thruway North", 1938.800, 2508.230, -89.084, 2121.400, 2624.230, 110.916)
	AddZone("Commerce", 1667.960, -1577.590, -89.084, 1812.620, -1430.870, 110.916)
	AddZone("Rodeo", 72.648, -1544.170, -89.084, 225.165, -1404.970, 110.916)
	AddZone("Roca Escalante", 2536.430, 2202.760, -89.084, 2625.160, 2442.550, 110.916)
	AddZone("Rodeo", 72.648, -1684.650, -89.084, 225.165, -1544.170, 110.916)
	AddZone("Market", 952.663, -1310.210, -89.084, 1072.660, -1130.850, 110.916)
	AddZone("Las Colinas", 2632.740, -1135.040, -89.084, 2747.740, -945.035, 110.916)
	AddZone("Mulholland", 861.085, -674.885, -89.084, 1156.550, -600.896, 110.916)
	AddZone("King's", -2253.540, 373.539, -9.1, -1993.280, 458.411, 200.000)
	AddZone("Redsands East", 1848.400, 2342.830, -89.084, 2011.940, 2478.490, 110.916)
	AddZone("Downtown", -1580.010, 744.267, -6.1, -1499.890, 1025.980, 200.000)
	AddZone("Conference Center", 1046.150, -1804.210, -89.084, 1323.900, -1722.260, 110.916)
	AddZone("Richman", 647.557, -1118.280, -89.084, 787.461, -954.662, 110.916)
	AddZone("Ocean Flats", -2994.490, 277.411, -9.1, -2867.850, 458.411, 200.000)
	AddZone("Greenglass College", 964.391, 930.890, -89.084, 1166.530, 1044.690, 110.916)
	AddZone("Glen Park", 1812.620, -1100.820, -89.084, 1994.330, -973.380, 110.916)
	AddZone("LVA Freight Depot", 1375.600, 919.447, -89.084, 1457.370, 1203.280, 110.916)
	AddZone("Regular Tom", -405.770, 1712.860, -3.0, -276.719, 1892.750, 200.000)
	AddZone("Verona Beach", 1161.520, -1722.260, -89.084, 1323.900, -1577.590, 110.916)
	AddZone("East Los Santos", 2281.450, -1372.040, -89.084, 2381.680, -1135.040, 110.916)
	AddZone("Caligula's Palace", 2137.400, 1703.230, -89.084, 2437.390, 1783.230, 110.916)
	AddZone("Idlewood", 1951.660, -1742.310, -89.084, 2124.660, -1602.310, 110.916)
	AddZone("Pilgrim", 2624.400, 1383.230, -89.084, 2685.160, 1783.230, 110.916)
	AddZone("Idlewood", 2124.660, -1742.310, -89.084, 2222.560, -1494.030, 110.916)
	AddZone("Queens", -2533.040, 458.411, 0.000, -2329.310, 578.396, 200.000)
	AddZone("Downtown", -1871.720, 1176.420, -4.5, -1620.300, 1274.260, 200.000)
	AddZone("Commerce", 1583.500, -1722.260, -89.084, 1758.900, -1577.590, 110.916)
	AddZone("East Los Santos", 2381.680, -1454.350, -89.084, 2462.130, -1135.040, 110.916)
	AddZone("Marina", 647.712, -1577.590, -89.084, 807.922, -1416.250, 110.916)
	AddZone("Richman", 72.648, -1404.970, -89.084, 225.165, -1235.070, 110.916)
	AddZone("Vinewood", 647.712, -1416.250, -89.084, 787.461, -1227.280, 110.916)
	AddZone("East Los Santos", 2222.560, -1628.530, -89.084, 2421.030, -1494.030, 110.916)
	AddZone("Rodeo", 558.099, -1684.650, -89.084, 647.522, -1384.930, 110.916)
	AddZone("Easter Tunnel", -1709.710, -833.034, -1.5, -1446.010, -730.118, 200.000)
	AddZone("Rodeo", 466.223, -1385.070, -89.084, 647.522, -1235.070, 110.916)
	AddZone("Redsands East", 1817.390, 2202.760, -89.084, 2011.940, 2342.830, 110.916)
	AddZone("The Clown's Pocket", 2162.390, 1783.230, -89.084, 2437.390, 1883.230, 110.916)
	AddZone("Idlewood", 1971.660, -1852.870, -89.084, 2222.560, -1742.310, 110.916)
	AddZone("Montgomery Intersection", 1546.650, 208.164, 0.000, 1745.830, 347.457, 200.000)
	AddZone("Willowfield", 2089.000, -2235.840, -89.084, 2201.820, -1989.900, 110.916)
	AddZone("Temple", 952.663, -1130.840, -89.084, 1096.470, -937.184, 110.916)
	AddZone("Prickle Pine", 1848.400, 2553.490, -89.084, 1938.800, 2863.230, 110.916)
	AddZone("Los Santos International", 1400.970, -2669.260, -39.084, 2189.820, -2597.260, 60.916)
	AddZone("Garver Bridge", -1213.910, 950.022, -89.084, -1087.930, 1178.930, 110.916)
	AddZone("Garver Bridge", -1339.890, 828.129, -89.084, -1213.910, 1057.040, 110.916)
	AddZone("Kincaid Bridge", -1339.890, 599.218, -89.084, -1213.910, 828.129, 110.916)
	AddZone("Kincaid Bridge", -1213.910, 721.111, -89.084, -1087.930, 950.022, 110.916)
	AddZone("Verona Beach", 930.221, -2006.780, -89.084, 1073.220, -1804.210, 110.916)
	AddZone("Verdant Bluffs", 1073.220, -2006.780, -89.084, 1249.620, -1842.270, 110.916)
	AddZone("Vinewood", 787.461, -1130.840, -89.084, 952.604, -954.662, 110.916)
	AddZone("Vinewood", 787.461, -1310.210, -89.084, 952.663, -1130.840, 110.916)
	AddZone("Commerce", 1463.900, -1577.590, -89.084, 1667.960, -1430.870, 110.916)
	AddZone("Market", 787.461, -1416.250, -89.084, 1072.660, -1310.210, 110.916)
	AddZone("Rockshore West", 2377.390, 596.349, -89.084, 2537.390, 788.894, 110.916)
	AddZone("Julius Thruway North", 2237.400, 2542.550, -89.084, 2498.210, 2663.170, 110.916)
	AddZone("East Beach", 2632.830, -1668.130, -89.084, 2747.740, -1393.420, 110.916)
	AddZone("Fallow Bridge", 434.341, 366.572, 0.000, 603.035, 555.680, 200.000)
	AddZone("Willowfield", 2089.000, -1989.900, -89.084, 2324.000, -1852.870, 110.916)
	AddZone("Chinatown", -2274.170, 578.396, -7.6, -2078.670, 744.170, 200.000)
	AddZone("El Castillo del Diablo", -208.570, 2337.180, 0.000, 8.430, 2487.180, 200.000)
	AddZone("Ocean Docks", 2324.000, -2145.100, -89.084, 2703.580, -2059.230, 110.916)
	AddZone("Easter Bay Chemicals", -1132.820, -768.027, 0.000, -956.476, -578.118, 200.000)
	AddZone("The Visage", 1817.390, 1703.230, -89.084, 2027.400, 1863.230, 110.916)
	AddZone("Ocean Flats", -2994.490, -430.276, -1.2, -2831.890, -222.589, 200.000)
	AddZone("Richman", 321.356, -860.619, -89.084, 687.802, -768.027, 110.916)
	AddZone("Green Palms", 176.581, 1305.450, -3.0, 338.658, 1520.720, 200.000)
	AddZone("Richman", 321.356, -768.027, -89.084, 700.794, -674.885, 110.916)
	AddZone("Starfish Casino", 2162.390, 1883.230, -89.084, 2437.390, 2012.180, 110.916)
	AddZone("East Beach", 2747.740, -1668.130, -89.084, 2959.350, -1498.620, 110.916)
	AddZone("Jefferson", 2056.860, -1372.040, -89.084, 2281.450, -1210.740, 110.916)
	AddZone("Downtown Los Santos", 1463.900, -1290.870, -89.084, 1724.760, -1150.870, 110.916)
	AddZone("Downtown Los Santos", 1463.900, -1430.870, -89.084, 1724.760, -1290.870, 110.916)
	AddZone("Garver Bridge", -1499.890, 696.442, -179.615, -1339.890, 925.353, 20.385)
	AddZone("Julius Thruway South", 1457.390, 823.228, -89.084, 2377.390, 863.229, 110.916)
	AddZone("East Los Santos", 2421.030, -1628.530, -89.084, 2632.830, -1454.350, 110.916)
	AddZone("Greenglass College", 964.391, 1044.690, -89.084, 1197.390, 1203.220, 110.916)
	AddZone("Las Colinas", 2747.740, -1120.040, -89.084, 2959.350, -945.035, 110.916)
	AddZone("Mulholland", 737.573, -768.027, -89.084, 1142.290, -674.885, 110.916)
	AddZone("Ocean Docks", 2201.820, -2730.880, -89.084, 2324.000, -2418.330, 110.916)
	AddZone("East Los Santos", 2462.130, -1454.350, -89.084, 2581.730, -1135.040, 110.916)
	AddZone("Ganton", 2222.560, -1722.330, -89.084, 2632.830, -1628.530, 110.916)
	AddZone("Avispa Country Club", -2831.890, -430.276, -6.1, -2646.400, -222.589, 200.000)
	AddZone("Willowfield", 1970.620, -2179.250, -89.084, 2089.000, -1852.870, 110.916)
	AddZone("Esplanade North", -1982.320, 1274.260, -4.5, -1524.240, 1358.900, 200.000)
	AddZone("The High Roller", 1817.390, 1283.230, -89.084, 2027.390, 1469.230, 110.916)
	AddZone("Ocean Docks", 2201.820, -2418.330, -89.084, 2324.000, -2095.000, 110.916)
	AddZone("Last Dime Motel", 1823.080, 596.349, -89.084, 1997.220, 823.228, 110.916)
	AddZone("Bayside Marina", -2353.170, 2275.790, 0.000, -2153.170, 2475.790, 200.000)
	AddZone("King's", -2329.310, 458.411, -7.6, -1993.280, 578.396, 200.000)
	AddZone("El Corona", 1692.620, -2179.250, -89.084, 1812.620, -1842.270, 110.916)
	AddZone("Blackfield Chapel", 1375.600, 596.349, -89.084, 1558.090, 823.228, 110.916)
	AddZone("The Pink Swan", 1817.390, 1083.230, -89.084, 2027.390, 1283.230, 110.916)
	AddZone("Julius Thruway West", 1197.390, 1163.390, -89.084, 1236.630, 2243.230, 110.916)
	AddZone("Los Flores", 2581.730, -1393.420, -89.084, 2747.740, -1135.040, 110.916)
	AddZone("The Visage", 1817.390, 1863.230, -89.084, 2106.700, 2011.830, 110.916)
	AddZone("Prickle Pine", 1938.800, 2624.230, -89.084, 2121.400, 2861.550, 110.916)
	AddZone("Verona Beach", 851.449, -1804.210, -89.084, 1046.150, -1577.590, 110.916)
	AddZone("Robada Intersection", -1119.010, 1178.930, -89.084, -862.025, 1351.450, 110.916)
	AddZone("Linden Side", 2749.900, 943.235, -89.084, 2923.390, 1198.990, 110.916)
	AddZone("Ocean Docks", 2703.580, -2302.330, -89.084, 2959.350, -2126.900, 110.916)
	AddZone("Willowfield", 2324.000, -2059.230, -89.084, 2541.700, -1852.870, 110.916)
	AddZone("King's", -2411.220, 265.243, -9.1, -1993.280, 373.539, 200.000)
	AddZone("Commerce", 1323.900, -1842.270, -89.084, 1701.900, -1722.260, 110.916)
	AddZone("Mulholland", 1269.130, -768.027, -89.084, 1414.070, -452.425, 110.916)
	AddZone("Marina", 647.712, -1804.210, -89.084, 851.449, -1577.590, 110.916)
	AddZone("Battery Point", -2741.070, 1268.410, -4.5, -2533.040, 1490.470, 200.000)
	AddZone("The Four Dragons Casino", 1817.390, 863.232, -89.084, 2027.390, 1083.230, 110.916)
	AddZone("Blackfield", 964.391, 1203.220, -89.084, 1197.390, 1403.220, 110.916)
	AddZone("Julius Thruway North", 1534.560, 2433.230, -89.084, 1848.400, 2583.230, 110.916)
	AddZone("Yellow Bell Gol Course", 1117.400, 2723.230, -89.084, 1457.460, 2863.230, 110.916)
	AddZone("Idlewood", 1812.620, -1602.310, -89.084, 2124.660, -1449.670, 110.916)
	AddZone("Redsands West", 1297.470, 2142.860, -89.084, 1777.390, 2243.230, 110.916)
	AddZone("Doherty", -2270.040, -324.114, -1.2, -1794.920, -222.589, 200.000)
	AddZone("Hilltop Farm", 967.383, -450.390, -3.0, 1176.780, -217.900, 200.000)
	AddZone("Las Barrancas", -926.130, 1398.730, -3.0, -719.234, 1634.690, 200.000)
	AddZone("Pirates in Men's Pants", 1817.390, 1469.230, -89.084, 2027.400, 1703.230, 110.916)
	AddZone("City Hall", -2867.850, 277.411, -9.1, -2593.440, 458.411, 200.000)
	AddZone("Avispa Country Club", -2646.400, -355.493, 0.000, -2270.040, -222.589, 200.000)
	AddZone("The Strip", 2027.400, 863.229, -89.084, 2087.390, 1703.230, 110.916)
	AddZone("Hashbury", -2593.440, -222.589, -1.0, -2411.220, 54.722, 200.000)
	AddZone("Los Santos International", 1852.000, -2394.330, -89.084, 2089.000, -2179.250, 110.916)
	AddZone("Whitewood Estates", 1098.310, 1726.220, -89.084, 1197.390, 2243.230, 110.916)
	AddZone("Sherman Reservoir", -789.737, 1659.680, -89.084, -599.505, 1929.410, 110.916)
	AddZone("El Corona", 1812.620, -2179.250, -89.084, 1970.620, -1852.870, 110.916)
	AddZone("Downtown", -1700.010, 744.267, -6.1, -1580.010, 1176.520, 200.000)
	AddZone("Foster Valley", -2178.690, -1250.970, 0.000, -1794.920, -1115.580, 200.000)
	AddZone("Las Payasadas", -354.332, 2580.360, 2.0, -133.625, 2816.820, 200.000)
	AddZone("Valle Ocultado", -936.668, 2611.440, 2.0, -715.961, 2847.900, 200.000)
	AddZone("Blackfield Intersection", 1166.530, 795.010, -89.084, 1375.600, 1044.690, 110.916)
	AddZone("Ganton", 2222.560, -1852.870, -89.084, 2632.830, -1722.330, 110.916)
	AddZone("Easter Bay Airport", -1213.910, -730.118, 0.000, -1132.820, -50.096, 200.000)
	AddZone("Redsands East", 1817.390, 2011.830, -89.084, 2106.700, 2202.760, 110.916)
	AddZone("Esplanade East", -1499.890, 578.396, -79.615, -1339.890, 1274.260, 20.385)
	AddZone("Caligula's Palace", 2087.390, 1543.230, -89.084, 2437.390, 1703.230, 110.916)
	AddZone("Royal Casino", 2087.390, 1383.230, -89.084, 2437.390, 1543.230, 110.916)
	AddZone("Richman", 72.648, -1235.070, -89.084, 321.356, -1008.150, 110.916)
	AddZone("Starfish Casino", 2437.390, 1783.230, -89.084, 2685.160, 2012.180, 110.916)
	AddZone("Mulholland", 1281.130, -452.425, -89.084, 1641.130, -290.913, 110.916)
	AddZone("Downtown", -1982.320, 744.170, -6.1, -1871.720, 1274.260, 200.000)
	AddZone("Hankypanky Point", 2576.920, 62.158, 0.000, 2759.250, 385.503, 200.000)
	AddZone("K.A.C.C. Military Fuels", 2498.210, 2626.550, -89.084, 2749.900, 2861.550, 110.916)
	AddZone("Harry Gold Parkway", 1777.390, 863.232, -89.084, 1817.390, 2342.830, 110.916)
	AddZone("Bayside Tunnel", -2290.190, 2548.290, -89.084, -1950.190, 2723.290, 110.916)
	AddZone("Ocean Docks", 2324.000, -2302.330, -89.084, 2703.580, -2145.100, 110.916)
	AddZone("Richman", 321.356, -1044.070, -89.084, 647.557, -860.619, 110.916)
	AddZone("Randolph Industrial Estate", 1558.090, 596.349, -89.084, 1823.080, 823.235, 110.916)
	AddZone("East Beach", 2632.830, -1852.870, -89.084, 2959.350, -1668.130, 110.916)
	AddZone("Flint Water", -314.426, -753.874, -89.084, -106.339, -463.073, 110.916)
	AddZone("Blueberry", 19.607, -404.136, 3.8, 349.607, -220.137, 200.000)
	AddZone("Linden Station", 2749.900, 1198.990, -89.084, 2923.390, 1548.990, 110.916)
	AddZone("Glen Park", 1812.620, -1350.720, -89.084, 2056.860, -1100.820, 110.916)
	AddZone("Downtown", -1993.280, 265.243, -9.1, -1794.920, 578.396, 200.000)
	AddZone("Redsands West", 1377.390, 2243.230, -89.084, 1704.590, 2433.230, 110.916)
	AddZone("Richman", 321.356, -1235.070, -89.084, 647.522, -1044.070, 110.916)
	AddZone("Gant Bridge", -2741.450, 1659.680, -6.1, -2616.400, 2175.150, 200.000)
	AddZone("Lil' Probe Inn", -90.218, 1286.850, -3.0, 153.859, 1554.120, 200.000)
	AddZone("Flint Intersection", -187.700, -1596.760, -89.084, 17.063, -1276.600, 110.916)
	AddZone("Las Colinas", 2281.450, -1135.040, -89.084, 2632.740, -945.035, 110.916)
	AddZone("Sobell Rail Yards", 2749.900, 1548.990, -89.084, 2923.390, 1937.250, 110.916)
	AddZone("The Emerald Isle", 2011.940, 2202.760, -89.084, 2237.400, 2508.230, 110.916)
	AddZone("El Castillo del Diablo", -208.570, 2123.010, -7.6, 114.033, 2337.180, 200.000)
	AddZone("Santa Flora", -2741.070, 458.411, -7.6, -2533.040, 793.411, 200.000)
	AddZone("Playa del Seville", 2703.580, -2126.900, -89.084, 2959.350, -1852.870, 110.916)
	AddZone("Market", 926.922, -1577.590, -89.084, 1370.850, -1416.250, 110.916)
	AddZone("Queens", -2593.440, 54.722, 0.000, -2411.220, 458.411, 200.000)
	AddZone("Pilson Intersection", 1098.390, 2243.230, -89.084, 1377.390, 2507.230, 110.916)
	AddZone("Spinybed", 2121.400, 2663.170, -89.084, 2498.210, 2861.550, 110.916)
	AddZone("Pilgrim", 2437.390, 1383.230, -89.084, 2624.400, 1783.230, 110.916)
	AddZone("Blackfield", 964.391, 1403.220, -89.084, 1197.390, 1726.220, 110.916)
	AddZone("'The Big Ear'", -410.020, 1403.340, -3.0, -137.969, 1681.230, 200.000)
	AddZone("Dillimore", 580.794, -674.885, -9.5, 861.085, -404.790, 200.000)
	AddZone("El Quebrados", -1645.230, 2498.520, 0.000, -1372.140, 2777.850, 200.000)
	AddZone("Esplanade North", -2533.040, 1358.900, -4.5, -1996.660, 1501.210, 200.000)
	AddZone("Easter Bay Airport", -1499.890, -50.096, -1.0, -1242.980, 249.904, 200.000)
	AddZone("Fisher's Lagoon", 1916.990, -233.323, -100.000, 2131.720, 13.800, 200.000)
	AddZone("Mulholland", 1414.070, -768.027, -89.084, 1667.610, -452.425, 110.916)
	AddZone("East Beach", 2747.740, -1498.620, -89.084, 2959.350, -1120.040, 110.916)
	AddZone("San Andreas Sound", 2450.390, 385.503, -100.000, 2759.250, 562.349, 200.000)
	AddZone("Shady Creeks", -2030.120, -2174.890, -6.1, -1820.640, -1771.660, 200.000)
	AddZone("Market", 1072.660, -1416.250, -89.084, 1370.850, -1130.850, 110.916)
	AddZone("Rockshore West", 1997.220, 596.349, -89.084, 2377.390, 823.228, 110.916)
	AddZone("Prickle Pine", 1534.560, 2583.230, -89.084, 1848.400, 2863.230, 110.916)
	AddZone("Easter Basin", -1794.920, -50.096, -1.04, -1499.890, 249.904, 200.000)
	AddZone("Leafy Hollow", -1166.970, -1856.030, 0.000, -815.624, -1602.070, 200.000)
	AddZone("LVA Freight Depot", 1457.390, 863.229, -89.084, 1777.400, 1143.210, 110.916)
	AddZone("Prickle Pine", 1117.400, 2507.230, -89.084, 1534.560, 2723.230, 110.916)
	AddZone("Blueberry", 104.534, -220.137, 2.3, 349.607, 152.236, 200.000)
	AddZone("El Castillo del Diablo", -464.515, 2217.680, 0.000, -208.570, 2580.360, 200.000)
	AddZone("Downtown", -2078.670, 578.396, -7.6, -1499.890, 744.267, 200.000)
	AddZone("Rockshore East", 2537.390, 676.549, -89.084, 2902.350, 943.235, 110.916)
	AddZone("San Fierro Bay", -2616.400, 1501.210, -3.0, -1996.660, 1659.680, 200.000)
	AddZone("Paradiso", -2741.070, 793.411, -6.1, -2533.040, 1268.410, 200.000)
	AddZone("The Camel's Toe", 2087.390, 1203.230, -89.084, 2640.400, 1383.230, 110.916)
	AddZone("Old Venturas Strip", 2162.390, 2012.180, -89.084, 2685.160, 2202.760, 110.916)
	AddZone("Juniper Hill", -2533.040, 578.396, -7.6, -2274.170, 968.369, 200.000)
	AddZone("Juniper Hollow", -2533.040, 968.369, -6.1, -2274.170, 1358.900, 200.000)
	AddZone("Roca Escalante", 2237.400, 2202.760, -89.084, 2536.430, 2542.550, 110.916)
	AddZone("Julius Thruway East", 2685.160, 1055.960, -89.084, 2749.900, 2626.550, 110.916)
	AddZone("Verona Beach", 647.712, -2173.290, -89.084, 930.221, -1804.210, 110.916)
	AddZone("Foster Valley", -2178.690, -599.884, -1.2, -1794.920, -324.114, 200.000)
	AddZone("Arco del Oeste", -901.129, 2221.860, 0.000, -592.090, 2571.970, 200.000)
	AddZone("Fallen Tree", -792.254, -698.555, -5.3, -452.404, -380.043, 200.000)
	AddZone("The Farm", -1209.670, -1317.100, 114.981, -908.161, -787.391, 251.981)
	AddZone("The Sherman Dam", -968.772, 1929.410, -3.0, -481.126, 2155.260, 200.000)
	AddZone("Esplanade North", -1996.660, 1358.900, -4.5, -1524.240, 1592.510, 200.000)
	AddZone("Financial", -1871.720, 744.170, -6.1, -1701.300, 1176.420, 300.000)
	AddZone("Garcia", -2411.220, -222.589, -1.14, -2173.040, 265.243, 200.000)
	AddZone("Montgomery", 1119.510, 119.526, -3.0, 1451.400, 493.323, 200.000)
	AddZone("Creek", 2749.900, 1937.250, -89.084, 2921.620, 2669.790, 110.916)
	AddZone("Los Santos International", 1249.620, -2394.330, -89.084, 1852.000, -2179.250, 110.916)
	AddZone("Santa Maria Beach", 72.648, -2173.290, -89.084, 342.648, -1684.650, 110.916)
	AddZone("Mulholland Intersection", 1463.900, -1150.870, -89.084, 1812.620, -768.027, 110.916)
	AddZone("Angel Pine", -2324.940, -2584.290, -6.1, -1964.220, -2212.110, 200.000)
	AddZone("Verdant Meadows", 37.032, 2337.180, -3.0, 435.988, 2677.900, 200.000)
	AddZone("Octane Springs", 338.658, 1228.510, 0.000, 664.308, 1655.050, 200.000)
	AddZone("Come-A-Lot", 2087.390, 943.235, -89.084, 2623.180, 1203.230, 110.916)
	AddZone("Redsands West", 1236.630, 1883.110, -89.084, 1777.390, 2142.860, 110.916)
	AddZone("Santa Maria Beach", 342.648, -2173.290, -89.084, 647.712, -1684.650, 110.916)
	AddZone("Verdant Bluffs", 1249.620, -2179.250, -89.084, 1692.620, -1842.270, 110.916)
	AddZone("Las Venturas Airport", 1236.630, 1203.280, -89.084, 1457.370, 1883.110, 110.916)
	AddZone("Flint Range", -594.191, -1648.550, 0.000, -187.700, -1276.600, 200.000)
	AddZone("Verdant Bluffs", 930.221, -2488.420, -89.084, 1249.620, -2006.780, 110.916)
	AddZone("Palomino Creek", 2160.220, -149.004, 0.000, 2576.920, 228.322, 200.000)
	AddZone("Ocean Docks", 2373.770, -2697.090, -89.084, 2809.220, -2330.460, 110.916)
	AddZone("Easter Bay Airport", -1213.910, -50.096, -4.5, -947.980, 578.396, 200.000)
	AddZone("Whitewood Estates", 883.308, 1726.220, -89.084, 1098.310, 2507.230, 110.916)
	AddZone("Calton Heights", -2274.170, 744.170, -6.1, -1982.320, 1358.900, 200.000)
	AddZone("Easter Basin", -1794.920, 249.904, -9.1, -1242.980, 578.396, 200.000)
	AddZone("Los Santos Inlet", -321.744, -2224.430, -89.084, 44.615, -1724.430, 110.916)
	AddZone("Doherty", -2173.040, -222.589, -1.0, -1794.920, 265.243, 200.000)
	AddZone("Mount Chiliad", -2178.690, -2189.910, -47.917, -2030.120, -1771.660, 576.083)
	AddZone("Fort Carson", -376.233, 826.326, -3.0, 123.717, 1220.440, 200.000)
	AddZone("Foster Valley", -2178.690, -1115.580, 0.000, -1794.920, -599.884, 200.000)
	AddZone("Ocean Flats", -2994.490, -222.589, -1.0, -2593.440, 277.411, 200.000)
	AddZone("Fern Ridge", 508.189, -139.259, 0.000, 1306.660, 119.526, 200.000)
	AddZone("Bayside", -2741.070, 2175.150, 0.000, -2353.170, 2722.790, 200.000)
	AddZone("Las Venturas Airport", 1457.370, 1203.280, -89.084, 1777.390, 1883.110, 110.916)
	AddZone("Blueberry Acres", -319.676, -220.137, 0.000, 104.534, 293.324, 200.000)
	AddZone("Palisades", -2994.490, 458.411, -6.1, -2741.070, 1339.610, 200.000)
	AddZone("North Rock", 2285.370, -768.027, 0.000, 2770.590, -269.740, 200.000)
	AddZone("Hunter Quarry", 337.244, 710.840, -115.239, 860.554, 1031.710, 203.761)
	AddZone("Los Santos International", 1382.730, -2730.880, -89.084, 2201.820, -2394.330, 110.916)
	AddZone("Missionary Hill", -2994.490, -811.276, 0.000, -2178.690, -430.276, 200.000)
	AddZone("San Fierro Bay", -2616.400, 1659.680, -3.0, -1996.660, 2175.150, 200.000)
	AddZone("Restricted Area", -91.586, 1655.050, -50.000, 421.234, 2123.010, 250.000)
	AddZone("Mount Chiliad", -2997.470, -1115.580, -47.917, -2178.690, -971.913, 576.083)
	AddZone("Mount Chiliad", -2178.690, -1771.660, -47.917, -1936.120, -1250.970, 576.083)
	AddZone("Easter Bay Airport", -1794.920, -730.118, -3.0, -1213.910, -50.096, 200.000)
	AddZone("The Panopticon", -947.980, -304.320, -1.1, -319.676, 327.071, 200.000)
	AddZone("Shady Creeks", -1820.640, -2643.680, -8.0, -1226.780, -1771.660, 200.000)
	AddZone("Back o Beyond", -1166.970, -2641.190, 0.000, -321.744, -1856.030, 200.000)
	AddZone("Mount Chiliad", -2994.490, -2189.910, -47.917, -2178.690, -1115.580, 576.083)
	AddZone("Tierra Robada", -1213.910, 596.349, -242.990, -480.539, 1659.680, 900.000)
	AddZone("Flint County", -1213.910, -2892.970, -242.990, 44.615, -768.027, 900.000)
	AddZone("Whetstone", -2997.470, -2892.970, -242.990, -1213.910, -1115.580, 900.000)
	AddZone("Bone County", -480.539, 596.349, -242.990, 869.461, 2993.870, 900.000)
	AddZone("Tierra Robada", -2997.470, 1659.680, -242.990, -480.539, 2993.870, 900.000)
	AddZone("San Fierro", -2997.470, -1115.580, -242.990, -1213.910, 1659.680, 900.000)
	AddZone("Las Venturas", 869.461, 596.349, -242.990, 2997.060, 2993.870, 900.000)
	AddZone("Red County", -1213.910, -768.027, -242.990, 2997.060, 596.349, 900.000)
	AddZone("Los Santos", 44.615, -2892.970, -242.990, 2997.060, -768.027, 900.000)
}

calculateZone(posX, posY, posZ) {
	if ( bInitZaC == 0 )
	{
		initZonesAndCities()
		bInitZaC := 1
	}
		
	Loop % nZone-1
	{
		if (posX >= zone%A_Index%_x1) && (posY >= zone%A_Index%_y1) && (posZ >= zone%A_Index%_z1) && (posX <= zone%A_Index%_x2) && (posY <= zone%A_Index%_y2) && (posZ <= zone%A_Index%_z2)
		{
			ErrorLevel := ERROR_OK
			return zone%A_Index%_name
		}
	}
	
	ErrorLevel := ERROR_ZONE_NOT_FOUND
	return "Unbekannt"
}

calculateCity(posX, posY, posZ) {
	if ( bInitZaC == 0 )
	{
		initZonesAndCities()
		bInitZaC := 1
	}
	smallestCity := "Unbekannt"
	currentCitySize := 0
	smallestCitySize := 0
	
	Loop % nCity-1
	{
		if (posX >= city%A_Index%_x1) && (posY >= city%A_Index%_y1) && (posZ >= city%A_Index%_z1) && (posX <= city%A_Index%_x2) && (posY <= city%A_Index%_y2) && (posZ <= city%A_Index%_z2)
		{
			currentCitySize := ((city%A_Index%_x2 - city%A_Index%_x1) * (city%A_Index%_y2 - city%A_Index%_y1) * (city%A_Index%_z2 - city%A_Index%_z1))
			if (smallestCity == "Unbekannt") || (currentCitySize < smallestCitySize)
			{
				smallestCity := city%A_Index%_name
				smallestCitySize := currentCitySize
			}
		}
	}
	
	if(smallestCity == "Unbekannt") {
		ErrorLevel := ERROR_CITY_NOT_FOUND
	} else {
		ErrorLevel := ERROR_OK
	}
	return smallestCity
}

; ################# Interface Editor for GTA:SA v1.0 US #################

global aInterface := []

aInterface["HealthX"] 			:= Object("ADDRESSES", [0x58EE87], "DEFAULT_POINTER", 0x86535C, "DEFAULT_VALUE", 141.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["HealthY"] 			:= Object("ADDRESSES", [0x58EE68], "DEFAULT_POINTER", 0x866CA8, "DEFAULT_VALUE", 77.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["HealthWidth"] 		:= Object("ADDRESSES", [0x5892D8], "DEFAULT_POINTER", 0x866BB8, "DEFAULT_VALUE", 109.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["HealthHeight"] 		:= Object("ADDRESSES", [0x589358], "DEFAULT_POINTER", 0x85EED4, "DEFAULT_VALUE", 9.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["HealthColor"] 		:= Object("ADDRESSES", [0x58932A], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 0, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["HealthBorder"] 		:= Object("ADDRESSES", [0x589353], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 1, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["HealthPercentage"] 	:= Object("ADDRESSES", [0x589355], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 0, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["ArmorX"] 			:= Object("ADDRESSES", [0x58EF59], "DEFAULT_POINTER", 0x866B78, "DEFAULT_VALUE", 94.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["ArmorY"] 			:= Object("ADDRESSES", [0x58EF3A], "DEFAULT_POINTER", 0x862D38, "DEFAULT_VALUE", 48.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["ArmorWidth"] 		:= Object("ADDRESSES", [0x58915D], "DEFAULT_POINTER", 0x86503C, "DEFAULT_VALUE", 62.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["ArmorHeight"] 		:= Object("ADDRESSES", [0x589146], "DEFAULT_POINTER", 0x85EED4, "DEFAULT_VALUE", 9.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["ArmorColor"] 		:= Object("ADDRESSES", [0x5890F5], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 4, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["ArmorBorder"] 		:= Object("ADDRESSES", [0x589123], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 1, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["ArmorPercentage"] 	:= Object("ADDRESSES", [0x589125], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 0, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["BreathX"] 			:= Object("ADDRESSES", [0x58F11F], "DEFAULT_POINTER", 0x866B78, "DEFAULT_VALUE", 94.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["BreathY"] 			:= Object("ADDRESSES", [0x58F100], "DEFAULT_POINTER", 0x86503C, "DEFAULT_VALUE", 62.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["BreathWidth"] 		:= Object("ADDRESSES", [0x589235], "DEFAULT_POINTER", 0x86503C, "DEFAULT_VALUE", 62.0 ,"VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["BreathHeight"] 		:= Object("ADDRESSES", [0x58921E], "DEFAULT_POINTER", 0x85EED4, "DEFAULT_VALUE", 9.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["BreathColor"] 		:= Object("ADDRESSES", [0x5891E4], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 3, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["BreathBorder"] 		:= Object("ADDRESSES", [0x589207], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 1, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["BreathPercentage"] 	:= Object("ADDRESSES", [0x589209], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 0, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["MoneyX"] 			:= Object("ADDRESSES", [0x58F5FC], "DEFAULT_POINTER", 0x85950C, "DEFAULT_VALUE", 32.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["MoneyY"] 			:= Object("ADDRESSES", [0x58F5DC], "DEFAULT_POINTER", 0x866C88, "DEFAULT_VALUE", 89.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["MoneyXScale"] 		:= Object("ADDRESSES", [0x58F564], "DEFAULT_POINTER", 0x866CAC, "DEFAULT_VALUE", 0.55 ,"VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["MoneyYScale"] 		:= Object("ADDRESSES", [0x58F54E], "DEFAULT_POINTER", 0x858F14, "DEFAULT_VALUE", 1.1, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["MoneyColor"] 		:= Object("ADDRESSES", [0x58F492], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 1, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)
aInterface["MoneyColorDebt"] 	:= Object("ADDRESSES", [0x58F4D4], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 0, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["WeaponX"] 			:= Object("ADDRESSES", [0x58F92F], "DEFAULT_POINTER", 0x866C84, "DEFAULT_VALUE", 0.17343046, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponIconX"] 		:= Object("ADDRESSES", [0x58F927], "DEFAULT_POINTER", 0x85950C, "DEFAULT_VALUE", 32.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponIconY"] 		:= Object("ADDRESSES", [0x58F913], "DEFAULT_POINTER", 0x858BA4, "DEFAULT_VALUE", 20.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponAmmoY"] 		:= Object("ADDRESSES", [0x58F9DC], "DEFAULT_POINTER", 0x858BA4, "DEFAULT_VALUE", 20.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponAmmoX"] 		:= Object("ADDRESSES", [0x58F9F7], "DEFAULT_POINTER", 0x866C84, "DEFAULT_VALUE", 0.17343046, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponIconWidth"] 	:= Object("ADDRESSES", [0x58FAAB], "DEFAULT_POINTER", 0x866C4C, "DEFAULT_VALUE", 47.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponAmmoHeight"]	:= Object("ADDRESSES", [0x5894B7], "DEFAULT_POINTER", 0x858CB0, "DEFAULT_VALUE", 0.7, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WeaponAmmoWidth"]	:= Object("ADDRESSES", [0x5894CD], "DEFAULT_POINTER", 0x858C24, "DEFAULT_VALUE", 0.3, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)

aInterface["WantedX"] 			:= Object("ADDRESSES", [0x58DD0F], "DEFAULT_POINTER", 0x863210, "DEFAULT_VALUE", 29.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WantedY"] 			:= Object("ADDRESSES", [0x58DDFC], "DEFAULT_POINTER", 0x866C5C, "DEFAULT_VALUE", 114.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WantedEmptyY"] 		:= Object("ADDRESSES", [0x58DE27], "DEFAULT_POINTER", 0x858CCC, "DEFAULT_VALUE", 12.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WantedXScale"] 		:= Object("ADDRESSES", [0x58DCC0], "DEFAULT_POINTER", 0x866C60, "DEFAULT_VALUE", 0.605, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WantedYScale"] 		:= Object("ADDRESSES", [0x58DCAA], "DEFAULT_POINTER", 0x866C64, "DEFAULT_VALUE", 1.21, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["WantedColor"] 		:= Object("ADDRESSES", [0x58DDC9], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 6, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["RadioY"] 			:= Object("ADDRESSES", [0x4E9FD8], "DEFAULT_POINTER", 0x858F8C, "DEFAULT_VALUE", 22.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadioXScale"] 		:= Object("ADDRESSES", [0x4E9F38], "DEFAULT_POINTER", 0x858CC8, "DEFAULT_VALUE", 0.6, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadioYScale"] 		:= Object("ADDRESSES", [0x4E9F22], "DEFAULT_POINTER", 0x858C20, "DEFAULT_VALUE", 0.9, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadioColor"] 		:= Object("ADDRESSES", [0x4E9F91], "DEFAULT_POINTER", null, "DEFAULT_VALUE", 6, "VALUE_TYPE", "Byte", "DETOUR_ADDRESS", null)

aInterface["RadarX"] 			:= Object("ADDRESSES", [0x58A79B, 0x5834D4, 0x58A836, 0x58A8E9, 0x58A98A, 0x58A469, 0x58A5E2, 0x58A6E6], "DEFAULT_POINTER", 0x858A10, "DEFAULT_VALUE", 40.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadarY"] 			:= Object("ADDRESSES", [0x58A7C7, 0x58A868, 0x58A913, 0x58A9C7, 0x583500, 0x58A499, 0x58A60E, 0x58A71E], "DEFAULT_POINTER", 0x866B70, "DEFAULT_VALUE", 104.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)

aInterface["RadarHeight"]		:= Object("ADDRESSES", [0x58A47D, 0x58A632, 0x58A6AB, 0x58A70E, 0x58A801, 0x58A8AB, 0x58A921, 0x58A9D5, 0x5834F6], "DEFAULT_POINTER", 0x866B74, "DEFAULT_VALUE", 76.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadarWidth"]		:= Object("ADDRESSES", [0x5834C2, 0x58A449, 0x58A7E9, 0x58A840, 0x58A943, 0x58A99D], "DEFAULT_POINTER", 0x866B78, "DEFAULT_VALUE", 94.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)

aInterface["RadarScaleWidth"]	:= Object("ADDRESSES", [0x5834EE, 0x58A475, 0x58A602, 0x58A706, 0x58A7BB, 0x58A85C, 0x58A90B, 0x58A9BF], "DEFAULT_POINTER", 0x859524, "DEFAULT_VALUE", 0.002232143, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["RadarScaleHeight"]	:= Object("ADDRESSES", [0x5834BC, 0x58A443, 0x58A5DA, 0x58A6E0, 0x58A793, 0x58A830, 0x58A8E1, 0x58A984], "DEFAULT_POINTER", 0x859520, "DEFAULT_VALUE", 0.0015625, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)

setHUDValue(sName, value) {
	if (!aInterface.HasKey(sName) || !checkHandles())
		return false

	oKey := aInterface[sName]
	dwAddress := oKey.DEFAULT_POINTER != null ? pDetours + (getKeyIndex(sName) - 1) * 4 : oKey.ADDRESSES[1]

	if (value = "DEFAULT")
		value := oKey.DEFAULT_VALUE
	else if (value = "RESET")
	{
		if (oKey.DEFAULT_POINTER != null) 
		{
			; reset to default pointer
			for i, o in oKey.ADDRESSES {
				__WRITEMEM(hGTA, o, [0x0], oKey.DEFAULT_POINTER, "UInt")
				if (ErrorLevel)
					return false
			}
			
			return true
		}
		else
			value := oKey.DEFAULT_VALUE
	}
	else if (oKey.DEFAULT_POINTER != null && (oKey.DETOUR_ADDRESS == null || __READMEM(hGTA, oKey.ADDRESSES[1], [0x0], "UInt") != oKey.DETOUR_ADDRESS))
	{
		; install detour
		__WRITEMEM(hGTA, dwAddress, [0x0], oKey.DEFAULT_VALUE, oKey.VALUE_TYPE)
		if (ErrorLevel)
			return false

		oKey.DETOUR_ADDRESS := dwAddress

		for i, o in oKey.ADDRESSES {
			__WRITEMEM(hGTA, o, [0x0], dwAddress, "UInt")
			if (ErrorLevel)
				return false
		}
	}

	; set value
	__WRITEMEM(hGTA, dwAddress, [0x0], value, oKey.VALUE_TYPE)
	if (ErrorLevel)
		return false

	return true
}

resetHUD() {
	for i, o in aInterface 
	{
		for k, v in o.ADDRESSES {
			if (o.DEFAULT_POINTER != null)
				__WRITEMEM(hGTA, v, [0x0], o.DEFAULT_POINTER, "UInt")
			else
				__WRITEMEM(hGTA, v, [0x0], o.DEFAULT_VALUE, o.VALUE_TYPE)
		}
	}

	if (ErrorLevel)
		return false

	return true
}

getKeyIndex(sKey) {
	for i, o in aInterface {
		if (aInterface[sKey] == o)
			return A_Index
	}

	return false
}
