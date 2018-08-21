; #######################################################################################################
; # Memory Functions:                                                                                   #
; # --------------------------------------------------------------------------------------------------- #
; #######################################################################################################

SetTitleMatchMode, 3

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

__unicodeToAnsi(wString, nLen = 0) {
	pString := wString + 1 > 65536 ? wString : &wString

	if (!nLen)
		nLen := DllCall("WideCharToMultiByte", "UInt", 0, "UInt", 0, "UInt", pString, "Int",  -1, "UInt", 0, "Int",  0, "UInt", 0, "UInt", 0)

	VarSetCapacity(sString, nLen)
	DllCall("WideCharToMultiByte", "UInt", 0, "UInt", 0, "UInt", pString, "Int",  -1, "Str",  sString, "Int",  nLen, "UInt", 0, "UInt", 0)

	return sString
}

__NOP(hProcess, dwAddress, dwLen) {
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

global SERVER_SPEED_KOEFF := 1.425
global MATH_PI := 3.141592653589793

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


global cities := []
cities.Push(Object("NAME", "Las Venturas", "X1", 685.0, "Y1", 476.093, "X2", 3000.0, "Y2", 3000.0))
cities.Push(Object("NAME", "San Fierro", "X1", -3000.0, "Y1", -742.306, "X2", -1270.53, "Y2", 1530.24))
cities.Push(Object("NAME", "San Fierro", "X1", -1270.53, "Y1", -402.481, "X2", -1038.45, "Y2", 832.495))
cities.Push(Object("NAME", "San Fierro", "X1", -1038.45, "Y1", -145.539, "X2", -897.546, "Y2", 376.632))
cities.Push(Object("NAME", "Los Santos", "X1", 480.0, "Y1", -3000.0, "X2", 3000.0, "Y2", -850.0))
cities.Push(Object("NAME", "Los Santos", "X1", 80.0, "Y1", -2101.61, "X2", 1075.0, "Y2", -1239.61))
cities.Push(Object("NAME", "Tierra Robada", "X1", -1213.91, "Y1", 596.349, "X2", -480.539, "Y2", 1659.68))
cities.Push(Object("NAME", "Red County", "X1", -1213.91, "Y1", -768.027, "X2", 2997.06, "Y2", 596.349))
cities.Push(Object("NAME", "Flint County", "X1", -1213.91, "Y1", -2892.97, "X2", 44.6147, "Y2", -768.027))
cities.Push(Object("NAME", "Whetstone", "X1", -2997.47, "Y1", -2892.97, "X2", -1213.91, "Y2", -1115.58))

global zones := []
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2667.810, "Y1", -302.135, "X2", -2646.400, "Y2", -262.320))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1315.420, "Y1", -405.388, "X2", -1264.400, "Y2", -209.543))
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2550.040, "Y1", -355.493, "X2", -2470.040, "Y2", -318.493))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1490.330, "Y1", -209.543, "X2", -1264.400, "Y2", -148.388))
zones.Push(Object("NAME", "Garcia", "X1", -2395.140, "Y1", -222.589, "X2", -2354.090, "Y2", -204.792))
zones.Push(Object("NAME", "Shady Cabin", "X1", -1632.830, "Y1", -2263.440, "X2", -1601.330, "Y2", -2231.790))
zones.Push(Object("NAME", "East Los Santos", "X1", 2381.680, "Y1", -1494.030, "X2", 2421.030, "Y2", -1454.350))
zones.Push(Object("NAME", "LVA Freight Depot", "X1", 1236.630, "Y1", 1163.410, "X2", 1277.050, "Y2", 1203.280))
zones.Push(Object("NAME", "Blackfield Intersection", "X1", 1277.050, "Y1", 1044.690, "X2", 1315.350, "Y2", 1087.630))
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2470.040, "Y1", -355.493, "X2", -2270.040, "Y2", -318.493))
zones.Push(Object("NAME", "Temple", "X1", 1252.330, "Y1", -926.999, "X2", 1357.000, "Y2", -910.170))
zones.Push(Object("NAME", "Unity Station", "X1", 1692.620, "Y1", -1971.800, "X2", 1812.620, "Y2", -1932.800))
zones.Push(Object("NAME", "LVA Freight Depot", "X1", 1315.350, "Y1", 1044.690, "X2", 1375.600, "Y2", 1087.630))
zones.Push(Object("NAME", "Los Flores", "X1", 2581.730, "Y1", -1454.350, "X2", 2632.830, "Y2", -1393.420))
zones.Push(Object("NAME", "Starfish Casino", "X1", 2437.390, "Y1", 1858.100, "X2", 2495.090, "Y2", 1970.850))
zones.Push(Object("NAME", "Easter Bay Chemicals", "X1", -1132.820, "Y1", -787.391, "X2", -956.476, "Y2", -768.027))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1370.850, "Y1", -1170.870, "X2", 1463.900, "Y2", -1130.850))
zones.Push(Object("NAME", "Esplanade East", "X1", -1620.300, "Y1", 1176.520, "X2", -1580.010, "Y2", 1274.260))
zones.Push(Object("NAME", "Market Station", "X1", 787.461, "Y1", -1410.930, "X2", 866.009, "Y2", -1310.210))
zones.Push(Object("NAME", "Linden Station", "X1", 2811.250, "Y1", 1229.590, "X2", 2861.250, "Y2", 1407.590))
zones.Push(Object("NAME", "Montgomery Intersection", "X1", 1582.440, "Y1", 347.457, "X2", 1664.620, "Y2", 401.750))
zones.Push(Object("NAME", "Frederick Bridge", "X1", 2759.250, "Y1", 296.501, "X2", 2774.250, "Y2", 594.757))
zones.Push(Object("NAME", "Yellow Bell Station", "X1", 1377.480, "Y1", 2600.430, "X2", 1492.450, "Y2", 2687.360))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1507.510, "Y1", -1385.210, "X2", 1582.550, "Y2", -1325.310))
zones.Push(Object("NAME", "Jefferson", "X1", 2185.330, "Y1", -1210.740, "X2", 2281.450, "Y2", -1154.590))
zones.Push(Object("NAME", "Mulholland", "X1", 1318.130, "Y1", -910.170, "X2", 1357.000, "Y2", -768.027))
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2361.510, "Y1", -417.199, "X2", -2270.040, "Y2", -355.493))
zones.Push(Object("NAME", "Jefferson", "X1", 1996.910, "Y1", -1449.670, "X2", 2056.860, "Y2", -1350.720))
zones.Push(Object("NAME", "Julius Thruway West", "X1", 1236.630, "Y1", 2142.860, "X2", 1297.470, "Y2", 2243.230))
zones.Push(Object("NAME", "Jefferson", "X1", 2124.660, "Y1", -1494.030, "X2", 2266.210, "Y2", -1449.670))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 1848.400, "Y1", 2478.490, "X2", 1938.800, "Y2", 2553.490))
zones.Push(Object("NAME", "Rodeo", "X1", 422.680, "Y1", -1570.200, "X2", 466.223, "Y2", -1406.050))
zones.Push(Object("NAME", "Cranberry Station", "X1", -2007.830, "Y1", 56.306, "X2", -1922.000, "Y2", 224.782))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1391.050, "Y1", -1026.330, "X2", 1463.900, "Y2", -926.999))
zones.Push(Object("NAME", "Redsands West", "X1", 1704.590, "Y1", 2243.230, "X2", 1777.390, "Y2", 2342.830))
zones.Push(Object("NAME", "Little Mexico", "X1", 1758.900, "Y1", -1722.260, "X2", 1812.620, "Y2", -1577.590))
zones.Push(Object("NAME", "Blackfield Intersection", "X1", 1375.600, "Y1", 823.228, "X2", 1457.390, "Y2", 919.447))
zones.Push(Object("NAME", "Los Santos International", "X1", 1974.630, "Y1", -2394.330, "X2", 2089.000, "Y2", -2256.590))
zones.Push(Object("NAME", "Beacon Hill", "X1", -399.633, "Y1", -1075.520, "X2", -319.033, "Y2", -977.516))
zones.Push(Object("NAME", "Rodeo", "X1", 334.503, "Y1", -1501.950, "X2", 422.680, "Y2", -1406.050))
zones.Push(Object("NAME", "Richman", "X1", 225.165, "Y1", -1369.620, "X2", 334.503, "Y2", -1292.070))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1724.760, "Y1", -1250.900, "X2", 1812.620, "Y2", -1150.870))
zones.Push(Object("NAME", "The Strip", "X1", 2027.400, "Y1", 1703.230, "X2", 2137.400, "Y2", 1783.230))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1378.330, "Y1", -1130.850, "X2", 1463.900, "Y2", -1026.330))
zones.Push(Object("NAME", "Blackfield Intersection", "X1", 1197.390, "Y1", 1044.690, "X2", 1277.050, "Y2", 1163.390))
zones.Push(Object("NAME", "Conference Center", "X1", 1073.220, "Y1", -1842.270, "X2", 1323.900, "Y2", -1804.210))
zones.Push(Object("NAME", "Montgomery", "X1", 1451.400, "Y1", 347.457, "X2", 1582.440, "Y2", 420.802))
zones.Push(Object("NAME", "Foster Valley", "X1", -2270.040, "Y1", -430.276, "X2", -2178.690, "Y2", -324.114))
zones.Push(Object("NAME", "Blackfield Chapel", "X1", 1325.600, "Y1", 596.349, "X2", 1375.600, "Y2", 795.010))
zones.Push(Object("NAME", "Los Santos International", "X1", 2051.630, "Y1", -2597.260, "X2", 2152.450, "Y2", -2394.330))
zones.Push(Object("NAME", "Mulholland", "X1", 1096.470, "Y1", -910.170, "X2", 1169.130, "Y2", -768.027))
zones.Push(Object("NAME", "Yellow Bell Gol Course", "X1", 1457.460, "Y1", 2723.230, "X2", 1534.560, "Y2", 2863.230))
zones.Push(Object("NAME", "The Strip", "X1", 2027.400, "Y1", 1783.230, "X2", 2162.390, "Y2", 1863.230))
zones.Push(Object("NAME", "Jefferson", "X1", 2056.860, "Y1", -1210.740, "X2", 2185.330, "Y2", -1126.320))
zones.Push(Object("NAME", "Mulholland", "X1", 952.604, "Y1", -937.184, "X2", 1096.470, "Y2", -860.619))
zones.Push(Object("NAME", "Aldea Malvada", "X1", -1372.140, "Y1", 2498.520, "X2", -1277.590, "Y2", 2615.350))
zones.Push(Object("NAME", "Las Colinas", "X1", 2126.860, "Y1", -1126.320, "X2", 2185.330, "Y2", -934.489))
zones.Push(Object("NAME", "Las Colinas", "X1", 1994.330, "Y1", -1100.820, "X2", 2056.860, "Y2", -920.815))
zones.Push(Object("NAME", "Richman", "X1", 647.557, "Y1", -954.662, "X2", 768.694, "Y2", -860.619))
zones.Push(Object("NAME", "LVA Freight Depot", "X1", 1277.050, "Y1", 1087.630, "X2", 1375.600, "Y2", 1203.280))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 1377.390, "Y1", 2433.230, "X2", 1534.560, "Y2", 2507.230))
zones.Push(Object("NAME", "Willowfield", "X1", 2201.820, "Y1", -2095.000, "X2", 2324.000, "Y2", -1989.900))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 1704.590, "Y1", 2342.830, "X2", 1848.400, "Y2", 2433.230))
zones.Push(Object("NAME", "Temple", "X1", 1252.330, "Y1", -1130.850, "X2", 1378.330, "Y2", -1026.330))
zones.Push(Object("NAME", "Little Mexico", "X1", 1701.900, "Y1", -1842.270, "X2", 1812.620, "Y2", -1722.260))
zones.Push(Object("NAME", "Queens", "X1", -2411.220, "Y1", 373.539, "X2", -2253.540, "Y2", 458.411))
zones.Push(Object("NAME", "Las Venturas Airport", "X1", 1515.810, "Y1", 1586.400, "X2", 1729.950, "Y2", 1714.560))
zones.Push(Object("NAME", "Richman", "X1", 225.165, "Y1", -1292.070, "X2", 466.223, "Y2", -1235.070))
zones.Push(Object("NAME", "Temple", "X1", 1252.330, "Y1", -1026.330, "X2", 1391.050, "Y2", -926.999))
zones.Push(Object("NAME", "East Los Santos", "X1", 2266.260, "Y1", -1494.030, "X2", 2381.680, "Y2", -1372.040))
zones.Push(Object("NAME", "Julius Thruway East", "X1", 2623.180, "Y1", 943.235, "X2", 2749.900, "Y2", 1055.960))
zones.Push(Object("NAME", "Willowfield", "X1", 2541.700, "Y1", -1941.400, "X2", 2703.580, "Y2", -1852.870))
zones.Push(Object("NAME", "Las Colinas", "X1", 2056.860, "Y1", -1126.320, "X2", 2126.860, "Y2", -920.815))
zones.Push(Object("NAME", "Julius Thruway East", "X1", 2625.160, "Y1", 2202.760, "X2", 2685.160, "Y2", 2442.550))
zones.Push(Object("NAME", "Rodeo", "X1", 225.165, "Y1", -1501.950, "X2", 334.503, "Y2", -1369.620))
zones.Push(Object("NAME", "Las Brujas", "X1", -365.167, "Y1", 2123.010, "X2", -208.570, "Y2", 2217.680))
zones.Push(Object("NAME", "Julius Thruway East", "X1", 2536.430, "Y1", 2442.550, "X2", 2685.160, "Y2", 2542.550))
zones.Push(Object("NAME", "Rodeo", "X1", 334.503, "Y1", -1406.050, "X2", 466.223, "Y2", -1292.070))
zones.Push(Object("NAME", "Vinewood", "X1", 647.557, "Y1", -1227.280, "X2", 787.461, "Y2", -1118.280))
zones.Push(Object("NAME", "Rodeo", "X1", 422.680, "Y1", -1684.650, "X2", 558.099, "Y2", -1570.200))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 2498.210, "Y1", 2542.550, "X2", 2685.160, "Y2", 2626.550))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1724.760, "Y1", -1430.870, "X2", 1812.620, "Y2", -1250.900))
zones.Push(Object("NAME", "Rodeo", "X1", 225.165, "Y1", -1684.650, "X2", 312.803, "Y2", -1501.950))
zones.Push(Object("NAME", "Jefferson", "X1", 2056.860, "Y1", -1449.670, "X2", 2266.210, "Y2", -1372.040))
zones.Push(Object("NAME", "Hampton Barns", "X1", 603.035, "Y1", 264.312, "X2", 761.994, "Y2", 366.572))
zones.Push(Object("NAME", "Temple", "X1", 1096.470, "Y1", -1130.840, "X2", 1252.330, "Y2", -1026.330))
zones.Push(Object("NAME", "Kincaid Bridge", "X1", -1087.930, "Y1", 855.370, "X2", -961.950, "Y2", 986.281))
zones.Push(Object("NAME", "Verona Beach", "X1", 1046.150, "Y1", -1722.260, "X2", 1161.520, "Y2", -1577.590))
zones.Push(Object("NAME", "Commerce", "X1", 1323.900, "Y1", -1722.260, "X2", 1440.900, "Y2", -1577.590))
zones.Push(Object("NAME", "Mulholland", "X1", 1357.000, "Y1", -926.999, "X2", 1463.900, "Y2", -768.027))
zones.Push(Object("NAME", "Rodeo", "X1", 466.223, "Y1", -1570.200, "X2", 558.099, "Y2", -1385.070))
zones.Push(Object("NAME", "Mulholland", "X1", 911.802, "Y1", -860.619, "X2", 1096.470, "Y2", -768.027))
zones.Push(Object("NAME", "Mulholland", "X1", 768.694, "Y1", -954.662, "X2", 952.604, "Y2", -860.619))
zones.Push(Object("NAME", "Julius Thruway South", "X1", 2377.390, "Y1", 788.894, "X2", 2537.390, "Y2", 897.901))
zones.Push(Object("NAME", "Idlewood", "X1", 1812.620, "Y1", -1852.870, "X2", 1971.660, "Y2", -1742.310))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2089.000, "Y1", -2394.330, "X2", 2201.820, "Y2", -2235.840))
zones.Push(Object("NAME", "Commerce", "X1", 1370.850, "Y1", -1577.590, "X2", 1463.900, "Y2", -1384.950))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 2121.400, "Y1", 2508.230, "X2", 2237.400, "Y2", 2663.170))
zones.Push(Object("NAME", "Temple", "X1", 1096.470, "Y1", -1026.330, "X2", 1252.330, "Y2", -910.170))
zones.Push(Object("NAME", "Glen Park", "X1", 1812.620, "Y1", -1449.670, "X2", 1996.910, "Y2", -1350.720))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1242.980, "Y1", -50.096, "X2", -1213.910, "Y2", 578.396))
zones.Push(Object("NAME", "Martin Bridge", "X1", -222.179, "Y1", 293.324, "X2", -122.126, "Y2", 476.465))
zones.Push(Object("NAME", "The Strip", "X1", 2106.700, "Y1", 1863.230, "X2", 2162.390, "Y2", 2202.760))
zones.Push(Object("NAME", "Willowfield", "X1", 2541.700, "Y1", -2059.230, "X2", 2703.580, "Y2", -1941.400))
zones.Push(Object("NAME", "Marina", "X1", 807.922, "Y1", -1577.590, "X2", 926.922, "Y2", -1416.250))
zones.Push(Object("NAME", "Las Venturas Airport", "X1", 1457.370, "Y1", 1143.210, "X2", 1777.400, "Y2", 1203.280))
zones.Push(Object("NAME", "Idlewood", "X1", 1812.620, "Y1", -1742.310, "X2", 1951.660, "Y2", -1602.310))
zones.Push(Object("NAME", "Esplanade East", "X1", -1580.010, "Y1", 1025.980, "X2", -1499.890, "Y2", 1274.260))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1370.850, "Y1", -1384.950, "X2", 1463.900, "Y2", -1170.870))
zones.Push(Object("NAME", "The Mako Span", "X1", 1664.620, "Y1", 401.750, "X2", 1785.140, "Y2", 567.203))
zones.Push(Object("NAME", "Rodeo", "X1", 312.803, "Y1", -1684.650, "X2", 422.680, "Y2", -1501.950))
zones.Push(Object("NAME", "Pershing Square", "X1", 1440.900, "Y1", -1722.260, "X2", 1583.500, "Y2", -1577.590))
zones.Push(Object("NAME", "Mulholland", "X1", 687.802, "Y1", -860.619, "X2", 911.802, "Y2", -768.027))
zones.Push(Object("NAME", "Gant Bridge", "X1", -2741.070, "Y1", 1490.470, "X2", -2616.400, "Y2", 1659.680))
zones.Push(Object("NAME", "Las Colinas", "X1", 2185.330, "Y1", -1154.590, "X2", 2281.450, "Y2", -934.489))
zones.Push(Object("NAME", "Mulholland", "X1", 1169.130, "Y1", -910.170, "X2", 1318.130, "Y2", -768.027))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 1938.800, "Y1", 2508.230, "X2", 2121.400, "Y2", 2624.230))
zones.Push(Object("NAME", "Commerce", "X1", 1667.960, "Y1", -1577.590, "X2", 1812.620, "Y2", -1430.870))
zones.Push(Object("NAME", "Rodeo", "X1", 72.648, "Y1", -1544.170, "X2", 225.165, "Y2", -1404.970))
zones.Push(Object("NAME", "Roca Escalante", "X1", 2536.430, "Y1", 2202.760, "X2", 2625.160, "Y2", 2442.550))
zones.Push(Object("NAME", "Rodeo", "X1", 72.648, "Y1", -1684.650, "X2", 225.165, "Y2", -1544.170))
zones.Push(Object("NAME", "Market", "X1", 952.663, "Y1", -1310.210, "X2", 1072.660, "Y2", -1130.850))
zones.Push(Object("NAME", "Las Colinas", "X1", 2632.740, "Y1", -1135.040, "X2", 2747.740, "Y2", -945.035))
zones.Push(Object("NAME", "Mulholland", "X1", 861.085, "Y1", -674.885, "X2", 1156.550, "Y2", -600.896))
zones.Push(Object("NAME", "King's", "X1", -2253.540, "Y1", 373.539, "X2", -1993.280, "Y2", 458.411))
zones.Push(Object("NAME", "Redsands East", "X1", 1848.400, "Y1", 2342.830, "X2", 2011.940, "Y2", 2478.490))
zones.Push(Object("NAME", "Downtown", "X1", -1580.010, "Y1", 744.267, "X2", -1499.890, "Y2", 1025.980))
zones.Push(Object("NAME", "Conference Center", "X1", 1046.150, "Y1", -1804.210, "X2", 1323.900, "Y2", -1722.260))
zones.Push(Object("NAME", "Richman", "X1", 647.557, "Y1", -1118.280, "X2", 787.461, "Y2", -954.662))
zones.Push(Object("NAME", "Ocean Flats", "X1", -2994.490, "Y1", 277.411, "X2", -2867.850, "Y2", 458.411))
zones.Push(Object("NAME", "Greenglass College", "X1", 964.391, "Y1", 930.890, "X2", 1166.530, "Y2", 1044.690))
zones.Push(Object("NAME", "Glen Park", "X1", 1812.620, "Y1", -1100.820, "X2", 1994.330, "Y2", -973.380))
zones.Push(Object("NAME", "LVA Freight Depot", "X1", 1375.600, "Y1", 919.447, "X2", 1457.370, "Y2", 1203.280))
zones.Push(Object("NAME", "Regular Tom", "X1", -405.770, "Y1", 1712.860, "X2", -276.719, "Y2", 1892.750))
zones.Push(Object("NAME", "Verona Beach", "X1", 1161.520, "Y1", -1722.260, "X2", 1323.900, "Y2", -1577.590))
zones.Push(Object("NAME", "East Los Santos", "X1", 2281.450, "Y1", -1372.040, "X2", 2381.680, "Y2", -1135.040))
zones.Push(Object("NAME", "Caligula's Palace", "X1", 2137.400, "Y1", 1703.230, "X2", 2437.390, "Y2", 1783.230))
zones.Push(Object("NAME", "Idlewood", "X1", 1951.660, "Y1", -1742.310, "X2", 2124.660, "Y2", -1602.310))
zones.Push(Object("NAME", "Pilgrim", "X1", 2624.400, "Y1", 1383.230, "X2", 2685.160, "Y2", 1783.230))
zones.Push(Object("NAME", "Idlewood", "X1", 2124.660, "Y1", -1742.310, "X2", 2222.560, "Y2", -1494.030))
zones.Push(Object("NAME", "Queens", "X1", -2533.040, "Y1", 458.411, "X2", -2329.310, "Y2", 578.396))
zones.Push(Object("NAME", "Downtown", "X1", -1871.720, "Y1", 1176.420, "X2", -1620.300, "Y2", 1274.260))
zones.Push(Object("NAME", "Commerce", "X1", 1583.500, "Y1", -1722.260, "X2", 1758.900, "Y2", -1577.590))
zones.Push(Object("NAME", "East Los Santos", "X1", 2381.680, "Y1", -1454.350, "X2", 2462.130, "Y2", -1135.040))
zones.Push(Object("NAME", "Marina", "X1", 647.712, "Y1", -1577.590, "X2", 807.922, "Y2", -1416.250))
zones.Push(Object("NAME", "Richman", "X1", 72.648, "Y1", -1404.970, "X2", 225.165, "Y2", -1235.070))
zones.Push(Object("NAME", "Vinewood", "X1", 647.712, "Y1", -1416.250, "X2", 787.461, "Y2", -1227.280))
zones.Push(Object("NAME", "East Los Santos", "X1", 2222.560, "Y1", -1628.530, "X2", 2421.030, "Y2", -1494.030))
zones.Push(Object("NAME", "Rodeo", "X1", 558.099, "Y1", -1684.650, "X2", 647.522, "Y2", -1384.930))
zones.Push(Object("NAME", "Easter Tunnel", "X1", -1709.710, "Y1", -833.034, "X2", -1446.010, "Y2", -730.118))
zones.Push(Object("NAME", "Rodeo", "X1", 466.223, "Y1", -1385.070, "X2", 647.522, "Y2", -1235.070))
zones.Push(Object("NAME", "Redsands East", "X1", 1817.390, "Y1", 2202.760, "X2", 2011.940, "Y2", 2342.830))
zones.Push(Object("NAME", "The Clown's Pocket", "X1", 2162.390, "Y1", 1783.230, "X2", 2437.390, "Y2", 1883.230))
zones.Push(Object("NAME", "Idlewood", "X1", 1971.660, "Y1", -1852.870, "X2", 2222.560, "Y2", -1742.310))
zones.Push(Object("NAME", "Montgomery Intersection", "X1", 1546.650, "Y1", 208.164, "X2", 1745.830, "Y2", 347.457))
zones.Push(Object("NAME", "Willowfield", "X1", 2089.000, "Y1", -2235.840, "X2", 2201.820, "Y2", -1989.900))
zones.Push(Object("NAME", "Temple", "X1", 952.663, "Y1", -1130.840, "X2", 1096.470, "Y2", -937.184))
zones.Push(Object("NAME", "Prickle Pine", "X1", 1848.400, "Y1", 2553.490, "X2", 1938.800, "Y2", 2863.230))
zones.Push(Object("NAME", "Los Santos International", "X1", 1400.970, "Y1", -2669.260, "X2", 2189.820, "Y2", -2597.260))
zones.Push(Object("NAME", "Garver Bridge", "X1", -1213.910, "Y1", 950.022, "X2", -1087.930, "Y2", 1178.930))
zones.Push(Object("NAME", "Garver Bridge", "X1", -1339.890, "Y1", 828.129, "X2", -1213.910, "Y2", 1057.040))
zones.Push(Object("NAME", "Kincaid Bridge", "X1", -1339.890, "Y1", 599.218, "X2", -1213.910, "Y2", 828.129))
zones.Push(Object("NAME", "Kincaid Bridge", "X1", -1213.910, "Y1", 721.111, "X2", -1087.930, "Y2", 950.022))
zones.Push(Object("NAME", "Verona Beach", "X1", 930.221, "Y1", -2006.780, "X2", 1073.220, "Y2", -1804.210))
zones.Push(Object("NAME", "Verdant Bluffs", "X1", 1073.220, "Y1", -2006.780, "X2", 1249.620, "Y2", -1842.270))
zones.Push(Object("NAME", "Vinewood", "X1", 787.461, "Y1", -1130.840, "X2", 952.604, "Y2", -954.662))
zones.Push(Object("NAME", "Vinewood", "X1", 787.461, "Y1", -1310.210, "X2", 952.663, "Y2", -1130.840))
zones.Push(Object("NAME", "Commerce", "X1", 1463.900, "Y1", -1577.590, "X2", 1667.960, "Y2", -1430.870))
zones.Push(Object("NAME", "Market", "X1", 787.461, "Y1", -1416.250, "X2", 1072.660, "Y2", -1310.210))
zones.Push(Object("NAME", "Rockshore West", "X1", 2377.390, "Y1", 596.349, "X2", 2537.390, "Y2", 788.894))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 2237.400, "Y1", 2542.550, "X2", 2498.210, "Y2", 2663.170))
zones.Push(Object("NAME", "East Beach", "X1", 2632.830, "Y1", -1668.130, "X2", 2747.740, "Y2", -1393.420))
zones.Push(Object("NAME", "Fallow Bridge", "X1", 434.341, "Y1", 366.572, "X2", 603.035, "Y2", 555.680))
zones.Push(Object("NAME", "Willowfield", "X1", 2089.000, "Y1", -1989.900, "X2", 2324.000, "Y2", -1852.870))
zones.Push(Object("NAME", "Chinatown", "X1", -2274.170, "Y1", 578.396, "X2", -2078.670, "Y2", 744.170))
zones.Push(Object("NAME", "El Castillo del Diablo", "X1", -208.570, "Y1", 2337.180, "X2", 8.430, "Y2", 2487.180))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2324.000, "Y1", -2145.100, "X2", 2703.580, "Y2", -2059.230))
zones.Push(Object("NAME", "Easter Bay Chemicals", "X1", -1132.820, "Y1", -768.027, "X2", -956.476, "Y2", -578.118))
zones.Push(Object("NAME", "The Visage", "X1", 1817.390, "Y1", 1703.230, "X2", 2027.400, "Y2", 1863.230))
zones.Push(Object("NAME", "Ocean Flats", "X1", -2994.490, "Y1", -430.276, "X2", -2831.890, "Y2", -222.589))
zones.Push(Object("NAME", "Richman", "X1", 321.356, "Y1", -860.619, "X2", 687.802, "Y2", -768.027))
zones.Push(Object("NAME", "Green Palms", "X1", 176.581, "Y1", 1305.450, "X2", 338.658, "Y2", 1520.720))
zones.Push(Object("NAME", "Richman", "X1", 321.356, "Y1", -768.027, "X2", 700.794, "Y2", -674.885))
zones.Push(Object("NAME", "Starfish Casino", "X1", 2162.390, "Y1", 1883.230, "X2", 2437.390, "Y2", 2012.180))
zones.Push(Object("NAME", "East Beach", "X1", 2747.740, "Y1", -1668.130, "X2", 2959.350, "Y2", -1498.620))
zones.Push(Object("NAME", "Jefferson", "X1", 2056.860, "Y1", -1372.040, "X2", 2281.450, "Y2", -1210.740))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1463.900, "Y1", -1290.870, "X2", 1724.760, "Y2", -1150.870))
zones.Push(Object("NAME", "Downtown Los Santos", "X1", 1463.900, "Y1", -1430.870, "X2", 1724.760, "Y2", -1290.870))
zones.Push(Object("NAME", "Garver Bridge", "X1", -1499.890, "Y1", 696.442, "X2", -1339.890, "Y2", 925.353))
zones.Push(Object("NAME", "Julius Thruway South", "X1", 1457.390, "Y1", 823.228, "X2", 2377.390, "Y2", 863.229))
zones.Push(Object("NAME", "East Los Santos", "X1", 2421.030, "Y1", -1628.530, "X2", 2632.830, "Y2", -1454.350))
zones.Push(Object("NAME", "Greenglass College", "X1", 964.391, "Y1", 1044.690, "X2", 1197.390, "Y2", 1203.220))
zones.Push(Object("NAME", "Las Colinas", "X1", 2747.740, "Y1", -1120.040, "X2", 2959.350, "Y2", -945.035))
zones.Push(Object("NAME", "Mulholland", "X1", 737.573, "Y1", -768.027, "X2", 1142.290, "Y2", -674.885))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2201.820, "Y1", -2730.880, "X2", 2324.000, "Y2", -2418.330))
zones.Push(Object("NAME", "East Los Santos", "X1", 2462.130, "Y1", -1454.350, "X2", 2581.730, "Y2", -1135.040))
zones.Push(Object("NAME", "Ganton", "X1", 2222.560, "Y1", -1722.330, "X2", 2632.830, "Y2", -1628.530))
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2831.890, "Y1", -430.276, "X2", -2646.400, "Y2", -222.589))
zones.Push(Object("NAME", "Willowfield", "X1", 1970.620, "Y1", -2179.250, "X2", 2089.000, "Y2", -1852.870))
zones.Push(Object("NAME", "Esplanade North", "X1", -1982.320, "Y1", 1274.260, "X2", -1524.240, "Y2", 1358.900))
zones.Push(Object("NAME", "The High Roller", "X1", 1817.390, "Y1", 1283.230, "X2", 2027.390, "Y2", 1469.230))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2201.820, "Y1", -2418.330, "X2", 2324.000, "Y2", -2095.000))
zones.Push(Object("NAME", "Last Dime Motel", "X1", 1823.080, "Y1", 596.349, "X2", 1997.220, "Y2", 823.228))
zones.Push(Object("NAME", "Bayside Marina", "X1", -2353.170, "Y1", 2275.790, "X2", -2153.170, "Y2", 2475.790))
zones.Push(Object("NAME", "King's", "X1", -2329.310, "Y1", 458.411, "X2", -1993.280, "Y2", 578.396))
zones.Push(Object("NAME", "El Corona", "X1", 1692.620, "Y1", -2179.250, "X2", 1812.620, "Y2", -1842.270))
zones.Push(Object("NAME", "Blackfield Chapel", "X1", 1375.600, "Y1", 596.349, "X2", 1558.090, "Y2", 823.228))
zones.Push(Object("NAME", "The Pink Swan", "X1", 1817.390, "Y1", 1083.230, "X2", 2027.390, "Y2", 1283.230))
zones.Push(Object("NAME", "Julius Thruway West", "X1", 1197.390, "Y1", 1163.390, "X2", 1236.630, "Y2", 2243.230))
zones.Push(Object("NAME", "Los Flores", "X1", 2581.730, "Y1", -1393.420, "X2", 2747.740, "Y2", -1135.040))
zones.Push(Object("NAME", "The Visage", "X1", 1817.390, "Y1", 1863.230, "X2", 2106.700, "Y2", 2011.830))
zones.Push(Object("NAME", "Prickle Pine", "X1", 1938.800, "Y1", 2624.230, "X2", 2121.400, "Y2", 2861.550))
zones.Push(Object("NAME", "Verona Beach", "X1", 851.449, "Y1", -1804.210, "X2", 1046.150, "Y2", -1577.590))
zones.Push(Object("NAME", "Robada Intersection", "X1", -1119.010, "Y1", 1178.930, "X2", -862.025, "Y2", 1351.450))
zones.Push(Object("NAME", "Linden Side", "X1", 2749.900, "Y1", 943.235, "X2", 2923.390, "Y2", 1198.990))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2703.580, "Y1", -2302.330, "X2", 2959.350, "Y2", -2126.900))
zones.Push(Object("NAME", "Willowfield", "X1", 2324.000, "Y1", -2059.230, "X2", 2541.700, "Y2", -1852.870))
zones.Push(Object("NAME", "King's", "X1", -2411.220, "Y1", 265.243, "X2", -1993.280, "Y2", 373.539))
zones.Push(Object("NAME", "Commerce", "X1", 1323.900, "Y1", -1842.270, "X2", 1701.900, "Y2", -1722.260))
zones.Push(Object("NAME", "Mulholland", "X1", 1269.130, "Y1", -768.027, "X2", 1414.070, "Y2", -452.425))
zones.Push(Object("NAME", "Marina", "X1", 647.712, "Y1", -1804.210, "X2", 851.449, "Y2", -1577.590))
zones.Push(Object("NAME", "Battery Point", "X1", -2741.070, "Y1", 1268.410, "X2", -2533.040, "Y2", 1490.470))
zones.Push(Object("NAME", "The Four Dragons Casino", "X1", 1817.390, "Y1", 863.232, "X2", 2027.390, "Y2", 1083.230))
zones.Push(Object("NAME", "Blackfield", "X1", 964.391, "Y1", 1203.220, "X2", 1197.390, "Y2", 1403.220))
zones.Push(Object("NAME", "Julius Thruway North", "X1", 1534.560, "Y1", 2433.230, "X2", 1848.400, "Y2", 2583.230))
zones.Push(Object("NAME", "Yellow Bell Gol Course", "X1", 1117.400, "Y1", 2723.230, "X2", 1457.460, "Y2", 2863.230))
zones.Push(Object("NAME", "Idlewood", "X1", 1812.620, "Y1", -1602.310, "X2", 2124.660, "Y2", -1449.670))
zones.Push(Object("NAME", "Redsands West", "X1", 1297.470, "Y1", 2142.860, "X2", 1777.390, "Y2", 2243.230))
zones.Push(Object("NAME", "Doherty", "X1", -2270.040, "Y1", -324.114, "X2", -1794.920, "Y2", -222.589))
zones.Push(Object("NAME", "Hilltop Farm", "X1", 967.383, "Y1", -450.390, "X2", 1176.780, "Y2", -217.900))
zones.Push(Object("NAME", "Las Barrancas", "X1", -926.130, "Y1", 1398.730, "X2", -719.234, "Y2", 1634.690))
zones.Push(Object("NAME", "Pirates in Men's Pants", "X1", 1817.390, "Y1", 1469.230, "X2", 2027.400, "Y2", 1703.230))
zones.Push(Object("NAME", "City Hall", "X1", -2867.850, "Y1", 277.411, "X2", -2593.440, "Y2", 458.411))
zones.Push(Object("NAME", "Avispa Country Club", "X1", -2646.400, "Y1", -355.493, "X2", -2270.040, "Y2", -222.589))
zones.Push(Object("NAME", "The Strip", "X1", 2027.400, "Y1", 863.229, "X2", 2087.390, "Y2", 1703.230))
zones.Push(Object("NAME", "Hashbury", "X1", -2593.440, "Y1", -222.589, "X2", -2411.220, "Y2", 54.722))
zones.Push(Object("NAME", "Los Santos International", "X1", 1852.000, "Y1", -2394.330, "X2", 2089.000, "Y2", -2179.250))
zones.Push(Object("NAME", "Whitewood Estates", "X1", 1098.310, "Y1", 1726.220, "X2", 1197.390, "Y2", 2243.230))
zones.Push(Object("NAME", "Sherman Reservoir", "X1", -789.737, "Y1", 1659.680, "X2", -599.505, "Y2", 1929.410))
zones.Push(Object("NAME", "El Corona", "X1", 1812.620, "Y1", -2179.250, "X2", 1970.620, "Y2", -1852.870))
zones.Push(Object("NAME", "Downtown", "X1", -1700.010, "Y1", 744.267, "X2", -1580.010, "Y2", 1176.520))
zones.Push(Object("NAME", "Foster Valley", "X1", -2178.690, "Y1", -1250.970, "X2", -1794.920, "Y2", -1115.580))
zones.Push(Object("NAME", "Las Payasadas", "X1", -354.332, "Y1", 2580.360, "X2", -133.625, "Y2", 2816.820))
zones.Push(Object("NAME", "Valle Ocultado", "X1", -936.668, "Y1", 2611.440, "X2", -715.961, "Y2", 2847.900))
zones.Push(Object("NAME", "Blackfield Intersection", "X1", 1166.530, "Y1", 795.010, "X2", 1375.600, "Y2", 1044.690))
zones.Push(Object("NAME", "Ganton", "X1", 2222.560, "Y1", -1852.870, "X2", 2632.830, "Y2", -1722.330))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1213.910, "Y1", -730.118, "X2", -1132.820, "Y2", -50.096))
zones.Push(Object("NAME", "Redsands East", "X1", 1817.390, "Y1", 2011.830, "X2", 2106.700, "Y2", 2202.760))
zones.Push(Object("NAME", "Esplanade East", "X1", -1499.890, "Y1", 578.396, "X2", -1339.890, "Y2", 1274.260))
zones.Push(Object("NAME", "Caligula's Palace", "X1", 2087.390, "Y1", 1543.230, "X2", 2437.390, "Y2", 1703.230))
zones.Push(Object("NAME", "Royal Casino", "X1", 2087.390, "Y1", 1383.230, "X2", 2437.390, "Y2", 1543.230))
zones.Push(Object("NAME", "Richman", "X1", 72.648, "Y1", -1235.070, "X2", 321.356, "Y2", -1008.150))
zones.Push(Object("NAME", "Starfish Casino", "X1", 2437.390, "Y1", 1783.230, "X2", 2685.160, "Y2", 2012.180))
zones.Push(Object("NAME", "Mulholland", "X1", 1281.130, "Y1", -452.425, "X2", 1641.130, "Y2", -290.913))
zones.Push(Object("NAME", "Downtown", "X1", -1982.320, "Y1", 744.170, "X2", -1871.720, "Y2", 1274.260))
zones.Push(Object("NAME", "Hankypanky Point", "X1", 2576.920, "Y1", 62.158, "X2", 2759.250, "Y2", 385.503))
zones.Push(Object("NAME", "K.A.C.C. Military Fuels", "X1", 2498.210, "Y1", 2626.550, "X2", 2749.900, "Y2", 2861.550))
zones.Push(Object("NAME", "Harry Gold Parkway", "X1", 1777.390, "Y1", 863.232, "X2", 1817.390, "Y2", 2342.830))
zones.Push(Object("NAME", "Bayside Tunnel", "X1", -2290.190, "Y1", 2548.290, "X2", -1950.190, "Y2", 2723.290))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2324.000, "Y1", -2302.330, "X2", 2703.580, "Y2", -2145.100))
zones.Push(Object("NAME", "Richman", "X1", 321.356, "Y1", -1044.070, "X2", 647.557, "Y2", -860.619))
zones.Push(Object("NAME", "Randolph Industrial Estate", "X1", 1558.090, "Y1", 596.349, "X2", 1823.080, "Y2", 823.235))
zones.Push(Object("NAME", "East Beach", "X1", 2632.830, "Y1", -1852.870, "X2", 2959.350, "Y2", -1668.130))
zones.Push(Object("NAME", "Flint Water", "X1", -314.426, "Y1", -753.874, "X2", -106.339, "Y2", -463.073))
zones.Push(Object("NAME", "Blueberry", "X1", 19.607, "Y1", -404.136, "X2", 349.607, "Y2", -220.137))
zones.Push(Object("NAME", "Linden Station", "X1", 2749.900, "Y1", 1198.990, "X2", 2923.390, "Y2", 1548.990))
zones.Push(Object("NAME", "Glen Park", "X1", 1812.620, "Y1", -1350.720, "X2", 2056.860, "Y2", -1100.820))
zones.Push(Object("NAME", "Downtown", "X1", -1993.280, "Y1", 265.243, "X2", -1794.920, "Y2", 578.396))
zones.Push(Object("NAME", "Redsands West", "X1", 1377.390, "Y1", 2243.230, "X2", 1704.590, "Y2", 2433.230))
zones.Push(Object("NAME", "Richman", "X1", 321.356, "Y1", -1235.070, "X2", 647.522, "Y2", -1044.070))
zones.Push(Object("NAME", "Gant Bridge", "X1", -2741.450, "Y1", 1659.680, "X2", -2616.400, "Y2", 2175.150))
zones.Push(Object("NAME", "Lil' Probe Inn", "X1", -90.218, "Y1", 1286.850, "X2", 153.859, "Y2", 1554.120))
zones.Push(Object("NAME", "Flint Intersection", "X1", -187.700, "Y1", -1596.760, "X2", 17.063, "Y2", -1276.600))
zones.Push(Object("NAME", "Las Colinas", "X1", 2281.450, "Y1", -1135.040, "X2", 2632.740, "Y2", -945.035))
zones.Push(Object("NAME", "Sobell Rail Yards", "X1", 2749.900, "Y1", 1548.990, "X2", 2923.390, "Y2", 1937.250))
zones.Push(Object("NAME", "The Emerald Isle", "X1", 2011.940, "Y1", 2202.760, "X2", 2237.400, "Y2", 2508.230))
zones.Push(Object("NAME", "El Castillo del Diablo", "X1", -208.570, "Y1", 2123.010, "X2", 114.033, "Y2", 2337.180))
zones.Push(Object("NAME", "Santa Flora", "X1", -2741.070, "Y1", 458.411, "X2", -2533.040, "Y2", 793.411))
zones.Push(Object("NAME", "Playa del Seville", "X1", 2703.580, "Y1", -2126.900, "X2", 2959.350, "Y2", -1852.870))
zones.Push(Object("NAME", "Market", "X1", 926.922, "Y1", -1577.590, "X2", 1370.850, "Y2", -1416.250))
zones.Push(Object("NAME", "Queens", "X1", -2593.440, "Y1", 54.722, "X2", -2411.220, "Y2", 458.411))
zones.Push(Object("NAME", "Pilson Intersection", "X1", 1098.390, "Y1", 2243.230, "X2", 1377.390, "Y2", 2507.230))
zones.Push(Object("NAME", "Spinybed", "X1", 2121.400, "Y1", 2663.170, "X2", 2498.210, "Y2", 2861.550))
zones.Push(Object("NAME", "Pilgrim", "X1", 2437.390, "Y1", 1383.230, "X2", 2624.400, "Y2", 1783.230))
zones.Push(Object("NAME", "Blackfield", "X1", 964.391, "Y1", 1403.220, "X2", 1197.390, "Y2", 1726.220))
zones.Push(Object("NAME", "'The Big Ear'", "X1", -410.020, "Y1", 1403.340, "X2", -137.969, "Y2", 1681.230))
zones.Push(Object("NAME", "Dillimore", "X1", 580.794, "Y1", -674.885, "X2", 861.085, "Y2", -404.790))
zones.Push(Object("NAME", "El Quebrados", "X1", -1645.230, "Y1", 2498.520, "X2", -1372.140, "Y2", 2777.850))
zones.Push(Object("NAME", "Esplanade North", "X1", -2533.040, "Y1", 1358.900, "X2", -1996.660, "Y2", 1501.210))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1499.890, "Y1", -50.096, "X2", -1242.980, "Y2", 249.904))
zones.Push(Object("NAME", "Fisher's Lagoon", "X1", 1916.990, "Y1", -233.323, "X2", 2131.720, "Y2", 13.800))
zones.Push(Object("NAME", "Mulholland", "X1", 1414.070, "Y1", -768.027, "X2", 1667.610, "Y2", -452.425))
zones.Push(Object("NAME", "East Beach", "X1", 2747.740, "Y1", -1498.620, "X2", 2959.350, "Y2", -1120.040))
zones.Push(Object("NAME", "San Andreas Sound", "X1", 2450.390, "Y1", 385.503, "X2", 2759.250, "Y2", 562.349))
zones.Push(Object("NAME", "Shady Creeks", "X1", -2030.120, "Y1", -2174.890, "X2", -1820.640, "Y2", -1771.660))
zones.Push(Object("NAME", "Market", "X1", 1072.660, "Y1", -1416.250, "X2", 1370.850, "Y2", -1130.850))
zones.Push(Object("NAME", "Rockshore West", "X1", 1997.220, "Y1", 596.349, "X2", 2377.390, "Y2", 823.228))
zones.Push(Object("NAME", "Prickle Pine", "X1", 1534.560, "Y1", 2583.230, "X2", 1848.400, "Y2", 2863.230))
zones.Push(Object("NAME", "Easter Basin", "X1", -1794.920, "Y1", -50.096, "X2", -1499.890, "Y2", 249.904))
zones.Push(Object("NAME", "Leafy Hollow", "X1", -1166.970, "Y1", -1856.030, "X2", -815.624, "Y2", -1602.070))
zones.Push(Object("NAME", "LVA Freight Depot", "X1", 1457.390, "Y1", 863.229, "X2", 1777.400, "Y2", 1143.210))
zones.Push(Object("NAME", "Prickle Pine", "X1", 1117.400, "Y1", 2507.230, "X2", 1534.560, "Y2", 2723.230))
zones.Push(Object("NAME", "Blueberry", "X1", 104.534, "Y1", -220.137, "X2", 349.607, "Y2", 152.236))
zones.Push(Object("NAME", "El Castillo del Diablo", "X1", -464.515, "Y1", 2217.680, "X2", -208.570, "Y2", 2580.360))
zones.Push(Object("NAME", "Downtown", "X1", -2078.670, "Y1", 578.396, "X2", -1499.890, "Y2", 744.267))
zones.Push(Object("NAME", "Rockshore East", "X1", 2537.390, "Y1", 676.549, "X2", 2902.350, "Y2", 943.235))
zones.Push(Object("NAME", "San Fierro Bay", "X1", -2616.400, "Y1", 1501.210, "X2", -1996.660, "Y2", 1659.680))
zones.Push(Object("NAME", "Paradiso", "X1", -2741.070, "Y1", 793.411, "X2", -2533.040, "Y2", 1268.410))
zones.Push(Object("NAME", "The Camel's Toe", "X1", 2087.390, "Y1", 1203.230, "X2", 2640.400, "Y2", 1383.230))
zones.Push(Object("NAME", "Old Venturas Strip", "X1", 2162.390, "Y1", 2012.180, "X2", 2685.160, "Y2", 2202.760))
zones.Push(Object("NAME", "Juniper Hill", "X1", -2533.040, "Y1", 578.396, "X2", -2274.170, "Y2", 968.369))
zones.Push(Object("NAME", "Juniper Hollow", "X1", -2533.040, "Y1", 968.369, "X2", -2274.170, "Y2", 1358.900))
zones.Push(Object("NAME", "Roca Escalante", "X1", 2237.400, "Y1", 2202.760, "X2", 2536.430, "Y2", 2542.550))
zones.Push(Object("NAME", "Julius Thruway East", "X1", 2685.160, "Y1", 1055.960, "X2", 2749.900, "Y2", 2626.550))
zones.Push(Object("NAME", "Verona Beach", "X1", 647.712, "Y1", -2173.290, "X2", 930.221, "Y2", -1804.210))
zones.Push(Object("NAME", "Foster Valley", "X1", -2178.690, "Y1", -599.884, "X2", -1794.920, "Y2", -324.114))
zones.Push(Object("NAME", "Arco del Oeste", "X1", -901.129, "Y1", 2221.860, "X2", -592.090, "Y2", 2571.970))
zones.Push(Object("NAME", "Fallen Tree", "X1", -792.254, "Y1", -698.555, "X2", -452.404, "Y2", -380.043))
zones.Push(Object("NAME", "The Farm", "X1", -1209.670, "Y1", -1317.100, "X2", -908.161, "Y2", -787.391))
zones.Push(Object("NAME", "The Sherman Dam", "X1", -968.772, "Y1", 1929.410, "X2", -481.126, "Y2", 2155.260))
zones.Push(Object("NAME", "Esplanade North", "X1", -1996.660, "Y1", 1358.900, "X2", -1524.240, "Y2", 1592.510))
zones.Push(Object("NAME", "Financial", "X1", -1871.720, "Y1", 744.170, "X2", -1701.300, "Y2", 1176.420))
zones.Push(Object("NAME", "Garcia", "X1", -2411.220, "Y1", -222.589, "X2", -2173.040, "Y2", 265.243))
zones.Push(Object("NAME", "Montgomery", "X1", 1119.510, "Y1", 119.526, "X2", 1451.400, "Y2", 493.323))
zones.Push(Object("NAME", "Creek", "X1", 2749.900, "Y1", 1937.250, "X2", 2921.620, "Y2", 2669.790))
zones.Push(Object("NAME", "Los Santos International", "X1", 1249.620, "Y1", -2394.330, "X2", 1852.000, "Y2", -2179.250))
zones.Push(Object("NAME", "Santa Maria Beach", "X1", 72.648, "Y1", -2173.290, "X2", 342.648, "Y2", -1684.650))
zones.Push(Object("NAME", "Mulholland Intersection", "X1", 1463.900, "Y1", -1150.870, "X2", 1812.620, "Y2", -768.027))
zones.Push(Object("NAME", "Angel Pine", "X1", -2324.940, "Y1", -2584.290, "X2", -1964.220, "Y2", -2212.110))
zones.Push(Object("NAME", "Verdant Meadows", "X1", 37.032, "Y1", 2337.180, "X2", 435.988, "Y2", 2677.900))
zones.Push(Object("NAME", "Octane Springs", "X1", 338.658, "Y1", 1228.510, "X2", 664.308, "Y2", 1655.050))
zones.Push(Object("NAME", "Come-A-Lot", "X1", 2087.390, "Y1", 943.235, "X2", 2623.180, "Y2", 1203.230))
zones.Push(Object("NAME", "Redsands West", "X1", 1236.630, "Y1", 1883.110, "X2", 1777.390, "Y2", 2142.860))
zones.Push(Object("NAME", "Santa Maria Beach", "X1", 342.648, "Y1", -2173.290, "X2", 647.712, "Y2", -1684.650))
zones.Push(Object("NAME", "Verdant Bluffs", "X1", 1249.620, "Y1", -2179.250, "X2", 1692.620, "Y2", -1842.270))
zones.Push(Object("NAME", "Las Venturas Airport", "X1", 1236.630, "Y1", 1203.280, "X2", 1457.370, "Y2", 1883.110))
zones.Push(Object("NAME", "Flint Range", "X1", -594.191, "Y1", -1648.550, "X2", -187.700, "Y2", -1276.600))
zones.Push(Object("NAME", "Verdant Bluffs", "X1", 930.221, "Y1", -2488.420, "X2", 1249.620, "Y2", -2006.780))
zones.Push(Object("NAME", "Palomino Creek", "X1", 2160.220, "Y1", -149.004, "X2", 2576.920, "Y2", 228.322))
zones.Push(Object("NAME", "Ocean Docks", "X1", 2373.770, "Y1", -2697.090, "X2", 2809.220, "Y2", -2330.460))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1213.910, "Y1", -50.096, "X2", -947.980, "Y2", 578.396))
zones.Push(Object("NAME", "Whitewood Estates", "X1", 883.308, "Y1", 1726.220, "X2", 1098.310, "Y2", 2507.230))
zones.Push(Object("NAME", "Calton Heights", "X1", -2274.170, "Y1", 744.170, "X2", -1982.320, "Y2", 1358.900))
zones.Push(Object("NAME", "Easter Basin", "X1", -1794.920, "Y1", 249.904, "X2", -1242.980, "Y2", 578.396))
zones.Push(Object("NAME", "Los Santos Inlet", "X1", -321.744, "Y1", -2224.430, "X2", 44.615, "Y2", -1724.430))
zones.Push(Object("NAME", "Doherty", "X1", -2173.040, "Y1", -222.589, "X2", -1794.920, "Y2", 265.243))
zones.Push(Object("NAME", "Mount Chiliad", "X1", -2178.690, "Y1", -2189.910, "X2", -2030.120, "Y2", -1771.660))
zones.Push(Object("NAME", "Fort Carson", "X1", -376.233, "Y1", 826.326, "X2", 123.717, "Y2", 1220.440))
zones.Push(Object("NAME", "Foster Valley", "X1", -2178.690, "Y1", -1115.580, "X2", -1794.920, "Y2", -599.884))
zones.Push(Object("NAME", "Ocean Flats", "X1", -2994.490, "Y1", -222.589, "X2", -2593.440, "Y2", 277.411))
zones.Push(Object("NAME", "Fern Ridge", "X1", 508.189, "Y1", -139.259, "X2", 1306.660, "Y2", 119.526))
zones.Push(Object("NAME", "Bayside", "X1", -2741.070, "Y1", 2175.150, "X2", -2353.170, "Y2", 2722.790))
zones.Push(Object("NAME", "Las Venturas Airport", "X1", 1457.370, "Y1", 1203.280, "X2", 1777.390, "Y2", 1883.110))
zones.Push(Object("NAME", "Blueberry Acres", "X1", -319.676, "Y1", -220.137, "X2", 104.534, "Y2", 293.324))
zones.Push(Object("NAME", "Palisades", "X1", -2994.490, "Y1", 458.411, "X2", -2741.070, "Y2", 1339.610))
zones.Push(Object("NAME", "North Rock", "X1", 2285.370, "Y1", -768.027, "X2", 2770.590, "Y2", -269.740))
zones.Push(Object("NAME", "Hunter Quarry", "X1", 337.244, "Y1", 710.840, "X2", 860.554, "Y2", 1031.710))
zones.Push(Object("NAME", "Los Santos International", "X1", 1382.730, "Y1", -2730.880, "X2", 2201.820, "Y2", -2394.330))
zones.Push(Object("NAME", "Missionary Hill", "X1", -2994.490, "Y1", -811.276, "X2", -2178.690, "Y2", -430.276))
zones.Push(Object("NAME", "San Fierro Bay", "X1", -2616.400, "Y1", 1659.680, "X2", -1996.660, "Y2", 2175.150))
zones.Push(Object("NAME", "Restricted Area", "X1", -91.586, "Y1", 1655.050, "X2", 421.234, "Y2", 2123.010))
zones.Push(Object("NAME", "Mount Chiliad", "X1", -2997.470, "Y1", -1115.580, "X2", -2178.690, "Y2", -971.913))
zones.Push(Object("NAME", "Mount Chiliad", "X1", -2178.690, "Y1", -1771.660, "X2", -1936.120, "Y2", -1250.970))
zones.Push(Object("NAME", "Easter Bay Airport", "X1", -1794.920, "Y1", -730.118, "X2", -1213.910, "Y2", -50.096))
zones.Push(Object("NAME", "The Panopticon", "X1", -947.980, "Y1", -304.320, "X2", -319.676, "Y2", 327.071))
zones.Push(Object("NAME", "Shady Creeks", "X1", -1820.640, "Y1", -2643.680, "X2", -1226.780, "Y2", -1771.660))
zones.Push(Object("NAME", "Back o Beyond", "X1", -1166.970, "Y1", -2641.190, "X2", -321.744, "Y2", -1856.030))
zones.Push(Object("NAME", "Mount Chiliad", "X1", -2994.490, "Y1", -2189.910, "X2", -2178.690, "Y2", -1115.580))
zones.Push(Object("NAME", "Tierra Robada", "X1", -1213.910, "Y1", 596.349, "X2", -480.539, "Y2", 1659.680))
zones.Push(Object("NAME", "Flint County", "X1", -1213.910, "Y1", -2892.970, "X2", 44.615, "Y2", -768.027))
zones.Push(Object("NAME", "Whetstone", "X1", -2997.470, "Y1", -2892.970, "X2", -1213.910, "Y2", -1115.580))
zones.Push(Object("NAME", "Bone County", "X1", -480.539, "Y1", 596.349, "X2", 869.461, "Y2", 2993.870))
zones.Push(Object("NAME", "Tierra Robada", "X1", -2997.470, "Y1", 1659.680, "X2", -480.539, "Y2", 2993.870))
zones.Push(Object("NAME", "San Fierro", "X1", -2997.470, "Y1", -1115.580, "X2", -1213.910, "Y2", 1659.680))
zones.Push(Object("NAME", "Las Venturas", "X1", 869.461, "Y1", 596.349, "X2", 2997.060, "Y2", 2993.870))
zones.Push(Object("NAME", "Red County", "X1", -1213.910, "Y1", -768.027, "X2", 2997.060, "Y2", 596.349))
zones.Push(Object("NAME", "Los Santos", "X1", 44.615, "Y1", -2892.970, "X2", 2997.060, "Y2", -768.027))

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
	global SAMP_POOL_VEHICLE						:= 0x1C
	global SAMP_POOL_PICKUP							:= 0x20

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
global scoreboardTick 						:= 0

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

showTextMessage(showText, showTime := 3000, unknown1 := 1, unknown2 := 1) {
	return !checkHandles() ? false : __WRITESTRING(hGTA, pMemory, [5000], showText) && __CALL(hGTA, 0x69F1E0, [["i", pMemory + 5000], ["i", showTime], ["i", 1], ["i", 1]])
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

writeToChatlog(text) {
	return checkHandles() && __CALL(hGTA, dwSAMP + 0x63C00, [["i", __DWORD(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR])], ["i", 4], ["s", text], ["i", 0]], false, true) 
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
	return !checkHandles() ? "" :  __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, 0x26])
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

getVehiclePointer(vehicleID) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, vehicleID * 4 + 0x4FB4])
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

updateScoreboardData() {
	return !checkHandles() ? false : (A_TickCount - scoreboardTick > 1000 ? __CALL(hGTA, dwSAMP + 0x8A10, [["i", __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR])]], false, true) && scoreboardTick := A_TickCount : true)
}

getPlayerScore(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !updateScoreboardData() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x24])
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

getPlayerAnimationID(playerID) {
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !checkHandles() ? "" : __READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x0, 0x108], "UShort")
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
	return playerID < 0 || playerID >= SAMP_MAX_PLAYERS || !updateScoreboardData() ? "" : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 4, 0x28])
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

isValidVehicle(dwVehicle) {
	if (!updateVehicles())
		return false

	for i, o in oVehicles {
		if (o.PTR = dwVehicle)
			return true
	}

	return false
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

togglePlaneTrail(toggle := true) {
	return checkHandles() && __WRITEMEM(hGTA, GTA_VEHICLE_PTR, [0xA00], toggle ? true : false, "UChar")
}

toggleLandingGear(toggle := true) {
	return checkHandles() && __WRITEMEM(hGTA, GTA_VEHICLE_PTR, [0x0, 0x98], toggle ? 0.0012 : 0.004, "Float")
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

	VarSetCapacity(buf, (len := 24), 0)
	NumPut(pMemory + 8, buf, 0, "UInt")
	NumPut(16 * 8, buf, 4, "Int")
	NumPut(fX, buf, 8, "Float")
	NumPut(fY, buf, 12, "Float")
	NumPut(fZ, buf, 16, "Float")
	NumPut(fSize, buf, 20, "Float")
	if (!__WRITERAW(hGTA, pMemory, &buf, len))
		return false

	return __CALL(hGTA, dwSAMP + 0xD220, [["i", pMemory]])
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

getWanteds() {
	return !checkHandles() ? -1 : __DWORD(hGTA, 0x58DB60, [0x0])
}

setWanteds(wanteds) {
	return !checkHandles() ? false : __WRITEMEM(hGTA, 0x58DB60, [0x0], wanteds, "UInt")
}

checkSendCMDNOP() {
	return checkHandles() && NOP(hGTA, dwSAMP + 0x65DF8, 5) && NOP(hGTA, dwSAMP + 0x65E45, 5)
}

patchSendSay(toggle := true) {
	return !checkHandles() ? false : (toggle ? __WRITEBYTES(hGTA, dwSAMP + 0x64915, [0xC3, 0x90]) : __WRITEBYTES(hGTA, dwSAMP + 0x64915, [0x85, 0xC0]))
}

unpatchSendCMD() {
	return !checkHandles() ? false : __WRITEBYTES(hGTA, dwSAMP + 0x65DF8, [0xE8, 0x63, 0xFE, 0xFF, 0xFF]) && __WRITEBYTES(hGTA, dwSAMP + 0x65E45, [0xE8, 0x16, 0xFE, 0xFF, 0xFF])
}

getChatRenderMode() {
	return !checkHandles() ? -1 : __READMEM(hGTA, [SAMP_CHAT_INFO_PTR, 0x8], "UChar")
}

renderChat() {
	if (!checkHandles())
		return false

	Sleep, 40
	__WRITEMEM(hGTA, dwSAMP, [SAMP_CHAT_INFO_PTR, 0x63DA], 1, "UInt")
	return true
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
	return checkHandles() && __WRITEMEM(hGTA, dwSAMP, [0x119CBC], 1, "UChar")
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

atan2(x, y) {
   return DllCall("msvcrt\atan2", "Double", y, "Double", x, "CDECL Double")
}

calcAngle(xActor, yActor, xPoint, yPoint) {
	fX := xActor - xPoint
	fY := yActor - yPoint
	return atan2(fX, fY)
}

getPlayerZAngle() {
	return !checkHandles() ? "" : __READMEM(hGTA, 0xB6F5F0, [0x0, 0x558], "Float")
}

setCameraPosX(fAngle) {
	return checkHandles() && __WRITEMEM(hGTA, 0xB6F258, [0x0], fAngle, "Float")
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

getRemotePlayerHealth(playerID) {
	return playerID < 0 || playerID > 1004 || !checkHandles() ? -1 : Round(__READMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_PLAYER, SAMP_REMOTEPLAYERS + playerID * 0x4, 0x0, 0x1BC], "Float"))
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

getFPS() {
	if (!checkHandles())
		return 0

	static timev := A_TickCount
	static val := __DWORD(hGTA, 0xB7CB4C, [0x0])
	temp := __DWORD(hGTA, 0xB7CB4C, [0x0])
	ret := (temp - val) / (A_TickCount - timev) * 1000
	timev := A_TickCount
	val := temp
	return ret
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

getPlayerAttachedObject(slot) {
	return slot < 0 || slot > 10 || !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_MISC_INFO_PTR, 0x8, 0x74 + slot * 0x34])
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

getPlayerTextDrawByIndex(index) {
	if (!checkHandles())
		return ""

	dwTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])
	if (!dwTextDraws)
		return ""

	if (!__DWORD(hGTA, dwTextDraws, [index * 4 + SAMP_MAX_TEXTDRAWS * 4]))
		return ""

	if (!(dwAddress := __DWORD(hGTA, dwTextDraws, [index * 4 + (4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS * 2))])))
		return ""

	return __READSTRING(hGTA, dwAddress, [0x0], 100)
}

setPlayerTextDrawByIndex(index, text) {
	if (!checkHandles())
		return false

	dwTextDraws := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])

	if (!dwTextDraws)
		return false

	if (!__DWORD(hGTA, dwTextDraws, [index * 4 + SAMP_MAX_TEXTDRAWS * 4]))
		return false

	if (!(dwAddress := __DWORD(hGTA, dwTextDraws, [index * 4 + (4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS * 2))])))
		return false

	return __WRITESTRING(hGTA, dwAddress, [0x0], text)
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

createTextDraw1(text, xPos, yPos, letterColor := 0xFFFFFFFF, font := 3, letterWidth := 0.4, letterHeight := 1, shadowSize := 0, outline := 1
	, shadowColor := 0xFF000000, box := 0, boxColor := 0xFFFFFFFF, boxSizeX := 0.0, boxSizeY := 0.0, left := 0, right := 0, center := 1
	, proportional := 1, modelID := 0, xRot := 0.0, yRot := 0.0, zRot := 0.0, zoom := 1.0, color1 := 0xFFFF, color2 := 0xFFFF) {

	if (font > 5 || StrLen(text) > 800 || !checkHandles() || !(dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW])))
		return -1

	Loop, 2048 {
		i := A_Index - 1
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

resizeTextDraw(textDrawID, letterWidth, letterHeight) {
	return return textDrawID < 0 || textDrawID > 2047 || checkHandles() 
		&& __WRITEMEM(hGTA, (dwAddress := __DWORD(hGTA, dwSAMP
		, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_TEXTDRAW, textDrawID * 4 + 4 * (SAMP_MAX_PLAYERTEXTDRAWS + SAMP_MAX_TEXTDRAWS)])), [0x963], letterWidth
		, "Float") && __WRITEMEM(hGTA, dwAddress, [0x967], letterHeight, "Float")
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

getClosestObject() {
	if (!updateObjects())
		return ""

	dist := -1
	obj := ""
	pPos := getPlayerPos()

	for i, o in oObjects {
		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			obj := o
			dist := newDist
		}
	}

	return obj
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

setClosestObjectDrawDistance(ddistance) {
	if (!updateObjects())
		return ""

	dist := -1
	obj := ""
	pPos := getPlayerPos()

	for i, o in oObjects {
		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			obj := o
			dist := newDist
		}
	}

	if (obj == "")
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	dwObject := __DWORD(hGTA, dwAddress, [obj.ID * 0x4 + 0xFA4])

	return __WRITEMEM(hGTA, dwObject, [0x54], ddistance, "Float")
}

getClosestObjectDrawDistance() {
	if (!updateObjects())
		return ""

	dist := -1
	obj := ""
	pPos := getPlayerPos()

	for i, o in oObjects {
		if ((newDist := getDistance([o.XPOS, o.YPOS, o.ZPOS], pPos)) < dist || dist == -1) {
			obj := o
			dist := newDist
		}
	}

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	dwObject := __DWORD(hGTA, dwAddress, [obj.ID * 0x4 + 0xFA4])

	return __READMEM(hGTA, dwObject, [0x54], "Float")
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
		AddChatMessage("Index: " o.ID ", Model: " o.MODELID ", xPos: " o.XPOS ", yPos: " o.YPOS ", zPos: " o.ZPOS ", " o.DRAW)

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

countAttachedObjects(modelID) {
	if (!checkHandles())
		return false

	vehPtr := __DWORD(hGTA, GTA_VEHICLE_PTR, [0x0])
	if (vehPtr == "" || !vehPtr)
		return false

	dwAddress := __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT])
	if (!dwAddress)
		return false
	
	oCount := 0
	count := __DWORD(hGTA, dwAddress, [0x0])
	Loop, % SAMP_MAX_OBJECTS {
		i := A_Index - 1
		
		if (!__DWORD(hGTA, dwAddress, [i * 4 + 0x4]))
			continue

		dwObject := __DWORD(hGTA, dwAddress, [i * 0x4 + 0xFA4])
		if (__DWORD(hGTA, dwObject, [0x4E]) == modelID && __DWORD(hGTA, dwObject, [0x40, 0xFC]) == vehPtr)
			oCount++

		count--
		if (count <= 0)
			break
	}

	return oCount
}

isObjectAttached() {
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
		if (__DWORD(hGTA, dwObject, [0x40, 0xFC]) == vehPtr)
			AddChatMessage("Object Model: " __DWORD(hGTA, dwObject, [0x4E]))

		count--
		if (count <= 0)
			break
	}

	return false
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

getObjectCount() {
	return !checkHandles() ? false : __DWORD(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_OBJECT, 0x0])
}

getObjectCountByModel(modelID) {
	if (!updateObjects())
		return false

	count := 0
	for i, o in oObjects {
		if (o.MODELID == modelID)
			count++
	}

	return count
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
			, __READMEM(hGTA, dwObject, [0x60], "Float"), "ZPOS", __READMEM(hGTA, dwObject, [0x64], "Float"), "DRAW", __READMEM(hGTA, dwObject, [0x53], "Float")))

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

		string := __READSTRING(hGTA, dwAddress, [0x0], 256)
		if (string == "")
			string := __READSTRING(hGTA, dwAddress, [0x0], getDialogTextSize(dwAddress))

		if (string == "")
			continue

		fX := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x8], "Float")
		fY := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0xC], "Float")
		fZ := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x10], "Float")
		wVehicleID := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x1B], "UShort")
		wPlayerID := __READMEM(hGTA, dwTextLabels, [i * 0x1D + 0x19], "UShort")
		
		oTextLabels.Push(Object("ID", i, "TEXT", string, "XPOS", fX, "YPOS", fY, "ZPOS", fZ, "VEHICLEID", wVehicleID, "PLAYERID"
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

	for i, o in oTextLabels {
		AddChatMessage("{FFFF00}ID: " o.ID ", " o.XPOS ", " o.YPOS ", " o.ZPOS ", ")
		AddChatMessage("Text: " o.TEXT)
	}

	AddChatMessage("TextLabel Count: " i)
	renderChat()
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

getNearestLabel2(text := "", pos1 := "") {
	if (!updateTextLabels())
		return 0
	
	nearest := ""
	dist := -1
	if (pos1 == "")
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
		if (text != "" && !InStr(o.TEXT, text))
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

clearBlip2(blipID) {
	if (!checkHandles() || !blipID)
		return false

	return __CALL(hGTA, 0x587C10, [["i", blipID]])
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

clearAllBlips() {
	if (!checkHandles())
		return false

	Loop % GTA_BLIP_COUNT {
		currentElement := GTA_BLIP_POOL + (A_Index - 1) * GTA_BLIP_ELEMENT_SIZE
		if (__READMEM(hGTA, currentElement + GTA_BLIP_ID_OFFSET, [0x0], "UChar") != 0)
			clearBlip2(A_Index - 1)
	}

	return true
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
			AddChatMessage("Icon ID: " id ", Style: " style ", Pos: " xPos " " yPos " " zPos ", ID: " A_Index - 1)
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

setVehicleColorSAMP(vehicleID, color, colorID := 1) {
	return !checkHandles() || vehicleID < 1 || vehicleID > SAMP_MAX_VEHICLES ? "" : __WRITEMEM(hGTA, dwSAMP, [SAMP_INFO_PTR, SAMP_POOLS, SAMP_POOL_VEHICLE, 0x1134 + vehicleID * 0x4, (colorID == 1 ? 0x79 : 0x7A)], color, "UChar")
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

getPlayerVehiclePassengers() {
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
	return RegExReplace(Round(value), "\G-?\d+?(?=(\d{3})+(?:\D|$))", "$0" delimiter)
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
	if (dwSAMP)
		return true

	dwSAMP := getModuleBaseAddress("samp.dll", hGTA)
	if (!dwSAMP)
		return false

	if (__READMEM(hGTA, dwSAMP, [0x1036], "UChar") != 0xD8) {
		msgbox, 64, % "SA:MP Version nicht kompatibel", % "Die installierte SA:MP Version ist nicht mit dem Keybinder kompatibel.`nBitte installiere die Version 0.3.7 um den Keybinder nutzen zu können."
		ExitApp
	}

	return true
}

refreshMemory() {
	if (!pMemory) {
		pMemory := virtualAllocEx(hGTA, 6984, 0x1000 | 0x2000, 0x40)
		if (ErrorLevel) {
			pMemory := 0x0
			return false
		}

		pInjectFunc := pMemory + 5120
		pDetours	:= pInjectFunc + 1024
	}

	return true
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

getCity(x, y, z) {
	if (z > 900.0)
		return "Interior"

	for i, o in cities {
		if (x >= o.X1 && y >= o.Y1 && x <= o.X2 && y <= o.Y2)
			return o.NAME
	}

	return "Unbekannt"
}

getZone(x, y, z) {
	if (z > 900.0)
		return "Interior"

	for i, o in zones {
		if (x >= o.X1 && y >= o.Y1 && x <= o.X2 && y <= o.Y2)
			return o.NAME
	}

	return "Unbekannt"
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

aInterface["Radar-Tilt-XPos"] 	:= Object("ADDRESSES", [0x58A469], "DEFAULT_POINTER", 0x858A10, "DEFAULT_VALUE", 40.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["Radar-Tilt-YPos"] 	:= Object("ADDRESSES", [0x58A499], "DEFAULT_POINTER", 0x866B70, "DEFAULT_VALUE", 104.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["Radar-Height-XPos"] := Object("ADDRESSES", [0x58A5E2, 0x58A6E6], "DEFAULT_POINTER", 0x858A10, "DEFAULT_VALUE", 40.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)
aInterface["Radar-Height-YPos"] := Object("ADDRESSES", [0x58A60E, 0x58A71E], "DEFAULT_POINTER", 0x866B70, "DEFAULT_VALUE", 104.0, "VALUE_TYPE", "Float", "DETOUR_ADDRESS", null)

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
