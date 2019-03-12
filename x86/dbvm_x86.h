#pragma once

#include <Windows.h>

#define VMCALL_GETVERSION 0
#define VMCALL_CHANGEPASSWORD 1
#define VMCALL_READ_PHYSICAL_MEMORY 3
#define VMCALL_WRITE_PHYSICAL_MEMORY 4
#define VMCALL_REDIRECTINT1 9
#define VMCALL_INT1REDIRECTED 10
#define VMCALL_CHANGESELECTORS 12
#define VMCALL_BLOCK_INTERRUPTS 13
#define VMCALL_RESTORE_INTERRUPTS 14

#define VMCALL_REGISTER_CR3_EDIT_CALLBACK 16
#define VMCALL_RETURN_FROM_CR3_EDIT_CALLBACK 17
#define VMCALL_GETCR0 18
#define VMCALL_GETCR3 19
#define VMCALL_GETCR4 20
#define VMCALL_RAISEPRIVILEGE 21
#define VMCALL_REDIRECTINT14 22
#define VMCALL_INT14REDIRECTED 23
#define VMCALL_REDIRECTINT3 24
#define VMCALL_INT3REDIRECTED 25

//dbvm v6+
#define VMCALL_READMSR 26
#define VMCALL_WRITEMSR 27

#define VMCALL_ULTIMAP 28
#define VMCALL_ULTIMAP_DISABLE 29


//dbvm v7
#define VMCALL_SWITCH_TO_KERNELMODE 30
#define VMCALL_DISABLE_DATAPAGEFAULTS 31
#define VMCALL_ENABLE_DATAPAGEFAULTS 32
#define VMCALL_GETLASTSKIPPEDPAGEFAULT 33

#define VMCALL_ULTIMAP_PAUSE 34
#define VMCALL_ULTIMAP_RESUME 35

#define VMCALL_ULTIMAP_DEBUGINFO 36

#define VMCALL_PSODTEST 37

//dbvm11
#define VMCALL_GETMEM 38
#define VMCALL_JTAGBREAK 39
#define VMCALL_GETNMICOUNT 40

#define VMCALL_WATCH_WRITES 41
#define VMCALL_WATCH_READS 42
#define VMCALL_WATCH_RETRIEVELOG 43
#define VMCALL_WATCH_DELETE 44

#define VMCALL_CLOAK_ACTIVATE 45
#define VMCALL_CLOAK_DEACTIVATE 46
#define VMCALL_CLOAK_READORIGINAL 47
#define VMCALL_CLOAK_WRITEORIGINAL 48

#define VMCALL_CLOAK_CHANGEREGONBP 49
#define VMCALL_CLOAK_REMOVECHANGEREGONBP 50

#define VMCALL_EPT_RESET 51

#define VMCALL_LOG_CR3VALUES_START 52
#define VMCALL_LOG_CR3VALUES_STOP 53

#define VMCALL_REGISTERPLUGIN 54
#define VMCALL_RAISEPMI 55
#define VMCALL_ULTIMAP2_HIDERANGEUSAGE 56

#define VMCALL_ADD_MEMORY 57
//#define VMCALL_DISABLE_EPT 58 dus nut wurk



#define VMCALL_GET_STATISTICS 59


#define VMCALL_WATCH_EXECUTES 60

#define VMCALL_GETPHYSICALADDRESSVM 1000

__declspec(naked) BOOL IsAMD() {
	__asm {
		pushad
		xor eax,eax
		cpuid
		cmp ebx,68747541h
		jne End
		cmp edx,69746E65h
		jne End
		cmp ecx,444D4163h
		jne End
		popad
		mov eax,1
		ret
End:
		popad
		xor eax,eax
		ret
	}
}

__declspec(naked) BOOL IsIntel() {
	__asm {
		pushad
		xor eax,eax
		cpuid
		cmp ebx,756E6547h
		jne End
		cmp edx,49656E69h
		jne End
		cmp ecx,6C65746Eh
		jne End
		popad
		mov eax,1
		ret
End:
		popad
		xor eax,eax
		ret
	}
}


__declspec(naked) DWORD64 dovmcall_amd(PVOID vmcallinfo, DWORD level1pass)
{
	__asm {
		mov eax,ecx
		//mov rax,rcx
		_emit 0x0F
		_emit 0x01
		_emit 0xD9
		//vmcall

		push eax
		//push rax

		pop dword ptr [esp+8h]
		//pop [rsp+8h]
		retf
	}
}

__declspec(naked) DWORD64 dovmcall_intel(PVOID vmcallinfo, DWORD level1pass)
{
	__asm {
		mov eax,ecx
		//mov rax,rcx
		_emit 0x0F
		_emit 0x01
		_emit 0xC1
		//vmmcall

		push eax
		//push rax

		pop dword ptr [esp+8h]
		//pop [rsp+8h]
		retf
	}
}

#pragma pack(push, 4)

class DBVM {
private:
	BOOL bIntel;
	BOOL bAMD;
	DWORD vmx_password1;
	DWORD vmx_password2;
public:
	DWORD64 dovmcall(PVOID vmcallinfo, DWORD level1pass) const {
		DWORD64 ret_val = 0;
		DWORD64 callgate = 0;
		PVOID callto = bIntel ? dovmcall_intel : dovmcall_amd;

		__asm {
			pushad
			mov eax,[callto]
			mov dword ptr [callgate],eax
			mov eax,33h
			mov dword ptr [callgate+4],eax
			sub esp,8
			mov ecx,[vmcallinfo]
			mov edx,[level1pass]
			call fword ptr [callgate]
			pop dword ptr [ret_val]
			pop dword ptr [ret_val+4]
			popad
		}
	
		return ret_val;
	}

	DWORD GetVersion() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_GETVERSION;

		return (DWORD)dovmcall(&vmcallinfo, vmx_password1);
	}


	DWORD64 GetRealCR0() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_GETCR0;

		return dovmcall(&vmcallinfo, vmx_password1);
	}

	DWORD64 GetRealCR3() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_GETCR3;

		return dovmcall(&vmcallinfo, vmx_password1);
	}

	DWORD64 GetRealCR4() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_GETCR4;

		return dovmcall(&vmcallinfo, vmx_password1);
	}

	DWORD64 GetPhysicalAddress(DWORD64 VA) const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD64 VA;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_GETPHYSICALADDRESSVM;
		vmcallinfo.VA = VA;

		return dovmcall(&vmcallinfo, vmx_password1);
	}

	void EPT_Reset() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_EPT_RESET;

		dovmcall(&vmcallinfo, vmx_password1);
	}

	void TestPSOD() const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_PSODTEST;

		dovmcall(&vmcallinfo, vmx_password1);
	}

	DWORD64 SwitchToKernelMode(WORD cs, LPVOID rip, LPCVOID parameters) const {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD cs;
			LPCVOID rip;
			LPCVOID parameters;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_SWITCH_TO_KERNELMODE;
		vmcallinfo.cs = cs;
		vmcallinfo.rip = rip;
		vmcallinfo.parameters = parameters;

		return dovmcall(&vmcallinfo, vmx_password1);
	}

	int CloakActivate(DWORD64 PA) const {
		//0 -> success
		//1 -> already cloaked
		//else -> error
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD64 PA;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_CLOAK_ACTIVATE;
		vmcallinfo.PA = PA;

		return (int)dovmcall(&vmcallinfo, vmx_password1);
	}

	int CloakDeactivate(DWORD64 PA) const {
		//0 -> not found
		//1 -> success
		//else -> error
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD64 PA;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_CLOAK_DEACTIVATE;
		vmcallinfo.PA = PA;

		return (BOOL)dovmcall(&vmcallinfo, vmx_password1);
	}

	int CloakReadOriginal(DWORD64 PA, LPVOID lpDst) const {
		//0 -> success
		//1 -> failed
		//else -> error
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD64 PA;
			DWORD64 lpDst;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_CLOAK_READORIGINAL;
		vmcallinfo.PA = PA;
		vmcallinfo.lpDst = (DWORD64)lpDst;

		return (int)dovmcall(&vmcallinfo, vmx_password1);
	}

	int CloakWriteOriginal(DWORD64 PA, LPCVOID lpSrc) const {
		//0 -> success
		//1 -> failed
		//else -> error
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD64 PA;
			DWORD64 lpSrc;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_CLOAK_WRITEORIGINAL;
		vmcallinfo.PA = PA;
		vmcallinfo.lpSrc = (DWORD64)lpSrc;

		return (int)dovmcall(&vmcallinfo, vmx_password1);
	}

	void ChangePassword(DWORD password1, DWORD password2) {
		struct
		{
			DWORD structsize;
			DWORD level2pass;
			DWORD command;
			DWORD password1;
			DWORD password2;
		} vmcallinfo;

		vmcallinfo.structsize = sizeof(vmcallinfo);
		vmcallinfo.level2pass = vmx_password2;
		vmcallinfo.command = VMCALL_CHANGEPASSWORD;
		vmcallinfo.password1 = password1;
		vmcallinfo.password2 = password2;

		dovmcall(&vmcallinfo, vmx_password1);
		SetPassword(password1, password2);
	}

	void SetPassword(DWORD password1, DWORD password2) {
		vmx_password1 = password1;
		vmx_password2 = password2;
	}

	DBVM(DWORD password1 = 0, DWORD password2 = 0) {
		bIntel = IsIntel();
		bAMD = IsAMD();
		if(password1 == 0) password1 = 0x76543210;
		if(password2 == 0) password2 = 0xfedcba98;
		SetPassword(password1, password2);
	}
};

#pragma pack(pop)
