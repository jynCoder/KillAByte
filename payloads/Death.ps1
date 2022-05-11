function Death {

<#
Raises an error that causes a Blue Screen of Death on Windows. It does this without
requiring administrator privileges.
#>

$source = @"
using System;
using System.Runtime.InteropServices;

public static class CS{
	[DllImport("ntdll.dll")]
	public static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

	[DllImport("ntdll.dll")]
	public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

	public static unsafe void Kill(){
		Boolean tmp1;
		uint tmp2;
		RtlAdjustPrivilege(19, true, false, out tmp1);
		NtRaiseHardError(0xc0000022, 0, 0, IntPtr.Zero, 6, out tmp2);
	}
}
"@
    $comparams = new-object -typename system.CodeDom.Compiler.CompilerParameters
    $comparams.CompilerOptions = '/unsafe'
    $a = Add-Type -TypeDefinition $source -Language CSharp -PassThru -CompilerParameters $comparams
    [CS]::Kill()
}

function Get-DumpSettings {
<#
Queries the registry for crash dump settings so that we'll have some idea
what type of dump we're going to generate, and where it will be.
#>

	$regdata = Get-ItemProperty -path HKLM:\System\CurrentControlSet\Control\CrashControl

	$dumpsettings = @{}
	$dumpsettings.CrashDumpMode = switch ($regdata.CrashDumpEnabled) {
		1 { if ($regdata.FilterPages) { "Active Memory Dump" } else { "Complete Memory Dump" } }
		2 {"Kernel Memory Dump"}
		3 {"Small Memory Dump"}
		7 {"Automatic Memory Dump"}
		default {"Unknown"}
	}
	$dumpsettings.DumpFileLocation = $regdata.DumpFile
	[bool]$dumpsettings.AutoReboot = $regdata.AutoReboot
	[bool]$dumpsettings.OverwritePrevious = $regdata.Overwrite
	[bool]$dumpsettings.AutoDeleteWhenLowSpace = -not $regdata.AlwaysKeepMemoryDump
	[bool]$dumpsettings.SystemLogEvent = $regdata.LogEvent
	$dumpsettings
}

Death
Get-DumpSettings
