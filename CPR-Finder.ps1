<#
    .SYNOPSIS

    Identifies shares and checks file content for CPR-numbers (Danish Social Security Numbers (SSN)). 
	The check is performed based on regular expressions. 
    Modulus 11 check is performed to minimize the number of false positives.
	Dates where modulus 11 is not upheld are excluded.

    Author: Christina Alfast Espensen and Benjamin Henriksen
    Version: 1.42
    License: BSD 3-Clause

    Required Dependencies:  - FileLocator Pro (Mythicsoft) including our two search criteria files (SearchCriteriaDocuments.srf and SavedCriteriaAllFiles.srf) 
                            - Powershell Active Directory module

    .DESCRIPTION
 	The credentials used to run the script, will determine which files are accessible (scanned) - so choose these credentials wisely.		
	If you are only interested in CPR-numbers that are readable to "everyone", create a "random" user account, and run the script with that user. 
	We recommend using a none priviledge account during the first scans, to ensure that unprotected files are addressed initially.

    For performance reasons the scan moves on to another file after 50 CPR-Number hits. Modulus confirmation stops after one CPR-number hit.

    CPR-Finder can run in two modes:
    
    1. Host-Only Mode (Default)

        CPR-Finder Host-Only Mode consists of the following three phases:

        Phase 1: Identify local fixed drives or supplied paths. 

        Phase 2: The identified local fixed drives or supplied paths are scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.                 

        Phase 3: Parse output to html file and csv file

    2. Domain Mode - All hosts
    
        CPR-Finder Domain Mode consists of the following three phases:

        Phase 1: Identify open shares found on the Active Directory hosts in your environment
                 by utilizing Invoke-ShareFinder by harmjoy. 

        Phase 2: The identified open shares are then scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.  

        Phase 3: Parse output to html file and csv file

    3. Domain Mode - Servers only
    
        CPR-Finder Domain Mode consists of the following three phases:

        Phase 1: Identify open shares found on the Active Directory servers in your environment
                 by utilizing Invoke-ShareFinder by harmjoy. 

        Phase 2: The identified open shares are then scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.  

        Phase 3: Parse output to html file and csv file
					
    .PARAMETER ComputerPasswordAgeDays
    Only applicable to Domain Mode.
	Specifies the amout of days since the computer has changed password.
    This is an indicator of whether or not a computer object in Active Directory is dead or alive.
    The lower the value, the less computers will be scanned. 
    The default and recommened value is 31.

    .PARAMETER StartGui
	You can choose to start the GUI of FileLocator Pro. When you do this, the output will not be parsed and no new html or csv file is generated.
    This should be used for debug purposes only.

    .PARAMETER ScanMode
    All: When this value is selected the scan will be performed on all hosts in the domain (default search base). 
    HostOnly: (Default) Will only scan drives or supplied paths. (Accepts UNC).
    ServerOnly: When this parameter is supplied the scan will only be performed on Windows servers and none Windows devices i.e. NAS devices (only those with shares will be scanned).
      	

    .PARAMETER ScanTarget 
    Not applicable for Domain Mode.
    Supply a semi colon (;) separated list of drives to scan. See example.

     .PARAMETER ScanAllFiles 
    Sets the file types to scan to all files.
    Default is Document type files. 
    Scaning all file types will increas the scanning time, and increase the number of false positives.
    

    .PARAMETER IncludeCPRInOutput 
    This will include the first found (and modulus matched) CPR number in the parsed output files.

    .PARAMETER DebugVerbose 
    This will output the computer that is currently scanned.


    .EXAMPLE
    > CPR-Finder.ps1 -ScanTarget "C:\Temp;C:\Temp Folder"
    Finds files with CPR numbers in c:\temp and c:\temp folder

    .EXAMPLE
    > CPR-Finder.ps1 -ScanTarget "\\pluto\users" -IncludeCPRInOutput
    Finds files with CPR numbers on the share \\pluto\users, and includes CPR-numbers in the output file.

    .EXAMPLE
    > CPR-Finder.ps1 -ScanMode All
    Scans shares in the entire domain.

    .EXAMPLE
    > CPR-Finder.ps1 -ScanMode HostOnly
    Scans all fixed drives on localhost, this is default.

    .EXAMPLE
    > CPR-Finder.ps1 -ScanMode HostOnly -ScanAllFiles
    Scans all file types on all fixed drives on localhost, this is default.

    .EXAMPLE
    > CPR-Finder.ps1 -ScanMode ServersOnly -ComputerPasswordAgeDays 5 -IncludeCPRInOutput
    Scans shares on servers in the domain, where the computer account has changed password within the last 5 days. CPR-nubers are inluded in the output.
    ComputerPasswordAgeDays can be used for testing purposes.

    .EXAMPLE
    > CPR-Finder.ps1 -StartGui 
    Loads FileLocator Pro, with all fixed drives as targets, press start to start the scan. The scanresult will not be parsed. 
    This is for testing only.

    .NOTES
    We have absolutely no affiliation with Mythicsoft or any of thier employees.
	If you are aware of free multi-threaded tools, that could replace FileLocator Pro please let us know.

	The following dates are dates CPR numbers without modulus control has been issued:

		1. januar 1960	1. januar 1964	1. januar 1965	1. januar 1966
		1. januar 1969	1. januar 1970	1. januar 1980	1. januar 1982
		1. januar 1984	1. januar 1985	1. januar 1986	1. januar 1987
		1. januar 1988	1. januar 1989	1. januar 1990	1. januar 1992

    .LINK
    https://cpr.dk/cpr-systemet/personnumre-uden-kontrolciffer-modulus-11-kontrol/

    #>	


param 
(
    [Parameter(Mandatory=$false)]
        [int]$ComputerPasswordAgeDays = 31,
    [Parameter(Mandatory=$false)]
        [switch]$StartGui,
    [Parameter(Mandatory=$false)]
        [switch]$ScanAllFiles,
    [parameter(Mandatory=$false)]
        [validateset( "HostOnly", "DomainModeAll", "DomainModeServersOnly")] [String] $ScanMode="HostOnly",
    [Parameter(Mandatory=$false)] 
        [string]$ScanTarget,
    [Parameter(Mandatory=$false)] 
        [switch]$IncludeCPRInOutput,
    [Parameter(Mandatory=$false)] 
        [switch]$DebugVerbose
)


Clear-Host

# ----- SCRIPT CONFIGURATION ----- #
# THIS PART CAN BE ALTERED TO MATCH YOUR INSTALLATION

$CPRFinderPath = $PSScriptRoot
$FileLocatorProInstallationPath = "C:\Program Files\Mythicsoft\FileLocator Pro"  # change path if necessary

if ($StartGui.IsPresent) { $flpsearchPath = "$FileLocatorProInstallationPath\filelocatorpro.exe" }
else { $flpsearchPath = "$FileLocatorProInstallationPath\flpsearch.exe" }

if ($ScanAllFiles.IsPresent) { $flpsearchCriteriaPath = "$CPRFinderPath\FileLocatorPro_Searches\SavedCriteriaAllFiles.srf" }
else { $flpsearchCriteriaPath = "$CPRFinderPath\FileLocatorPro_Searches\SearchCriteriaDocuments.srf" }

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$OutfilePath = "$CPRFinderPath\ScanOutput"
$OutFileFLPSearch = "$OutfilePath\$($TimeStamp)_cpr_finder_filelocatorpro_result.csv"

$OutFileHtml = "$OutfilePath\$($TimeStamp)_cpr_finder_result_parsed.html"
$OutFilecsv  = "$OutfilePath\$($TimeStamp)_cpr_finder_result_parsed.csv"
$ScreenOutput=""

# CPR NUMBERS TO EXCLUDE FROM THE SCAN. 
# YOU CAN ADD CPR NUMBERS TO THE LIST. EXAMPLE: $ExclusionList = @("1111111111","111111110") 
$ExclusionList = @("") 

# ----- SCRIPT CONFIGURATION END ----- #

# ----- BEGIN Invoke-ShareFinder ----- #
# We have made minor alterations to    #
# invoke-sharefinder.  The changes are #
# very limtied and restricted to input # 
# and output handling.                 #
#                                      #
# The inner workings of the script is  #
# unchanged.                           # 
# ------------------------------------ #

#requires -version 2

<#
    Implementation of Sharefinder that utilizes
        https://github.com/mattifestation/psreflect to
        stay off of disk.

    By @harmj0y
#>

function New-InMemoryModule
{
    <#
        .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
 
        .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

        .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

        .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
    #>

    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
# Author: Matthew Graeber (@mattifestation)
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
    <#
        .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func
 
        .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

        .PARAMETER DllName

        The name of the DLL.

        .PARAMETER FunctionName

        The name of the target function.

        .PARAMETER ReturnType

        The return type of the function.

        .PARAMETER ParameterTypes

        The function parameters.

        .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

        .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

        .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

        .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
        (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
        (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
        (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

        .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        # Define one type for each DLL
        if (!$TypeHash.ContainsKey($DllName))
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
            }
            else
            {
                $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
            }
        }

        $Method = $TypeHash[$DllName].DefineMethod(
            $FunctionName,
            'Public,Static,PinvokeImpl',
            $ReturnType,
            $ParameterTypes)

        # Make each ByRef parameter an Out parameter
        $i = 1
        foreach($Parameter in $ParameterTypes)
        {
            if ($Parameter.IsByRef)
            {
                [void] $Method.DefineParameter($i, 'Out', $null)
            }

            $i++
        }

        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

        # Equivalent to C# version of [DllImport(DllName)]
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
        $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
            $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
            [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
            [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

        $Method.SetCustomAttribute($DllImportAttribute)
    }

    END
    {
        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


# A helper function used to reduce typing while defining struct
# fields.
# Author: Matthew Graeber (@mattifestation)
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# Author: Matthew Graeber (@mattifestation)
function struct
{
    <#
        .SYNOPSIS

        Creates an in-memory struct for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: field
 
        .DESCRIPTION

        The 'struct' function facilitates the creation of structs entirely in
        memory using as close to a "C style" as PowerShell will allow. Struct
        fields are specified using a hashtable where each field of the struct
        is comprosed of the order in which it should be defined, its .NET
        type, and optionally, its offset and special marshaling attributes.

        One of the features of 'struct' is that after your struct is defined,
        it will come with a built-in GetSize method as well as an explicit
        converter so that you can easily cast an IntPtr to the struct without
        relying upon calling SizeOf and/or PtrToStructure in the Marshal
        class.

        .PARAMETER Module

        The in-memory module that will host the struct. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER FullName

        The fully-qualified name of the struct.

        .PARAMETER StructFields

        A hashtable of fields. Use the 'field' helper function to ease
        defining each field.

        .PARAMETER PackingSize

        Specifies the memory alignment of fields.

        .PARAMETER ExplicitLayout

        Indicates that an explicit offset for each field will be specified.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageDosSignature = enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
        }

        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
        }

        # Example of using an explicit layout in order to create a union.
        $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
        } -ExplicitLayout

        .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Struct. :P
    #>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


function Test-Server {
    <#
        .SYNOPSIS
        Tests a connection to a remote server.
        
        .DESCRIPTION
        This function uses either ping (test-connection) or RPC
        (through WMI) to test connectivity to a remote server.

        .PARAMETER Server
        The hostname/IP to test connectivity to.

        .OUTPUTS
        $True/$False
        
        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $Server,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }
    # otherwise, use ping
    else{
        Test-Connection -ComputerName $Server -count 1 -Quiet -ErrorAction SilentlyContinue
    }
}


function Get-ShuffledArray {
    <#
        .SYNOPSIS
        Returns a randomly-shuffled version of a passed array.
        
        .DESCRIPTION
        This function takes an array and returns a randomly-shuffled
        version.
        
        .PARAMETER Array
        The passed array to shuffle.

        .OUTPUTS
        System.Array. The passed array but shuffled.
        
        .EXAMPLE
        > $shuffled = Get-ShuffledArray $array
        Get a shuffled version of $array.

        .LINK
        http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}


function Get-NetCurrentUser {
    <#
        .SYNOPSIS
        Gets the name of the current user.
        
        .DESCRIPTION
        This function returns the username of the current user context,
        with the domain appended if appropriate.
        
        .OUTPUTS
        System.String. The current username.
        
        .EXAMPLE
        > Get-NetCurrentUser
        Return the current user.
    #>
    
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.
        
        .DESCRIPTION
        This function utilizes ADSI (Active Directory Service Interface) to
        get the currect domain root and return its distinguished name.
        It then formats the name into a single string.
        
        .PARAMETER Base
        Just return the base of the current domain (i.e. no .com)

        .OUTPUTS
        System.String. The full domain name.
        
        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .EXAMPLE
        > Get-NetDomain -base
        Return just the base of the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>
    
    [CmdletBinding()]
    param(
        [Switch]
        $Base
    )
    
    # just get the base of the domain name
    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}


function Get-NetComputers {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context 
        for current computer objects. Based off of Carlos Perez's Audit.psm1 
        script in Posh-SecMod (link below).
        
        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputers
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputers -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputers -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputers -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>
    
    [CmdletBinding()]
    Param (
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            # create the searcher object with our specific filters
            if ($ServicePack -ne '*'){
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if ($ServicePack -ne '*'){
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
        }
        else{
            # server 2012 peculiarity- remove any mention to service pack
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($CompSearcher){
        
        # eliminate that pesky 1000 system limit
        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {
            # return full data objects
            if ($FullData){
                $_.properties
            }
            else{
                # otherwise we're just returning the DNS host name
                $_.properties.dnshostname
            }
        }
    }
}


function Get-NetShare {
    <#
        .SYNOPSIS
        Gets share information for a specified server.
    
        .DESCRIPTION
        This function will execute the NetShareEnum Win32API call to query
        a given host for open shares. This is a replacement for
        "net share \\hostname"

        .PARAMETER HostName
        The hostname to query for shares.

        .OUTPUTS
        SHARE_INFO_1 structure. A representation of the SHARE_INFO_1
        result structure which includes the name and note for each share.

        .EXAMPLE
        > Get-NetShare
        Returns active shares on the local host.

        .EXAMPLE
        > Get-NetShare -HostName sqlserver
        Returns active shares on the 'sqlserver' host
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # arguments for NetShareEnum
    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get the share information
    $Result = $Netapi32::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetShare result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $SHARE_INFO_1::GetSize()
        
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $SHARE_INFO_1
            # return all the sections of the structure
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # free up the result buffer
        $Netapi32::NetApiBufferFree($ptrInfo) | Out-Null
    }
    else 
    {
        switch ($Result) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}


Function AddShareObject {
    <#
        .SYNOPSIS
        Create an object of the share
        This is not a part of invoke-sharefinder but has been added for ease of use.
 
        .DESCRIPTION
        Create an object of the share

        .PARAMETER ShareName
        The name of the share to create the object from    

    #>
    param 
    (
        [String]$ShareName = ""
    )
    $ShareObject = New-Object PSObject
        $ShareObject | Add-Member -type NoteProperty -Name 'ShareName' -Value $ShareName

    return $ShareObject
}
# 
 

function Invoke-ShareFinder {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.

        Author: @harmj0y
        Minor alterations by: @our_name
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER ExcludeStandard
        Exclude standard shares from display (C$, IPC$, print$ etc.)

        .PARAMETER ExcludePrint
        Exclude the print$ share

        .PARAMETER ExcludeIPC
        Exclude the IPC$ share

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.
        
        .EXAMPLE
        > Invoke-ShareFinder -ExcludeStandard
        Find non-standard shares on the domain.

        .EXAMPLE
        > Invoke-ShareFinder -Delay 60
        Find shares on the domain with a 60 second (+/- *.3) 
        randomized delay between touching each host.

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        
        $HostList,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [String]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # figure out the shares we want to ignore
    [String[]] $excludedShares = @('')
    
    if ($ExcludePrint){
        $excludedShares = $excludedShares + "PRINT$"
    }
    if ($ExcludeIPC){
        $excludedShares = $excludedShares + "IPC$"
    }
    if ($ExcludeStandard){
        $excludedShares = @('', "ADMIN$", "IPC$", "C$", "D$","E$","F$","G$","H$","I$","J$","K$","L$","M$","N$","O$","P$","Q$","R$","S$","T$","U$","V$","W$","X$","Y$","z$","PRINT$") # Expanded compared to the original list by @harmj0y.
    }
    # create empty share object
    $objShares = @()

    # random object for delay
    $randNo = New-Object System.Random
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running ShareFinder on domain $targetDomain with delay of $Delay"
    $servers = @()

    $servers = $HostList
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        
        # return/output the current status lines
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            if ($server -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                # optionally check if the server is up first
                $up = $true
                if(-not $NoPing){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne '')){
                            
                            # if we're just checking for access to ADMIN$
                            if($CheckAdmin){
                                if($netname.ToUpper() -eq "ADMIN$"){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        #"\\$server\$netname" # `t- $remark"
                                        $objShares += $(AddShareObject -ShareName "\\$server\$netname")
                                    }
                                    catch {}
                                }
                            }
                            
                            # skip this share if it's in the exclude list
                            elseif ($excludedShares -notcontains $netname.ToUpper()){
                                # see if we want to check access to this share
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        #"\\$server\$netname" # `t- $remark"
                                        $objShares += $(AddShareObject -ShareName "\\$server\$netname")
                                    }
                                    catch {}
                                }
                                else{
                                    #"\\$server\$netname" # `t- $remark"
                                    $objShares += $(AddShareObject -ShareName "\\$server\$netname")
                                }
                            } 
                            
                        }
                        
                    }
                }
                
            }
            
        }
    }
    return $objShares
}


function Invoke-ShareFinderThreaded {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.
        Threaded version of Invoke-ShareFinder.
        Author: @harmj0y
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.
        Threaded version of Invoke-ShareFinder.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.
        
        .EXAMPLE
        > Invoke-ShareFinder -ExcludedShares IPC$,PRINT$
        Find shares on the domain excluding IPC$ and PRINT$

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        
        $HostList,

        [string[]]
        $ExcludedShares = @(),

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [String]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Invoke-ShareFinderThreaded on domain $targetDomain with delay of $Delay"
    $servers = @()

    $servers = $HostList
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock = {
        param($Server, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){
            # get the shares for this host and check what we find
            $shares = Get-NetShare -HostName $Server
            foreach ($share in $shares) {
                Write-Debug "[*] Server share: $share"
                $netname = $share.shi1_netname
                $remark = $share.shi1_remark
                $path = '\\'+$server+'\'+$netname

                # make sure we get a real share name back
                if (($netname) -and ($netname.trim() -ne '')){
                    # if we're just checking for access to ADMIN$
                    if($CheckAdmin){
                        if($netname.ToUpper() -eq "ADMIN$"){
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                    }
                    # skip this share if it's in the exclude list
                    elseif ($excludedShares -notcontains $netname.ToUpper()){
                        # see if we want to check access to this share
                        if($CheckShareAccess){
                            # check if the user has access to this path
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                        else{
                            "\\$server\$netname `t- $remark"
                        }
                    } 
                }
            }
        }
    }

    # Adapted from:
    #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
 
    # grab all the current variables for this runspace
    $MyVars = Get-Variable -Scope 1
 
    # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
    $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
 
    # Add Variables from Parent Scope (current runspace) into the InitialSessionState 
    ForEach($Var in $MyVars) {
        If($VorbiddenVars -notcontains $Var.Name) {
        $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
        }
    }

    # Add Functions from current runspace to the InitialSessionState
    ForEach($Function in (Get-ChildItem Function:)) {
        $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
    }
 
    # threading adapted from
    # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
    # Thanks Carlos!   
    $counter = 0

    # create a pool of maxThread runspaces   
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
    $pool.Open()

    $jobs = @()   
    $ps = @()   
    $wait = @()

    $serverCount = $servers.count
    "`r`n[*] Enumerating $serverCount servers..."

    foreach ($server in $servers){
        
        # make sure we get a server name
        if ($server -ne ''){
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            While ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()
   
            $ps[$counter].runspacepool = $pool

            # add the script block + arguments
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares).AddParameter('CheckAdmin', $CheckAdmin)
    
            # start job
            $jobs += $ps[$counter].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$counter].AsyncWaitHandle

        }
        $counter = $counter + 1
    }

    Write-Verbose "Waiting for scanning threads to finish..."

    $waitTimeout = Get-Date

    while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -milliseconds 500
        } 

    # end async call   
    for ($y = 0; $y -lt $counter; $y++) {     

        try {   
            # complete async job   
            $ps[$y].EndInvoke($jobs[$y])   

        } catch {
            Write-Warning "error: $_"  
        }
        finally {
            $ps[$y].Dispose()
        }    
    }

    $pool.Dispose()
}

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}


$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']

# ----------------------------------- #
# ------ END Invoke-ShareFinder ----- #



# ------ BEGIN Check-CPRModulus Functions ----- #

Function IsValidDate {
    <#
        .SYNOPSIS
        Check if a date is valud.

        Author:  @our_name
        
        .DESCRIPTION
        Check if a date is valud.

    #>
param (
    [Parameter(Mandatory=$true)][int]$cpr0,
    [Parameter(Mandatory=$true)][int]$cpr1,
    [Parameter(Mandatory=$true)][int]$cpr2,
    [Parameter(Mandatory=$true)][int]$cpr3
)  

    if ((("$cpr2$cpr3") -gt 12) -or (("$cpr0$cpr1") -gt 31)) 
    {
        $IsValidDate = $false
    }
    else 
    {
        $IsValidDate = $true
    }

    return $IsValidDate
}

function IsNumeric {
    <#
        .SYNOPSIS
        Returns true if input is numeric.

        Author:  @our_name
        
        .DESCRIPTION
        Returns true if input is numeric.


        .PARAMETER x
        Something to test
      #>
param
(
    [Parameter(Mandatory=$true)]$x
)
    try 
    {
        0 + $x | Out-Null
        return $true
    } 
    catch 
    {
        return $false
    }
}

function Check-CPRModulus {
<#
    .SYNOPSIS

    Checks if a cpr number (Danish social security number) is modulus 11.

    .DESCRIPTION

    The function checks if the provided cpr number is modulus 11.

    The following dates are excepted and will always return true

	1. januar 1960	1. januar 1964	1. januar 1965	1. januar 1966
	1. januar 1969	1. januar 1970	1. januar 1980	1. januar 1982
	1. januar 1984	1. januar 1985	1. januar 1986	1. januar 1987
	1. januar 1988	1. januar 1989	1. januar 1990	1. januar 1992 

    Reference: https://www.cpr.dk/cpr-systemet/personnumre-uden-kontrolciffer-modulus-11-kontrol/

    .PARAMETER cpr

    The cpr number that will be modulus 11 checked.

    .OUTPUTS
    $True/$False

    .EXAMPLE

    $IsCPRNumber = Check-CPRModules -cpr "111111-1111"
#>

param 
(
    [Parameter(Mandatory=$true)][string]$cpr
)
    # check cpr is one of the dates where modulus 11 is not applicable 
    # https://www.cpr.dk/cpr-systemet/personnumre-uden-kontrolciffer-modulus-11-kontrol/
    $CprsWithoutModulusCheck = @('010160', '010164', '010165', '010166', 
                                 '010169', '010170', '010180', '010182',
                                 '010184', '010185', '010186', '010187',
                                 '010188', '010189', '010190', '010192')

    # REPLACE EXPECTED CHARS - THEN CHECK IF IS NUMERIC. IF NOT NUMERIC -> RETURN FALSE (WILL NOT RETURN)
    $cpr=$cpr.Replace('-','').Replace(' ','')
    if ((Isnumeric -x $cpr) -eq $false) {return $cprExists}

    $cprExists = $false

    # IF INPUT IS NOT 9 OR 10 CHARACTERS
    if ($cpr.Length -lt 9 -or $cpr.Length -gt 10) {  }
    else 
    {
        if ($CprsWithoutModulusCheck.Contains( $cpr.Substring(0,6)))
        {
            $cprExists = $true
        }
        else 
        {
            $cprdate="$cpr0$cpr1$cpr2$cpr3$cpr4$cpr5"

            [int]$cpr0=($cpr).Substring(0,1)
            [int]$cpr1=($cpr).Substring(1,1)
            [int]$cpr2=($cpr).Substring(2,1)
            [int]$cpr3=($cpr).Substring(3,1)
            [int]$cpr4=($cpr).Substring(4,1)
            [int]$cpr5=($cpr).Substring(5,1)
            [int]$cpr6=($cpr).Substring(6,1)
            [int]$cpr7=($cpr).Substring(7,1)
            [int]$cpr8=($cpr).Substring(8,1)

            if ($cpr.Length -gt 9) 
            {
                $cpr9=($cpr).Substring(9,1)
            }
            else
            {
                $cpr9=""
            }

            # IF THE DATE IS NOT VALID - RETURN FALSE (WILL NOT RETURN)
            if ((IsValidDate -cpr0 $cpr0 -cpr1 $cpr1 -cpr2 $cpr2 -cpr3 $cpr3) -eq $false) { return $cprExists}

            if ($cpr -ne "") 
            {
                [decimal]$findCPR  = ( $cpr0 * 4 ) + ( $cpr1 * 3 ) + ( $cpr2 * 2 ) + ( $cpr3 * 7 ) + ( $cpr4 * 6 ) + ( $cpr5 * 5 ) + ( $cpr6 * 4 )  + ( $cpr7 * 3 ) + ( $cpr8 * 2 ) 
                $cprtest2 = ( $findCPR/11 - [math]::floor( $findCPR / 11 ) ) * 11
                $cprtest3 = [math]::round($cprtest2)

                if ($cprtest3 -eq 1) 
                {
                    # Cifferet kan ikke være 1
                    return $cprExists
                }
                elseif ($cprtest3 -eq 0) 
                {
                    $cprtest3 = 11
                } 

                $cprGuess = 11 - $cprtest3
                if ($cpr9 -ne "") 
                {
                    if ($cpr9 -eq $cprGuess) 
                    {
                        $cprExists = $true
                    }        
                }
            }
        }
    }

    return $cprExists
}

# ------ END Check-CPRModulus Functions ----- #


Function Set-ProcessPriorityBelowNormal {
    <#
        .SYNOPSIS
        Changes the priority for the processpath to below normal.

        .DESCRIPTION
        Changes the priority for the processpath to below normal.
        This prevents systems becomming unresponsive when running cpr-finder.


        .PARAMETER ProcessPath
        Path to the process, for which you would like to change priority to below normla.
     #>
    param (
        [Parameter(Mandatory=$true)]
            [string]$ProcessPath
    )
    # set process to run below normal priority to keep server responsive
    (Get-Process | Where-Object {$_.Path -eq $ProcessPath}).PriorityClass = "BelowNormal" 
}

Function Check-IsProcessRunning {
    <#
        .SYNOPSIS
        Checks if the a scan is already in progress.

        .DESCRIPTION
        Checks if the a scan is already in progress, to prevent starting multiple scans at once.

        .PARAMETER ProcessPath
        Path to the process.
     #>
        
     $ReturnValue = $False
     $result= $null;$result=(Get-Process -ErrorAction SilentlyContinue |? name -in "flpsearch","FileLocatorPro")
     if ( $result -ne $null )
     {
        $Returnvalue = $True
        $result
     }
}

Function ShowScanProgress {

   # $LastShareOrDiskSearched50L
#    $LastLines = Get-Content $OutFileFLPSearch -tail 52

$LastLines = Get-Content $OutFileFLPSearch -tail 52

    foreach($line in $LastLines)
    { 
        # .pst files are handles slightly different and other files
        if ($line.StartsWith("\\")) 
        {
            $ArrLine           = $Line.Split("`t")
            $FullFilePath      = $ArrLine[0]
            $ArrFullFilePath   = $FullFilePath.Split('\')
            $ComputerName      = $ArrFullFilePath[2]
            $FirstFolderName   = $ArrFullFilePath[3]
            $ShareName         = "\\$ComputerName\$FirstFolderName"
            $LastShareOrDrive  = $ShareName 
        }
        elseif ($line -like '[A-z]:\*')
        {
            $LastShareOrDrive  = $line.Substring(0,2) 
        }
    }

    $ArrShareList = $SearchTarget.Split(';')
    $SearchTargetLength = $ArrShareList.Count

    if ($ArrShareList.Contains($LastShareOrDrive))
    {        [int]$ShareIndex = $ArrShareList.IndexOf($LastShareOrDrive) + 1 
        
        if ($SearchTargetLength -gt 1) 
        {
            if ($ScanMode.Contains("DomainMode")) 
            {
                Write-Progress -Activity "|| Scanning (progressbar can fluctuate, due to multithreaded nature of the scanner)" -Status "|| Scanning $ShareIndex/$SearchTargetLength shares" -PercentComplete ($ShareIndex / $SearchTargetLength * 100)     
            }  
            else 
            {
                Write-Progress -Activity "|| Scanning (progressbar can fluctuate, due to multithreaded nature of the scanner)" -Status "|| Scanning $ShareIndex/$SearchTargetLength drives" -PercentComplete ($ShareIndex / $SearchTargetLength * 100)  
            } 
        }
    }
}

Function Run-Scanner{
    <#
        .SYNOPSIS
        Runs filelocator pro.

        .DESCRIPTION
        Starts the actual scan.

        .PARAMETER ProcessPath
        flpsearchpath, path to the executable
        flpsearchCriteriaPath, parth to the predefined search criteria.
        ShareList, list of shares to scan
        OutFileFlpSearch output path.
        StartGui, if set to true the search will start with GUI
     #>
    # https://help.mythicsoft.com/filelocatorpro/en/commandline.htm
    param (
    [Parameter(Mandatory=$true)]
        [string]$flpsearchPath,
    [Parameter(Mandatory=$true)]
        [string]$flpsearchCriteriaPath,
    [Parameter(Mandatory=$true)]
        [string]$ShareList,
    [Parameter(Mandatory=$true)]
        [string]$OutFileFLPSearch,
    [Parameter(Mandatory=$false)]
        [switch]$StartGui
    )

    # run filelocater pro
    Write-Host "|| Searching for CPR-Numbers." 
    Write-Host "|| Starting external application, this can take a while."
     
    if ($StartGui.IsPresent) 
    { 
        Write-Host "|| Running in GUI mode. This is for " -NoNewline
        write-host "illustration only" -NoNewline -ForegroundColor Yellow
        Write-host ". The result will not be used and parsed!"
        Write-Host "|| GUI-mode allows you to see if the scan is actually running. Once that has been confirmed, restart wihtout -StartGUI."

        & $flpsearchPath $flpsearchCriteriaPath -d $ShareList -oeu -ofb -oc -ol 50 -pc     
        PauseAndClose
    } 
    else 
    { 

        Start-Process $flpsearchPath -ArgumentList $flpsearchCriteriaPath, "-d", $ShareList.Replace("'",'"'), "-oeu","-ofb","-oc"," -o",$OutFileFLPSearch,"-ol 50", "-pc"
        sleep 2
        try { Set-ProcessPriorityBelowNormal -ProcessPath $flpsearchPath}
        catch { sleep 10 }    

        #LOOP, WHILE SCAN IS RUNNING
        Do
        {
            ShowScanProgress
            Start-Sleep 10
        }while (Get-Process -Name flpsearch -ErrorAction SilentlyContinue)
    }
    Write-Host "|| " -NoNewline
    Write-Host "Scan complete." -ForegroundColor Green
}


Function IsInExclusionList 
{
    <#
        .SYNOPSIS
       Exception list, if a commonly known "real" CPR number is used for internal test, it can be excluded from the search.
        
        .DESCRIPTION
       Exception list, if a commonly known "real" CPR number is used for internal test, it can be excluded from the search.

        .PARAMETER cpr
        The CPR number check against the exclude list.
     #>

    param ([string]$cpr)
   
    if ($ExclusionList.contains($cpr)) { return $true }
    else { return $false}
    
}

Function AddFileObject {
  <#
       .SYNOPSIS
       Internal function which adds file information to a collection.

        Author:  @our_name
        
        .DESCRIPTION
        Internal function which adds file information to a collection.

        .PARAMETER ProcessPath
        
     #>
    param 
    (
        [String]$ComputerName = "",
        [String]$FullFilePath = "",
        [String]$FileLink = "",
        [String]$FileName = "",
        [String]$ShareName = "",
        [String]$FileSize = "",
        [String]$DocumentType = "",
        [String]$CreationDate = "",
        [String]$ModifyDate = "",
        [String]$LastAccessDate = "",
        [String]$FileOwner = "",       
        [String]$ModulusConfirmed = "",
        [String]$OnExclusionList = "",
        [String]$FirstMatchedCPR = ""
    )
    if ($ScanMode.Contains("DomainMode")) 
    {
        $FileObject = New-Object PSObject
            $FileObject | Add-Member -type NoteProperty -Name 'ComputerName' -Value $ComputerName
            $FileObject | Add-Member -type NoteProperty -Name 'FullFilePath' -Value $FullFilePath
            $FileObject | Add-Member -type NoteProperty -Name 'FileLink' -Value $FileLink
            $FileObject | Add-Member -type NoteProperty -Name 'FileName' -Value $FileName
            $FileObject | Add-Member -type NoteProperty -Name 'ShareName' -Value $ShareName
            $FileObject | Add-Member -type NoteProperty -Name 'FileSize' -Value $FileSize
            $FileObject | Add-Member -type NoteProperty -Name 'DocumentType' -Value $DocumentType
            $FileObject | Add-Member -type NoteProperty -Name 'CreationDate' -Value $CreationDate
            $FileObject | Add-Member -type NoteProperty -Name 'ModifyDate' -Value $ModifyDate
            $FileObject | Add-Member -type NoteProperty -Name 'LastAccessDate' -Value $LastAccessDate
            $FileObject | Add-Member -type NoteProperty -Name 'FileOwner' -Value $FileOwner
            $FileObject | Add-Member -type NoteProperty -Name 'ModulusConfirmed' -Value $ModulusConfirmed
            $FileObject | Add-Member -type NoteProperty -Name 'OnExclusionList' -Value $OnExclusionList
    }
    elseif ($IncludeCPRInOutput.IsPresent)
    {
            $FileObject = New-Object PSObject
            $FileObject | Add-Member -type NoteProperty -Name 'ComputerName' -Value $ComputerName
            $FileObject | Add-Member -type NoteProperty -Name 'FullFilePath' -Value $FullFilePath
            $FileObject | Add-Member -type NoteProperty -Name 'FileLink' -Value $FileLink
            $FileObject | Add-Member -type NoteProperty -Name 'FileName' -Value $FileName
            $FileObject | Add-Member -type NoteProperty -Name 'ShareName' -Value $ShareName
            $FileObject | Add-Member -type NoteProperty -Name 'FileSize' -Value $FileSize
            $FileObject | Add-Member -type NoteProperty -Name 'DocumentType' -Value $DocumentType
            $FileObject | Add-Member -type NoteProperty -Name 'CreationDate' -Value $CreationDate
            $FileObject | Add-Member -type NoteProperty -Name 'ModifyDate' -Value $ModifyDate
            $FileObject | Add-Member -type NoteProperty -Name 'LastAccessDate' -Value $LastAccessDate
            $FileObject | Add-Member -type NoteProperty -Name 'FileOwner' -Value $FileOwner
            $FileObject | Add-Member -type NoteProperty -Name 'ModulusConfirmed' -Value $ModulusConfirmed
            $FileObject | Add-Member -type NoteProperty -Name 'FirstMatchedCPR' -Value $FirstMatchedCPR
            $FileObject | Add-Member -type NoteProperty -Name 'OnExclusionList' -Value $OnExclusionList
    } 
    else
    {
        $FileObject = New-Object PSObject
            $FileObject | Add-Member -type NoteProperty -Name 'ComputerName' -Value $ComputerName
            $FileObject | Add-Member -type NoteProperty -Name 'FullFilePath' -Value $FullFilePath
            $FileObject | Add-Member -type NoteProperty -Name 'FileLink' -Value $FileLink
            $FileObject | Add-Member -type NoteProperty -Name 'FileName' -Value $FileName
            $FileObject | Add-Member -type NoteProperty -Name 'FileSize' -Value $FileSize
            $FileObject | Add-Member -type NoteProperty -Name 'DocumentType' -Value $DocumentType
            $FileObject | Add-Member -type NoteProperty -Name 'CreationDate' -Value $CreationDate
            $FileObject | Add-Member -type NoteProperty -Name 'ModifyDate' -Value $ModifyDate
            $FileObject | Add-Member -type NoteProperty -Name 'LastAccessDate' -Value $LastAccessDate
            $FileObject | Add-Member -type NoteProperty -Name 'FileOwner' -Value $FileOwner
            $FileObject | Add-Member -type NoteProperty -Name 'ModulusConfirmed' -Value $ModulusConfirmed
            $FileObject | Add-Member -type NoteProperty -Name 'OnExclusionList' -Value $OnExclusionList
    }
    return $FileObject 
}

Function ParseOutputFile {
  <#
        .SYNOPSIS
        Parsing output file from filelocator pro into a readable format.

        
        Author:  @our_name
        
        .DESCRIPTION
        This function parses the output once the scan has been complated.
        During the parsing process multiple steps are performed.

        Owner identification, where the owner of the file is found and recorded.

        Modulus 11 check, is performed to ensure the CPR number is not a false posetive,
        the modulus 11 check eliminates a large procentage of false posetives.

        The scan records each CPR hit found in every file up to a predefined maximum (50 by default), once we have a match which
        also matches the modulus 11 check, furthe processing and matchi is stopped, and the file is handled as a confirmed hit.
                

        .PARAMETER ProcessPath
        ExportHTML, if set to true export will be as html
        ExprotCsv, if set to true export will be as csv
     #>


    Set-StrictMode -Version 1

    $IsModulusConfirmed           = 0
    $FilesHandled                 = 0
    $ArrCprModulusConfirmed       = @()
    $HandlingPSTFile              = 0
    $InExclutionListCounter       = 0
    $ScanDate                     = Get-Date

    # setting date from culture
    $CultureDateTimeFormat = (Get-Culture).DateTimeFormat
    $DateFormat            = $CultureDateTimeFormat.ShortDatePattern
    $TimeFormat            = $CultureDateTimeFormat.LongTimePattern
    $DateTimeFormat        = "$DateFormat $TimeFormat"

    $ExclusionList         = $ExclusionList.replace('-','')
    

    try 
    { 
        $InputFile = Get-Content -path $OutFileFLPSearch
    } 
    catch 
    { 
        "File does not exist ($OutFileFLPSearch)" 
        PauseAndClose
    }

    $fileCreationTime = get-date (Get-Item $OutFileFLPSearch).CreationTime -UFormat "%Y-%m-%d"
    $Files = @()
    Write-Host "|| Parsing output."

    foreach($line in $InputFile)
    { 
        
        # .pst files are handles slightly different and other files
        if (($line.StartsWith("\\") -or  $line -like '[A-z]:\*') -and ($line.contains(".pst\") -or $line.contains(".zip\") -or $line.contains(".ost\")) ) 
        {
            # RESET MODULUS CHECK VARIABLE
            $IsModulusConfirmed  = 0
            $HandlingPSTFile     = 1
            $OnExclusionList     = 0 
            $FilesHandled        = $FilesHandled + 1
            $FirstMatchedCPRTemp = ''

            # SPLIT LINE AND STORE VARIABLES
            $ArrLine            = $Line.Split("`t")

            if ($line.Contains(".zip\")) { [int]$IndexZip = $line.IndexOf(".zip\") }
            else { [int]$IndexZip = 100000 }
            if ($line.Contains(".pst\")) { [int]$IndexPST = $line.IndexOf(".pst\") }
            else { [int]$IndexPST = 100000 }
            if ($line.Contains(".ost\")) { [int]$IndexOST = $line.IndexOf(".ost\") }
            else { [int]$IndexOST = 100000 }

            $MinimumIndexTemp = [int] $IndexZip, $IndexPST, $IndexOST

            $MinimumIndex = ($MinimumIndexTemp | measure -Minimum).Minimum

            $FileLink           = $ArrLine[0].Substring(0, $MinimumIndex +4)
            $FullFilePath       = $ArrLine[0]
            $FileSize           = $ArrLine[1]
            $DocumentType       = $ArrLine[2]  
                   
            $CreationDate   = [DateTime]::ParseExact($ArrLine[3],$DateTimeFormat,$null)
            $ModifyDate     = [DateTime]::ParseExact($ArrLine[4],$DateTimeFormat,$null)
            $LastAccessDate = [DateTime]::ParseExact($ArrLine[5],$DateTimeFormat,$null)
            $AmountLines    = $ArrLine[6]

            # PARSE FULLFILEPATH AND STORE VARIABLES
            if ($ScanMode.Contains("DomainMode") -or $line.StartsWith("\\"))
            {
                $ArrFullFilePath = $FullFilePath.Split('\')
                $ComputerName    = $ArrFullFilePath[2]
                $FirstFolderName = $ArrFullFilePath[3]
                $FileName        = $ArrFullFilePath[-1]
                $ShareName       = "\\$ComputerName\$FirstFolderName"
            }
            else 
            {
                $ArrFullFilePath = $FullFilePath.Split('\')
                $ComputerName    = $env:COMPUTERNAME
                $FirstFolderName = $ArrFullFilePath[1]
                $FileName        = $ArrFullFilePath[-1]
                $ShareName       = "\\$ComputerName\$FirstFolderName"
            }


            if (Test-Path $FullFilePath) 
            {
                $FileOwner = $(Get-ChildItem $FullFilePath | Select @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}).owner 
            }  
        }
        elseif ($line.StartsWith("\\") -or $line -like '[A-z]:\*')
        {       

            $FilesHandled       = $FilesHandled + 1

            # RESET MODULUS CHECK VARIABLE 
            $IsModulusConfirmed  = 0 
            $OnExclusionList     = 0 
            $HandlingPSTFile     = 0
            $FirstMatchedCPRTemp = ''

            # SPLIT LINE (tab) AND STORE VARIABLES
            $ArrLine        = $Line.Split("`t")
            $FullFilePath   = $ArrLine[0]
            $FileLink       = $FullFilePath
            $FileSize       = $ArrLine[1]
            $DocumentType   = $ArrLine[2]     

            $CreationDate   = [DateTime]::ParseExact($ArrLine[3],$DateTimeFormat,$null)
            $ModifyDate     = [DateTime]::ParseExact($ArrLine[4],$DateTimeFormat,$null)
            $LastAccessDate = [DateTime]::ParseExact($ArrLine[5],$DateTimeFormat,$null)
            $AmountLines    = $ArrLine[6]

            # PARSE FULLFILEPATH AND STORE VARIABLES
            if ($ScanMode.Contains("DomainMode") -or $line.StartsWith("\\"))
            {
                $ArrFullFilePath = $FullFilePath.Split('\')
                $ComputerName    = $ArrFullFilePath[2]
                $FirstFolderName = $ArrFullFilePath[3]
                $FileName        = $ArrFullFilePath[-1]
                $ShareName       = "\\$ComputerName\$FirstFolderName"
            }
            else 
            {
                $ArrFullFilePath = $FullFilePath.Split('\')
                $ComputerName    = $env:COMPUTERNAME
                $FirstFolderName = $ArrFullFilePath[1]
                $FileName        = $ArrFullFilePath[-1]
                $ShareName       = "\\$ComputerName\$FirstFolderName"
            }

            if (Test-Path $FullFilePath) 
            {
                $FileOwner = $(Get-ChildItem $FullFilePath | Select @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}).owner 
            } 
        }
        elseif ($line -eq "") 
        {
            # If line is empty then we have reach a new file, and are no longer handling CPR matches within the same file, thus file will be added to the collection.
            if ($IncludeCPRInOutput.IsPresent) 
            {
                $Files += $(AddFileObject   -ComputerName     $ComputerName        `
                                            -FullFilePath     $FullFilePath        `
                                            -FileLink         $FileLink            `
                                            -FileName         $filename            `
                                            -ShareName        $ShareName           `
                                            -FileSize         $FileSize            `
                                            -DocumentType     $DocumentType        `
                                            -CreationDate     $CreationDate        `
                                            -ModifyDate       $ModifyDate          `
                                            -LastAccessDate   $LastAccessDate      `
                                            -FileOwner        $FileOwner           `
                                            -ModulusConfirmed $IsModulusConfirmed  `
                                            -FirstMatchedCPR  $FirstMatchedCPRTemp `
                                            -OnExclusionList  $OnExclusionList)
            }
            else 
            {
                $Files += $(AddFileObject   -ComputerName     $ComputerName        `
                                            -FullFilePath     $FullFilePath        `
                                            -FileLink         $FileLink            `
                                            -FileName         $filename            `
                                            -ShareName        $ShareName           `
                                            -FileSize         $FileSize            `
                                            -DocumentType     $DocumentType        `
                                            -CreationDate     $CreationDate        `
                                            -ModifyDate       $ModifyDate          `
                                            -LastAccessDate   $LastAccessDate      `
                                            -FileOwner        $FileOwner           `
                                            -ModulusConfirmed $IsModulusConfirmed  `
                                            -OnExclusionList  $OnExclusionList)
            }
        }
        else 
        {            
            $ArrLine = $line.Split("`t")
            $cpr = $ArrLine[1]

            if ($cpr.length -gt 10) { $cpr = $cpr.Substring(0,11).Replace('-','').trim() }
            if ($cpr.length -eq 11) { $cpr =  $cpr.Substring(0,10) }

            if ($(IsInExclusionList -cpr $cpr) -eq $false) 
            {
                $OnExclusionList = 0               
            }
            else 
            {
                $OnExclusionList = 1
            }

            # If no cpr has yet been confirmed with modulus 11 then check cpr. Otherwise the check is skipped
            if (($IsModulusConfirmed -eq 0))
            {
                    if ($(Check-CprModulus -cpr $cpr) -eq $true) 
                    {
                        $ArrCprModulusConfirmed += $cpr
                        $IsModulusConfirmed = 1
                        $FirstMatchedCPRTemp = $cpr
                        if ($OnExclusionList -eq 1)
                        {
                            $InExclutionListCounter++
                        }

                    }
            }
        }
    } 

    
        $Header = @'
        <style>
        TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: black; color: white; text-align: left;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        </style>
'@

    if ($IncludeCPRInOutput.IsPresent) 
    {
        $FilesHelperTable = $Files |
        Where-Object {$_.FullFilePath} |
            Select ComputerName, `
                    @{n='FullFilePath';e={"<a href='$($_.FileLink)'>$($_.FullFilePath)</a>"}}, `
                    FileName, `
                    ShareName, `
                    FileSize, `
                    DocumentType, `
                    CreationDate,     `
                    ModifyDate,       `
                    LastAccessDate ,  `
                    FileOwner      ,  `
                    ModulusConfirmed,  `
                    FirstMatchedCPR,
                    OnExclusionList | ConvertTo-Html -Head $Header
    }
    else 
    {
       $FilesHelperTable = $Files |
            Where-Object {$_.FullFilePath} |
                Select ComputerName, `
                       @{n='FullFilePath';e={"<a href='$($_.FileLink)'>$($_.FullFilePath)</a>"}}, `
                       FileName, `
                       ShareName, `
                       FileSize, `
                       DocumentType, `
                       CreationDate,     `
                       ModifyDate,       `
                       LastAccessDate ,  `
                       FileOwner      ,  `
                       ModulusConfirmed,
                       OnExclusionList | ConvertTo-Html -Head $Header
    }

    Add-Type -AssemblyName System.Web
    [System.Web.HttpUtility]::HtmlDecode($FilesHelperTable) | Out-File $OutFileHTML
    $Files | Export-Csv $OutFilecsv -NoTypeInformation 
    Write-Host "|| " -NoNewline
    Write-Host "Done " -NoNewline -ForegroundColor Green
    Write-Host "parsing."
    Write-Host "|| Generated: " -NoNewline
    Write-Host $OutFileHtml -ForegroundColor Green
    Write-Host "|| Generated: " -NoNewline
    Write-Host $OutFilecsv -ForegroundColor Green
    Write-Host "|| Files handled " -NoNewline
    Write-Host $FilesHandled -ForegroundColor Yellow
    Write-Host "|| Files with modulus confirmed " -NoNewline
    Write-Host $ArrCprModulusConfirmed.Count -ForegroundColor Yellow
    Write-Host "|| Hereof in exclusionlist " -NoNewline
    Write-Host $InExclutionListCounter -ForegroundColor Yellow
}

Function ADModuleExistsCheck
{
    $ReturnValue = $false

    $OsInfo = $(Get-WmiObject -Class Win32_OperatingSystem).ProductType # Workstation = 1, Domain Controller = 2, Server = 3
     # Check if ad module exists. If not then check if user accepts insallation on the fly
        if (!(Get-Module -ListAvailable ActiveDirectory)) 
        {         
            $ReturnValue = $false
            Write-Host '|| ' -NoNewline
            Write-Host 'The Active Directory Module for Powershell is not installed.' -ForegroundColor Red
            Write-Host '|| ' -NoNewline
            Write-Host 'Install the module and run the script again.' -ForegroundColor Red
            Write-Host -NoNewLine '|| Press any key to continue...';
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            PauseAndClose            
        }
        else 
        {
            $ReturnValue = $true
        }

    return $ReturnValue
}

Function DefineSearchTargetDomain
{

    $ReturnValue = ""

    $ComputerStaleDate = (Get-Date).AddDays(-$ComputerPasswordAgeDays)

    if ($ScanMode -eq "DomainModeServersOnly") 
    {        
        $AdComputers = Get-ADComputer -filter {(passwordLastSet -ge $ComputerStaleDate) -and (enabled -eq $true) -and (OperatingSystem -like '*server*') } -properties Name
        $AdComputers += Get-ADComputer -filter {(passwordLastSet -ge $ComputerStaleDate) -and (enabled -eq $true) -and (OperatingSystem -notlike '*Windows*') } -properties Name
    }
    elseif ($ScanMode -eq "DomainModeAll")
    {
        $AdComputers = Get-ADComputer -filter {(passwordLastSet -ge $ComputerStaleDate) -and (enabled -eq $true) } -properties Name
    }
    
    $AdComputersCount = $AdComputers.Count
    
    Write-Host "|| Found $AdComputersCount computer objects in Active Directory, based on selected search criteria."

    [int]$Counter = 0
    [int]$ShareCounter = 0

    if ($AdComputersCount -gt 0) 
    {
        Write-Host "|| Enumerating shares"
        ForEach ($AdComputer in $AdComputers)
        {
            $Counter++
            
            Write-Progress -Activity "|| Locating shares from computer objects in Active Directory" -Status "|| Enumerating shares on $Counter/$adcomputerscount computers" -PercentComplete ($Counter / $AdComputersCount * 100)
            if ($DebugVerbose.IsPresent) { Write-Host "Debug::Working on computer: $adcomputer" -ForegroundColor Cyan }
   
            $ComputerName = $AdComputer.Name
            $Shares=$(Invoke-ShareFinder $ComputerName -CheckShareAccess -ExcludeStandard)

            foreach ($share in $Shares)
            {
                $ShareName = $share.ShareName
                $ShareCounter++
                

                if ($ShareName.Contains(' '))
                {
                    if ($ShareCounter -eq 1) {  $ReturnValue = "'" + $ShareName + "'" }
                    else { $ReturnValue = $ReturnValue + ";'" + $ShareName + "'" }
                }
                else 
                {
                    if ($ShareCounter -eq 1) {  $ReturnValue = $ShareName }
                    else { $ReturnValue = $ReturnValue + ';' + $ShareName }
                }
            } 
        }
    }
    Write-Host "|| Enumerated " -NoNewline
    Write-Host $ShareCounter  -ForegroundColor Yellow -NoNewline
    Write-Host " shares."
    return $ReturnValue
}

Function DefineSearchTargetStandalone
{
    $ReturnValue = ''

    $FixedDrives = GET-WMIOBJECT –query “SELECT * from win32_logicaldisk where DriveType = '3'"

    ForEach ($FixedDrive in $FixedDrives) 
    {
     
        $FixedDriveName = $FixedDrive.DeviceId

        if ($FixedDriveName.Contains(' '))
        {
            if ($ReturnValue.Length -eq 0) {  $ReturnValue = "'" + $FixedDriveName + "'" }
            else { $ReturnValue = $ReturnValue + ";'" + $FixedDriveName + "'" }
        }
        else 
        {
            if ($ReturnValue.Length -eq 0) {  $ReturnValue = $FixedDriveName }
            else { $ReturnValue = $ReturnValue + ';' + $FixedDriveName }
        }

    }
    Write-Host "|| Enumerated " -NoNewline
    Write-Host $ReturnValue -ForegroundColor Yellow -NoNewline
    Write-host " as fixed drive(s)."
    return $ReturnValue
}
Function DefineSearchTargetStandaloneScanTarget
{
param ($Target)

    $ReturnValue = ''

    $FixedDrives = @()
    $FixedDrives = $Target.split(';')

    ForEach ($FixedDrive in $FixedDrives) 
    {     
        if ($FixedDrive.Contains(' '))
        {
            if ($ReturnValue.Length -eq 0) {  $ReturnValue = "'" + $FixedDrive + "'" }
            else { $ReturnValue = $ReturnValue + ";'" + $FixedDrive + "'" }
        }
        else 
        {
            if ($ReturnValue.Length -eq 0) {  $ReturnValue = $FixedDrive }
            else { $ReturnValue = $ReturnValue + ';' + $FixedDrive }
        }

    }
    return $ReturnValue
}


Function PauseAndClose
{
    Write-Host '|| Exiting...' -ForegroundColor Red;
    Exit
}

Function CPR-Finder 
{
<#
    .SYNOPSIS

    Identifies shares and checks file content for CPR-numbers (Danish Social Security Numbers (SSN)). 
	The check is performed based on regular expressions. 
    Modulus 11 check is performed to minimize the amount of false positives.
	Dates where modulus 11 is not upheld are excluded.

    License: BSD 3-Clause


    #>	
    
    if (!$(Test-Path $flpsearchPath)) 
    {
        Write-Host "|| Can't locate FileLocator Pro on the following path ($flpsearchPath)" -ForegroundColor Red
        PauseAndClose
    }

    if (!$(Test-Path $flpsearchCriteriaPath)) 
    {
        Write-Host "|| Can't locate FileLocatorPro saved criteria on the following path ($flpsearchCriteriaPath)" -ForegroundColor Red
        PauseAndClose
    }
    
    if (!$(Test-Path $OutfilePath)) 
    {
        New-Item -Path $OutfilePath
    } 
    
    if (Check-IsProcessRunning)
    {
         Write-Host "|| FileLocatorPro is already running." -ForegroundColor Red
         PauseAndClose
    }

    
    if ($ScanMode.Contains("DomainMode")) 
    {

        if ($ScanTarget -ne "") 
        {
            Write-Host "||" -NoNewline
            Write-Host " ScanTarget can't be combined with DomainModes" -ForegroundColor Red
            Write-Host "|| Try Get-Help '$PSCommandPath'"
            PauseAndClose

        }


        $IsPartOfDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain 

        if ($IsPartOfDomain -eq $true )
        {
            $ADModuleExists = ADModuleExistsCheck

            if ($ADModuleExists) 
            {
                $SearchTarget = DefineSearchTargetDomain
            }

        } 
        else 
        {
            Write-Host "Computer not part of domain. Unable to perform domain scan"
            PauseAndClose
        }
    } 
    else
    {
        if ($ScanTarget -ne "") 
        {
            Write-Host "|| Scan target provided: " -NoNewline
            Write-Host $ScanTarget -NoNewline -ForegroundColor Yellow
            Write-Host "."
            $SearchTarget = DefineSearchTargetStandaloneScanTarget $ScanTarget           
        }
        else 
        {
            $SearchTarget = DefineSearchTargetStandalone
        
        }
    }                    
                   

    if ($StartGui.IsPresent) {Run-Scanner -flpsearchPath $flpsearchPath -flpsearchCriteriaPath $flpsearchCriteriaPath -ShareList $SearchTarget -OutFileFLPSearch $OutFileFLPSearch -StartGui}
    else  {Run-Scanner -flpsearchPath $flpsearchPath -flpsearchCriteriaPath $flpsearchCriteriaPath -ShareList $SearchTarget -OutFileFLPSearch $OutFileFLPSearch} 

    Start-Sleep -Seconds 5   

    # EXPORT FILES IN CSV AND HTML FORMAT
    ParseOutputFile 
}

# RUN CPR-Finder
CPR-Finder