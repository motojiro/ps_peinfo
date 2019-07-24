# todo  : 引数の解析部分
#       : functionまたはclassで各セクションを分別

function getExecutableProperties($path){

    $executable_path = $path

    # dos header設定関連
    $dos_header_offset = 0x00
    $e_magic_offset = 0x00
    $e_lfanew_offset = 0x3C # to a address of PE header(e_lfanew) 

    # compiled time: 
    # $size = 4(bytes)
    # offset = 4 from the top of the resource directory
    # timestampは秒単位の計算(unix timestamp)
    # ただし、[Datetime]::FromFileTimeだとナノ秒単位で取ってきてしまう(nt epoch)

    $buffer = 4096 #byte

    $bytes = New-Object byte[]($buffer)

    # System.IO.FileStreamオブジェクトの生成(バイナリデータ, fileのモード, ファイルのアクセス権限)
    # やっていることは、「どのファイルを」「何をするか」「どのような権限（rwx)で行うか」の設定
    $stream = New-Object System.IO.FileStream(
        $executable_path, 
        [System.IO.FileMode]::Open, 
        [System.IO.FileAccess]::Read
        )

    # MZヘッダのチェック
    if(!($stream.read($bytes, 0, $buffer) -and $bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a)){
        Write-Host 'Not PE image'
        Exit-PSSession
    }

    $e_magic_value = [System.BitConverter]::ToUInt16($bytes, $dos_header_offset + $e_magic_offset)

    # nt headerのオフセットが確定
    $nt_header_offset = [System.BitConverter]::ToUInt32($bytes, $dos_header_offset + $e_lfanew_offset)
    $peSignature = [System.BitConverter]::ToUInt32($bytes, $nt_header_offset)

    # nt file header設定関連（e_lfanewの値によって変化)
    # dword ptr [e_lfanew_offset] + 以下のオフセット
    $nt_file_header_offset = $nt_header_offset + 0x04
    $machineTypeOffset = 0x00
    $numberOfSectionsOffset = 0x02
    $compileTimeOffset = 0x04
    # PointerToSymbolTable = 0x0C
    # NumberOfSymbols = 0x10
    $sizeOfOptionalHeaderoffset = 0x010

    $machineType = [System.BitConverter]::ToUInt16($bytes, $nt_file_header_offset + $machineTypeOffset)
    $numberOfSections = [System.BitConverter]::ToUInt16($bytes, $nt_file_header_offset + $numberOfSectionsOffset)
    $compileTime = [System.BitConverter]::ToUInt32($bytes, $nt_file_header_offset + $compileTimeOffset)
    $sizeOfOptionalHeader = [System.BitConverter]::ToUInt16($bytes, $nt_file_header_offset + $sizeOfOptionalHeaderOffset)
   
    $bitness = switch($machineType){
        0x014c {'x86'}
        0x8664 {'x64'}
        default {'Unknown'}
    }

    $unix_epoch = New-Object -TypeName DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    $compiledTimeStampUTC = $unix_epoch.AddSeconds($compileTime)
    $compiledTimeStampLocal = $compiledTimeStampUTC.AddHours(9)

    # optional header設定関連
    $optional_header_offset = $nt_header_offset + 0x18
    $magicValueOffset = 0x00
    $addressOfentrypointOffset = 0x10
    $subsystemOffset = 0x44         #touint16
    $dllCharacteristicsOffset = 0x46 #touint16

    $magic_value = [System.BitConverter]::ToUInt16($bytes, $optional_header_offset + $magicValueOffset)
    $addressOfentrypoint = [System.BitConverter]::ToUInt32($bytes, $optional_header_offset + $addressOfentrypointOffset)
    $subsystem = [System.BitConverter]::ToUInt16($bytes, $optional_header_offset + $subsystemOffset)
    $dllCharacteristics = [System.BitConverter]::ToUInt16($bytes, $optional_header_offset + $dllCharacteristicsOffset)

    $optional_header_magic = switch($magic_value){
        0x0107 {'ROM'}
        0x010b {'PE32'}
        0x020b {'PE32+(64bit binary)'}
        default {'Unknown'}
    }

    $mode = switch($subsystem){
        1 {'Device Driver'}
        2 {'GUI'}
        3 {'Console'}
        default {'Unknown'}
    }

    # Data Directory設定関連（member size == 0x04)
    $data_directory_start_offset = $optional_header_offset + 0x60
    $ExportDirectoryRvaOffset = 0x00
    $ExportDirectorySizeOffset = 0x04
    $ImportDirectoryRvaOffset = 0x08
    $ImportDirectorySizeOffset = 0x0c
    # resourcedirectory rva/ size
    # exception directory rva/ size
    # security directory rva/ size
    # relocation directory rva/ size
    # debug Directory rva/ size
    # architecture directory rva/ size
    # reserved x 2
    # TLS Directory rva/ size
    # Configuration Directory rva/ size
    # Bound Import Directory rva/ size
    $iatDirectoryRvaOffset = 0x60
    $iatDirectorySizeOffset = 0x64
    # delay import directory rva/ size
    # .net metadata directory rva

    $iatDirectoryRva = [System.BitConverter]::ToUInt32($bytes, $data_directory_start_offset + $iatDirectoryRvaOffset)
    $iatDirectorySize = [System.BitConverter]::ToUInt32($bytes, $data_directory_start_offset + $iatDirectorySizeOffset)




    # Section Header設定関連


    # Import Directory設定関連



    # Resource Directory設定関連

    $stream.close()

    return [pscustomobject]@{
        # dos header info
        'DOS Signature'             = $e_magic_value.ToString("X2")
        # nt header info
        'PE Signature'              = $peSignature.ToString("X2")
        # nt file header info
        'Bitness'                   = $bitness
        'Optional header Image magic' = $optional_header_magic
        'Address Of EntryPoint'     = $addressOfentrypoint.ToString("X2")
        'Mode'                      = $mode
        'NumberOfSections'          = $numberOfSections
        'Compile Time(UTC)'         = $compiledTimeStampUTC
        'Compile Time(UTF+9:00)'    = $compiledTimeStampLocal
        'sizeOfOptionalHeader'      = $sizeOfOptionalHeader.ToString() + '(' + $sizeOfOptionalHeader.ToString("X2") + ')'
        'IAT Directory RVA/Size'    = $iatDirectoryRva.ToString("X2") + '/' + $iatDirectorySize.ToString("X2")
    }
}

function dos_header_parser(){

}

getExecutableProperties executable_file_path
