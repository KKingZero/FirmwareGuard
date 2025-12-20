#!/usr/bin/env python3
# FirmwareGuard Ghidra Firmware Analysis Script
# Automated UEFI driver and Intel ME firmware analysis
# Usage: analyzeHeadless <project> <name> -import <firmware> -postScript fw_analyze.py
#
# OFFLINE-ONLY: No network connectivity required

from __future__ import print_function
import os
import sys
import json
import hashlib
from datetime import datetime

try:
    # Ghidra imports (available when running inside Ghidra)
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SymbolType
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.program.flatapi import FlatProgramAPI
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False
    print("[!] Warning: Ghidra API not available - running in standalone mode")

# ============================================================================
# Configuration
# ============================================================================

VERSION = "1.0.0"
ANALYSIS_OUTPUT_DIR = "/var/lib/firmwareguard/ghidra_analysis"

# Known UEFI protocol GUIDs for identification
KNOWN_UEFI_GUIDS = {
    "964e5b21-6459-11d2-8e39-00a0c969723b": "EFI_BLOCK_IO_PROTOCOL",
    "09576e91-6d3f-11d2-8e39-00a0c969723b": "EFI_DEVICE_PATH_PROTOCOL",
    "387477c1-69c7-11d2-8e39-00a0c969723b": "EFI_SIMPLE_TEXT_INPUT_PROTOCOL",
    "387477c2-69c7-11d2-8e39-00a0c969723b": "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL",
    "18a031ab-b443-4d1a-a5c0-0c09261e9f71": "EFI_DRIVER_BINDING_PROTOCOL",
    "1d85cd7f-f43d-11d2-9a0c-0090273fc14d": "EFI_LOADED_IMAGE_PROTOCOL",
    "bc62157e-3e33-4fec-9920-2d3b36d750df": "EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL",
    "5b1b31a1-9562-11d2-8e3f-00a0c969723b": "EFI_SYSTEM_TABLE_POINTER",
    "8868e871-e4f1-11d3-bc22-0080c73c8881": "EFI_ACPI_TABLE_GUID",
    "eb9d2d30-2d88-11d3-9a16-0090273fc14d": "EFI_ACPI_20_TABLE_GUID",
}

# Suspicious function names to flag
SUSPICIOUS_FUNCTIONS = [
    "PhoneHome", "Beacon", "Telemetry", "Upload", "Download",
    "Connect", "Socket", "Network", "Remote", "Exfiltrate",
    "Keylog", "Capture", "Hook", "Inject", "Patch", "Modify",
    "SMM", "SmmHandler", "SmiHandler", "SystemManagement"
]

# Known malicious patterns (hex signatures)
MALICIOUS_PATTERNS = {
    "lojax_marker": "4C6F4A6178",  # "LoJax"
    "mosaic_marker": "4D6F73616963",  # "Mosaic"
    "moonbounce_marker": "4D6F6F6E426F756E6365",  # "MoonBounce"
    "blacklotus_marker": "424C6F747573",  # "BLotus"
}

# ============================================================================
# Analysis Classes
# ============================================================================

class FirmwareAnalysisResult:
    """Container for firmware analysis results"""

    def __init__(self, filename):
        self.filename = filename
        self.timestamp = datetime.now().isoformat()
        self.file_hash = ""
        self.file_size = 0
        self.firmware_type = "unknown"
        self.entry_points = []
        self.functions = []
        self.strings = []
        self.guids = []
        self.suspicious_indicators = []
        self.decompiled_functions = {}
        self.risk_score = 0
        self.risk_level = "unknown"

    def to_dict(self):
        return {
            "filename": self.filename,
            "timestamp": self.timestamp,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "firmware_type": self.firmware_type,
            "entry_points": self.entry_points,
            "functions_count": len(self.functions),
            "functions": self.functions[:100],  # Limit output
            "strings_count": len(self.strings),
            "strings": self.strings[:200],  # Limit output
            "guids": self.guids,
            "suspicious_indicators": self.suspicious_indicators,
            "decompiled_functions_count": len(self.decompiled_functions),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


class UEFIAnalyzer:
    """UEFI driver analysis module"""

    def __init__(self, program=None, flat_api=None):
        self.program = program
        self.api = flat_api
        self.result = None

    def analyze(self, result):
        """Perform UEFI-specific analysis"""
        self.result = result

        if not GHIDRA_AVAILABLE or not self.program:
            return self._standalone_analysis()

        # Ghidra-based analysis
        self._identify_uefi_type()
        self._extract_guids()
        self._find_protocol_handlers()
        self._detect_smm_handlers()
        self._check_suspicious_patterns()

        return self.result

    def _standalone_analysis(self):
        """Analysis without Ghidra (file-based only)"""
        self.result.firmware_type = "uefi_driver_standalone"
        return self.result

    def _identify_uefi_type(self):
        """Identify UEFI module type from PE header"""
        try:
            memory = self.program.getMemory()
            base_addr = self.program.getImageBase()

            # Read DOS header
            dos_magic = memory.getShort(base_addr)
            if dos_magic == 0x5A4D:  # MZ
                self.result.firmware_type = "uefi_pe_driver"

                # Get PE header offset
                pe_offset = memory.getInt(base_addr.add(0x3C))
                pe_addr = base_addr.add(pe_offset)

                # Check PE signature
                pe_sig = memory.getInt(pe_addr)
                if pe_sig == 0x00004550:  # PE\0\0
                    # Get subsystem type (offset 92 from PE sig for PE32+)
                    subsystem = memory.getShort(pe_addr.add(92))

                    if subsystem == 10:
                        self.result.firmware_type = "uefi_application"
                    elif subsystem == 11:
                        self.result.firmware_type = "uefi_boot_driver"
                    elif subsystem == 12:
                        self.result.firmware_type = "uefi_runtime_driver"
                    elif subsystem == 13:
                        self.result.firmware_type = "uefi_rom"

        except Exception as e:
            self.result.firmware_type = "uefi_unknown"

    def _extract_guids(self):
        """Extract and identify GUIDs from the binary"""
        try:
            memory = self.program.getMemory()

            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                # Scan for GUID patterns (16 bytes)
                addr = block.getStart()
                end = block.getEnd()

                while addr.compareTo(end) < 0:
                    try:
                        # Read potential GUID
                        guid_bytes = []
                        for i in range(16):
                            guid_bytes.append(memory.getByte(addr.add(i)) & 0xFF)

                        guid_str = self._format_guid(guid_bytes)

                        # Check if known GUID
                        if guid_str.lower() in KNOWN_UEFI_GUIDS:
                            self.result.guids.append({
                                "address": str(addr),
                                "guid": guid_str,
                                "name": KNOWN_UEFI_GUIDS[guid_str.lower()]
                            })

                        addr = addr.add(4)  # Align to 4 bytes
                    except MemoryAccessException:
                        addr = addr.add(4)
                        continue

        except Exception as e:
            pass

    def _format_guid(self, guid_bytes):
        """Format GUID bytes to string"""
        return "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
            (guid_bytes[0] | (guid_bytes[1] << 8) | (guid_bytes[2] << 16) | (guid_bytes[3] << 24)),
            (guid_bytes[4] | (guid_bytes[5] << 8)),
            (guid_bytes[6] | (guid_bytes[7] << 8)),
            guid_bytes[8], guid_bytes[9],
            guid_bytes[10], guid_bytes[11], guid_bytes[12],
            guid_bytes[13], guid_bytes[14], guid_bytes[15]
        )

    def _find_protocol_handlers(self):
        """Find UEFI protocol installation/usage"""
        try:
            symbol_table = self.program.getSymbolTable()

            protocol_funcs = [
                "InstallProtocolInterface",
                "InstallMultipleProtocolInterfaces",
                "LocateProtocol",
                "OpenProtocol",
                "HandleProtocol"
            ]

            for symbol in symbol_table.getAllSymbols(True):
                name = symbol.getName()
                for func_name in protocol_funcs:
                    if func_name in name:
                        self.result.functions.append({
                            "name": name,
                            "address": str(symbol.getAddress()),
                            "type": "protocol_handler"
                        })

        except Exception as e:
            pass

    def _detect_smm_handlers(self):
        """Detect SMM handler registrations"""
        try:
            func_mgr = self.program.getFunctionManager()

            smm_patterns = ["SmmHandler", "SmiHandler", "SwSmiHandler", "ChildDispatcher"]

            for func in func_mgr.getFunctions(True):
                name = func.getName()

                for pattern in smm_patterns:
                    if pattern.lower() in name.lower():
                        self.result.suspicious_indicators.append({
                            "type": "smm_handler",
                            "name": name,
                            "address": str(func.getEntryPoint()),
                            "severity": "high",
                            "description": "SMM handler detected - potential security concern"
                        })
                        self.result.risk_score += 20

        except Exception as e:
            pass

    def _check_suspicious_patterns(self):
        """Check for suspicious code patterns"""
        try:
            func_mgr = self.program.getFunctionManager()

            for func in func_mgr.getFunctions(True):
                name = func.getName()

                for suspicious in SUSPICIOUS_FUNCTIONS:
                    if suspicious.lower() in name.lower():
                        self.result.suspicious_indicators.append({
                            "type": "suspicious_function",
                            "name": name,
                            "address": str(func.getEntryPoint()),
                            "severity": "medium",
                            "description": f"Function name contains suspicious keyword: {suspicious}"
                        })
                        self.result.risk_score += 10

        except Exception as e:
            pass


class IntelMEAnalyzer:
    """Intel Management Engine firmware analysis module"""

    ME_PARTITION_MAGIC = b'\x04\x00\x00\x00$FPT'
    ME_MANIFEST_MAGIC = b'\x24\x4D\x4E\x32'  # $MN2

    def __init__(self, program=None, flat_api=None):
        self.program = program
        self.api = flat_api
        self.result = None

    def analyze(self, result):
        """Perform Intel ME-specific analysis"""
        self.result = result

        if not GHIDRA_AVAILABLE or not self.program:
            return self._standalone_analysis()

        self._identify_me_version()
        self._find_me_modules()
        self._detect_telemetry_functions()
        self._check_known_vulnerabilities()

        return self.result

    def _standalone_analysis(self):
        """Analysis without Ghidra (file-based only)"""
        self.result.firmware_type = "intel_me_standalone"
        return self.result

    def _identify_me_version(self):
        """Identify ME firmware version"""
        try:
            memory = self.program.getMemory()

            # Search for version string pattern
            version_pattern = b"ME Firmware Version"

            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                # Look for FPT (Flash Partition Table)
                addr = block.getStart()
                try:
                    magic = []
                    for i in range(8):
                        magic.append(memory.getByte(addr.add(i)) & 0xFF)

                    if bytes(magic[:4]) == b'$FPT':
                        self.result.firmware_type = "intel_me_firmware"
                        self.result.suspicious_indicators.append({
                            "type": "me_detected",
                            "address": str(addr),
                            "severity": "info",
                            "description": "Intel ME Flash Partition Table found"
                        })
                except:
                    pass

        except Exception as e:
            pass

    def _find_me_modules(self):
        """Find and enumerate ME modules"""
        try:
            memory = self.program.getMemory()

            # ME module names to look for
            me_modules = [
                "FTPR", "NFTP", "ROMB", "WCOD", "LOCL",
                "FLOG", "UTOK", "IVBP", "PSVN", "FTUP"
            ]

            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                # Search for module markers
                for mod_name in me_modules:
                    # This is simplified - real implementation would parse ME structures
                    pass

        except Exception as e:
            pass

    def _detect_telemetry_functions(self):
        """Detect ME telemetry and phone-home functions"""
        try:
            func_mgr = self.program.getFunctionManager()

            telemetry_keywords = [
                "telemetry", "beacon", "heartbeat", "report",
                "upload", "phone", "home", "remote", "network"
            ]

            for func in func_mgr.getFunctions(True):
                name = func.getName().lower()

                for keyword in telemetry_keywords:
                    if keyword in name:
                        self.result.suspicious_indicators.append({
                            "type": "me_telemetry",
                            "name": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "severity": "high",
                            "description": f"Potential ME telemetry function: {keyword}"
                        })
                        self.result.risk_score += 25

        except Exception as e:
            pass

    def _check_known_vulnerabilities(self):
        """Check for known ME vulnerability indicators"""
        # CVE patterns for offline detection
        vuln_patterns = {
            "CVE-2017-5689": "AMT vulnerability indicator",
            "CVE-2018-3616": "TXE vulnerability indicator",
            "CVE-2020-0566": "CSME vulnerability indicator"
        }

        # This would contain actual signature patterns in production
        # For now, flag ME presence as a risk
        if self.result.firmware_type == "intel_me_firmware":
            self.result.suspicious_indicators.append({
                "type": "me_risk",
                "severity": "medium",
                "description": "Intel ME detected - potential attack surface"
            })
            self.result.risk_score += 15


class FirmwareDecompiler:
    """Decompile firmware functions for manual analysis"""

    def __init__(self, program=None):
        self.program = program
        self.decompiler = None
        self.monitor = None

        if GHIDRA_AVAILABLE and program:
            self._init_decompiler()

    def _init_decompiler(self):
        """Initialize Ghidra decompiler"""
        try:
            self.decompiler = DecompInterface()
            self.decompiler.openProgram(self.program)
            self.monitor = ConsoleTaskMonitor()
        except Exception as e:
            self.decompiler = None

    def decompile_function(self, func):
        """Decompile a single function"""
        if not self.decompiler:
            return None

        try:
            results = self.decompiler.decompileFunction(func, 30, self.monitor)
            if results.decompileCompleted():
                return results.getDecompiledFunction().getC()
        except Exception as e:
            pass

        return None

    def decompile_suspicious(self, result):
        """Decompile suspicious functions for review"""
        if not self.program or not self.decompiler:
            return

        func_mgr = self.program.getFunctionManager()

        for indicator in result.suspicious_indicators:
            if "address" in indicator:
                try:
                    addr = self.program.getAddressFactory().getAddress(indicator["address"])
                    func = func_mgr.getFunctionContaining(addr)

                    if func:
                        decompiled = self.decompile_function(func)
                        if decompiled:
                            result.decompiled_functions[indicator["name"]] = decompiled
                except Exception as e:
                    pass


# ============================================================================
# Main Analysis Flow
# ============================================================================

def calculate_risk_level(score):
    """Calculate risk level from score"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "minimal"


def analyze_firmware(program=None, flat_api=None, output_path=None):
    """Main firmware analysis entry point"""

    result = FirmwareAnalysisResult(
        program.getName() if program else "unknown"
    )

    # Calculate file hash if possible
    if program:
        try:
            exe_path = program.getExecutablePath()
            if exe_path and os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    result.file_hash = hashlib.sha256(f.read()).hexdigest()
                result.file_size = os.path.getsize(exe_path)
        except:
            pass

    # Run UEFI analysis
    print("[*] Running UEFI driver analysis...")
    uefi_analyzer = UEFIAnalyzer(program, flat_api)
    result = uefi_analyzer.analyze(result)

    # Run Intel ME analysis
    print("[*] Running Intel ME analysis...")
    me_analyzer = IntelMEAnalyzer(program, flat_api)
    result = me_analyzer.analyze(result)

    # Decompile suspicious functions
    if GHIDRA_AVAILABLE and program:
        print("[*] Decompiling suspicious functions...")
        decompiler = FirmwareDecompiler(program)
        decompiler.decompile_suspicious(result)

    # Calculate final risk level
    result.risk_level = calculate_risk_level(result.risk_score)

    # Output results
    if output_path:
        output_file = output_path
    else:
        output_file = os.path.join(
            ANALYSIS_OUTPUT_DIR,
            f"analysis_{result.filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(result.to_json())

    print(f"[+] Analysis complete: {output_file}")
    print(f"[+] Risk Level: {result.risk_level.upper()} (Score: {result.risk_score})")
    print(f"[+] Suspicious indicators: {len(result.suspicious_indicators)}")

    return result


# Ghidra script entry point
if GHIDRA_AVAILABLE:
    try:
        api = FlatProgramAPI(currentProgram)
        analyze_firmware(currentProgram, api)
    except NameError:
        # Not running in Ghidra context
        pass
