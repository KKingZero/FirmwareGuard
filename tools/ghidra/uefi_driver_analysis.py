#!/usr/bin/env python3
# FirmwareGuard UEFI Driver Deep Analysis Script
# Specialized analysis for UEFI drivers
# OFFLINE-ONLY: No network connectivity required

from __future__ import print_function
import json
import os
from datetime import datetime

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.symbol import SymbolType, SourceType
    from ghidra.program.model.data import PointerDataType
    from ghidra.program.flatapi import FlatProgramAPI
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# ============================================================================
# UEFI Protocol Database
# ============================================================================

EFI_BOOT_SERVICES_FUNCTIONS = {
    0x18: "RaiseTPL",
    0x20: "RestoreTPL",
    0x28: "AllocatePages",
    0x30: "FreePages",
    0x38: "GetMemoryMap",
    0x40: "AllocatePool",
    0x48: "FreePool",
    0x50: "CreateEvent",
    0x58: "SetTimer",
    0x60: "WaitForEvent",
    0x68: "SignalEvent",
    0x70: "CloseEvent",
    0x78: "CheckEvent",
    0x80: "InstallProtocolInterface",
    0x88: "ReinstallProtocolInterface",
    0x90: "UninstallProtocolInterface",
    0x98: "HandleProtocol",
    0xA8: "RegisterProtocolNotify",
    0xB0: "LocateHandle",
    0xB8: "LocateDevicePath",
    0xC0: "InstallConfigurationTable",
    0xC8: "LoadImage",
    0xD0: "StartImage",
    0xD8: "Exit",
    0xE0: "UnloadImage",
    0xE8: "ExitBootServices",
    0xF0: "GetNextMonotonicCount",
    0xF8: "Stall",
    0x100: "SetWatchdogTimer",
    0x108: "ConnectController",
    0x110: "DisconnectController",
    0x118: "OpenProtocol",
    0x120: "CloseProtocol",
    0x128: "OpenProtocolInformation",
    0x130: "ProtocolsPerHandle",
    0x138: "LocateHandleBuffer",
    0x140: "LocateProtocol",
    0x148: "InstallMultipleProtocolInterfaces",
    0x150: "UninstallMultipleProtocolInterfaces",
    0x158: "CalculateCrc32",
    0x160: "CopyMem",
    0x168: "SetMem",
    0x170: "CreateEventEx"
}

EFI_RUNTIME_SERVICES_FUNCTIONS = {
    0x18: "GetTime",
    0x20: "SetTime",
    0x28: "GetWakeupTime",
    0x30: "SetWakeupTime",
    0x38: "SetVirtualAddressMap",
    0x40: "ConvertPointer",
    0x48: "GetVariable",
    0x50: "GetNextVariableName",
    0x58: "SetVariable",
    0x60: "GetNextHighMonotonicCount",
    0x68: "ResetSystem",
    0x70: "UpdateCapsule",
    0x78: "QueryCapsuleCapabilities",
    0x80: "QueryVariableInfo"
}

# SMM-related GUIDs for detection
SMM_GUIDS = {
    "f4ccbfb7-f6e0-47fd-9dd4-10a8f150c191": "EFI_SMM_BASE2_PROTOCOL_GUID",
    "e5db6c0a-91a0-4e9b-963a-31f4c5c7c7e3": "EFI_SMM_COMMUNICATION_PROTOCOL_GUID",
    "2f707ebb-4a1a-11d4-9a38-0090273fc14d": "EFI_SMM_CPU_PROTOCOL_GUID",
    "eb346b97-975f-4a9f-8b22-f8e92bb3d569": "EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID",
}

# Security-sensitive UEFI variables
SENSITIVE_VARIABLES = [
    "SecureBoot",
    "SetupMode",
    "PK",
    "KEK",
    "db",
    "dbx",
    "dbr",
    "dbt"
]


class UEFIDriverAnalyzer:
    """Deep UEFI driver analysis"""

    def __init__(self, program, flat_api):
        self.program = program
        self.api = flat_api
        self.decompiler = None
        self.monitor = ConsoleTaskMonitor()
        self.results = {
            "driver_info": {},
            "entry_points": [],
            "protocols_installed": [],
            "protocols_consumed": [],
            "boot_services_calls": [],
            "runtime_services_calls": [],
            "smm_handlers": [],
            "variable_access": [],
            "security_issues": [],
            "risk_score": 0
        }

        self._init_decompiler()

    def _init_decompiler(self):
        """Initialize decompiler"""
        try:
            self.decompiler = DecompInterface()
            self.decompiler.openProgram(self.program)
        except Exception as e:
            print(f"[!] Failed to initialize decompiler: {e}")

    def analyze(self):
        """Run full analysis"""
        print("[*] Starting UEFI driver analysis...")

        self._get_driver_info()
        self._find_entry_points()
        self._analyze_protocol_usage()
        self._analyze_service_calls()
        self._detect_smm_usage()
        self._analyze_variable_access()
        self._check_security_issues()

        return self.results

    def _get_driver_info(self):
        """Extract driver metadata"""
        try:
            self.results["driver_info"] = {
                "name": self.program.getName(),
                "path": self.program.getExecutablePath(),
                "image_base": str(self.program.getImageBase()),
                "language": str(self.program.getLanguage()),
                "compiler": str(self.program.getCompiler()),
                "format": str(self.program.getExecutableFormat())
            }
        except Exception as e:
            print(f"[!] Error getting driver info: {e}")

    def _find_entry_points(self):
        """Find driver entry points"""
        try:
            func_mgr = self.program.getFunctionManager()

            # Common UEFI entry point names
            entry_names = [
                "ModuleEntryPoint", "EfiMain", "DxeEntry", "SmmEntry",
                "PeimEntry", "UefiMain", "_ModuleEntryPoint"
            ]

            for func in func_mgr.getFunctions(True):
                name = func.getName()

                if any(en.lower() in name.lower() for en in entry_names):
                    self.results["entry_points"].append({
                        "name": name,
                        "address": str(func.getEntryPoint()),
                        "signature": str(func.getSignature())
                    })

            # Also check for entry point symbol
            symbol_table = self.program.getSymbolTable()
            for sym in symbol_table.getSymbols("entry"):
                self.results["entry_points"].append({
                    "name": "entry",
                    "address": str(sym.getAddress()),
                    "type": "symbol"
                })

        except Exception as e:
            print(f"[!] Error finding entry points: {e}")

    def _analyze_protocol_usage(self):
        """Analyze protocol installation and consumption"""
        try:
            func_mgr = self.program.getFunctionManager()
            listing = self.program.getListing()

            for func in func_mgr.getFunctions(True):
                # Decompile function
                if not self.decompiler:
                    continue

                results = self.decompiler.decompileFunction(func, 30, self.monitor)

                if not results.decompileCompleted():
                    continue

                decomp = results.getDecompiledFunction()
                if not decomp:
                    continue

                c_code = decomp.getC()

                # Check for protocol installation
                if "InstallProtocolInterface" in c_code or "InstallMultipleProtocolInterfaces" in c_code:
                    self.results["protocols_installed"].append({
                        "function": func.getName(),
                        "address": str(func.getEntryPoint())
                    })

                # Check for protocol consumption
                if "LocateProtocol" in c_code or "HandleProtocol" in c_code or "OpenProtocol" in c_code:
                    self.results["protocols_consumed"].append({
                        "function": func.getName(),
                        "address": str(func.getEntryPoint())
                    })

        except Exception as e:
            print(f"[!] Error analyzing protocols: {e}")

    def _analyze_service_calls(self):
        """Analyze Boot Services and Runtime Services usage"""
        try:
            ref_mgr = self.program.getReferenceManager()
            func_mgr = self.program.getFunctionManager()

            for func in func_mgr.getFunctions(True):
                if not self.decompiler:
                    continue

                results = self.decompiler.decompileFunction(func, 30, self.monitor)

                if not results.decompileCompleted():
                    continue

                decomp = results.getDecompiledFunction()
                if not decomp:
                    continue

                c_code = decomp.getC()

                # Check for Boot Services calls
                for offset, name in EFI_BOOT_SERVICES_FUNCTIONS.items():
                    if name in c_code:
                        self.results["boot_services_calls"].append({
                            "service": name,
                            "function": func.getName(),
                            "address": str(func.getEntryPoint())
                        })

                # Check for Runtime Services calls
                for offset, name in EFI_RUNTIME_SERVICES_FUNCTIONS.items():
                    if name in c_code:
                        self.results["runtime_services_calls"].append({
                            "service": name,
                            "function": func.getName(),
                            "address": str(func.getEntryPoint())
                        })

        except Exception as e:
            print(f"[!] Error analyzing service calls: {e}")

    def _detect_smm_usage(self):
        """Detect SMM-related functionality"""
        try:
            func_mgr = self.program.getFunctionManager()

            smm_keywords = [
                "Smm", "SMM", "Smi", "SMI", "SwDispatch",
                "SxDispatch", "PeriodicTimer", "GpiDispatch"
            ]

            for func in func_mgr.getFunctions(True):
                name = func.getName()

                if any(kw in name for kw in smm_keywords):
                    self.results["smm_handlers"].append({
                        "name": name,
                        "address": str(func.getEntryPoint()),
                        "signature": str(func.getSignature())
                    })

                    # SMM usage is a security concern
                    self.results["security_issues"].append({
                        "type": "smm_handler",
                        "function": name,
                        "severity": "high",
                        "description": "SMM handler detected - potential SMM vulnerability surface"
                    })
                    self.results["risk_score"] += 20

        except Exception as e:
            print(f"[!] Error detecting SMM usage: {e}")

    def _analyze_variable_access(self):
        """Analyze UEFI variable access patterns"""
        try:
            func_mgr = self.program.getFunctionManager()

            for func in func_mgr.getFunctions(True):
                if not self.decompiler:
                    continue

                results = self.decompiler.decompileFunction(func, 30, self.monitor)

                if not results.decompileCompleted():
                    continue

                decomp = results.getDecompiledFunction()
                if not decomp:
                    continue

                c_code = decomp.getC()

                # Check for variable access
                if "GetVariable" in c_code or "SetVariable" in c_code:
                    access_type = "read" if "GetVariable" in c_code else "write"

                    if "SetVariable" in c_code:
                        access_type = "write"

                    entry = {
                        "function": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "access_type": access_type
                    }

                    # Check for sensitive variable access
                    for var in SENSITIVE_VARIABLES:
                        if var in c_code:
                            entry["sensitive_variable"] = var
                            self.results["security_issues"].append({
                                "type": "sensitive_variable_access",
                                "variable": var,
                                "function": func.getName(),
                                "access_type": access_type,
                                "severity": "high" if access_type == "write" else "medium",
                                "description": f"Access to security-sensitive variable: {var}"
                            })
                            self.results["risk_score"] += 25 if access_type == "write" else 10

                    self.results["variable_access"].append(entry)

        except Exception as e:
            print(f"[!] Error analyzing variable access: {e}")

    def _check_security_issues(self):
        """Check for known security issues and patterns"""
        try:
            func_mgr = self.program.getFunctionManager()

            # Patterns indicating potential security issues
            dangerous_patterns = {
                "CopyMem": "Potential buffer overflow if size not validated",
                "SetMem": "Potential memory corruption if size not validated",
                "AllocatePool": "Check for return value validation",
                "AllocatePages": "Check for return value validation"
            }

            for func in func_mgr.getFunctions(True):
                if not self.decompiler:
                    continue

                results = self.decompiler.decompileFunction(func, 30, self.monitor)

                if not results.decompileCompleted():
                    continue

                decomp = results.getDecompiledFunction()
                if not decomp:
                    continue

                c_code = decomp.getC()

                for pattern, description in dangerous_patterns.items():
                    if pattern in c_code:
                        self.results["security_issues"].append({
                            "type": "dangerous_pattern",
                            "pattern": pattern,
                            "function": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "severity": "low",
                            "description": description
                        })

        except Exception as e:
            print(f"[!] Error checking security issues: {e}")

    def get_risk_level(self):
        """Calculate overall risk level"""
        score = self.results["risk_score"]

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


def main():
    """Main entry point for Ghidra script"""
    if not GHIDRA_AVAILABLE:
        print("[!] This script must be run within Ghidra")
        return

    try:
        api = FlatProgramAPI(currentProgram)
        analyzer = UEFIDriverAnalyzer(currentProgram, api)
        results = analyzer.analyze()

        risk_level = analyzer.get_risk_level()
        results["risk_level"] = risk_level

        # Output results
        output_dir = "/var/lib/firmwareguard/ghidra_analysis"
        os.makedirs(output_dir, exist_ok=True)

        filename = currentProgram.getName().replace(" ", "_")
        output_file = os.path.join(
            output_dir,
            f"uefi_analysis_{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[+] Analysis complete!")
        print(f"[+] Output: {output_file}")
        print(f"[+] Risk Level: {risk_level.upper()}")
        print(f"[+] Security Issues: {len(results['security_issues'])}")
        print(f"[+] SMM Handlers: {len(results['smm_handlers'])}")
        print(f"[+] Protocols Installed: {len(results['protocols_installed'])}")

    except NameError:
        print("[!] currentProgram not available - run from Ghidra")


if __name__ == "__main__":
    main()
