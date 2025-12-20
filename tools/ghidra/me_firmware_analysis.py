#!/usr/bin/env python3
# FirmwareGuard Intel ME Firmware Analysis Script
# Specialized analysis for Intel Management Engine firmware
# OFFLINE-ONLY: No network connectivity required

from __future__ import print_function
import json
import os
import struct
from datetime import datetime

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.flatapi import FlatProgramAPI
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# ============================================================================
# Intel ME Structures
# ============================================================================

# Flash Partition Table (FPT) entry structure
FPT_ENTRY_SIZE = 32
FPT_SIGNATURE = b'$FPT'

# ME Module types
ME_MODULE_TYPES = {
    0: "PROCESS",
    1: "SHARED_LIBRARY",
    2: "DATA",
    3: "MANIFEST"
}

# Known ME partition names
ME_PARTITIONS = {
    "FTPR": "Factory Partition",
    "NFTP": "Non-Factory Partition",
    "ROMB": "ROM Boot Extensions",
    "WCOD": "Wireless Code",
    "LOCL": "Localization",
    "FLOG": "Flash Log",
    "UTOK": "Update Token",
    "IVBP": "IVB Platform",
    "PSVN": "Platform SVN",
    "FTUP": "FW Update",
    "DLMP": "Dell ME Update",
    "EFFS": "EFFS Partition",
    "MFS": "ME File System"
}

# Known telemetry-related strings in ME firmware
ME_TELEMETRY_STRINGS = [
    "telemetry", "beacon", "heartbeat", "report_status",
    "phone_home", "remote_status", "connectivity_check",
    "platform_discovery", "device_registration",
    "usage_reporting", "error_reporting", "crash_dump",
    "analytics", "metrics", "statistics"
]

# ME vulnerability signatures (CVE patterns)
ME_VULN_PATTERNS = {
    "CVE-2017-5689": {
        "name": "Intel AMT Privilege Escalation",
        "description": "Critical vulnerability allowing unauthenticated remote access",
        "affected_versions": ["6.x", "7.x", "8.x", "9.x", "10.x", "11.0-11.6"],
        "severity": "critical"
    },
    "CVE-2018-3616": {
        "name": "Intel CSME Logic Bug",
        "description": "Logic bug allowing code execution",
        "affected_versions": ["11.x"],
        "severity": "high"
    },
    "CVE-2020-0566": {
        "name": "Intel CSME Memory Corruption",
        "description": "Memory corruption vulnerability",
        "affected_versions": ["12.x", "13.x", "14.x"],
        "severity": "high"
    },
    "CVE-2020-8705": {
        "name": "Intel Boot Guard Key Extraction",
        "description": "Boot Guard key extraction via hardware attack",
        "affected_versions": ["All"],
        "severity": "medium"
    }
}


class IntelMEAnalyzer:
    """Intel ME firmware deep analysis"""

    def __init__(self, program=None, flat_api=None):
        self.program = program
        self.api = flat_api
        self.decompiler = None
        self.monitor = ConsoleTaskMonitor() if GHIDRA_AVAILABLE else None
        self.results = {
            "me_info": {},
            "partitions": [],
            "modules": [],
            "telemetry_indicators": [],
            "vulnerability_indicators": [],
            "suspicious_functions": [],
            "strings_of_interest": [],
            "risk_score": 0,
            "risk_level": "unknown"
        }

        if GHIDRA_AVAILABLE and program:
            self._init_decompiler()

    def _init_decompiler(self):
        """Initialize Ghidra decompiler"""
        try:
            self.decompiler = DecompInterface()
            self.decompiler.openProgram(self.program)
        except Exception as e:
            print(f"[!] Decompiler init failed: {e}")

    def analyze(self):
        """Run complete ME analysis"""
        print("[*] Starting Intel ME firmware analysis...")

        self._get_me_info()
        self._find_partitions()
        self._enumerate_modules()
        self._detect_telemetry()
        self._check_vulnerabilities()
        self._find_suspicious_functions()
        self._extract_strings()
        self._calculate_risk()

        return self.results

    def _get_me_info(self):
        """Extract ME firmware metadata"""
        try:
            if not self.program:
                return

            memory = self.program.getMemory()
            base = self.program.getImageBase()

            self.results["me_info"] = {
                "name": self.program.getName(),
                "format": str(self.program.getExecutableFormat()),
                "image_base": str(base),
                "analysis_time": datetime.now().isoformat()
            }

            # Try to find ME version string
            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                try:
                    # Search for version pattern
                    addr = block.getStart()
                    end = block.getEnd()

                    while addr.compareTo(end) < 0:
                        # Look for version string patterns
                        bytes_read = []
                        for i in range(20):
                            try:
                                bytes_read.append(memory.getByte(addr.add(i)) & 0xFF)
                            except:
                                break

                        # Check for version pattern like "11.8.50.3425"
                        try:
                            s = bytes(bytes_read).decode('ascii', errors='ignore')
                            if s.count('.') == 3 and all(c.isdigit() or c == '.' for c in s[:12]):
                                self.results["me_info"]["version"] = s[:12]
                        except:
                            pass

                        addr = addr.add(16)
                except:
                    pass

        except Exception as e:
            print(f"[!] Error getting ME info: {e}")

    def _find_partitions(self):
        """Find and enumerate ME partitions"""
        try:
            if not self.program:
                return

            memory = self.program.getMemory()

            # Search for $FPT signature
            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                addr = block.getStart()

                try:
                    # Read potential FPT signature
                    sig = []
                    for i in range(4):
                        sig.append(memory.getByte(addr.add(i)) & 0xFF)

                    if bytes(sig) == FPT_SIGNATURE:
                        self.results["me_info"]["fpt_found"] = True
                        self.results["me_info"]["fpt_address"] = str(addr)

                        # Parse FPT entries
                        num_entries = memory.getInt(addr.add(4))

                        for i in range(min(num_entries, 32)):
                            entry_addr = addr.add(0x30 + i * FPT_ENTRY_SIZE)

                            # Read partition name
                            name_bytes = []
                            for j in range(4):
                                name_bytes.append(memory.getByte(entry_addr.add(j)) & 0xFF)
                            name = bytes(name_bytes).decode('ascii', errors='ignore')

                            # Read partition offset and length
                            offset = memory.getInt(entry_addr.add(8))
                            length = memory.getInt(entry_addr.add(12))

                            if name.strip() and offset > 0:
                                partition_info = {
                                    "name": name,
                                    "description": ME_PARTITIONS.get(name, "Unknown"),
                                    "offset": hex(offset),
                                    "length": hex(length)
                                }
                                self.results["partitions"].append(partition_info)

                except Exception as e:
                    pass

        except Exception as e:
            print(f"[!] Error finding partitions: {e}")

    def _enumerate_modules(self):
        """Enumerate ME modules"""
        try:
            if not self.program:
                return

            func_mgr = self.program.getFunctionManager()

            # ME modules often have specific naming patterns
            module_patterns = [
                "bup", "kernel", "policy", "amt", "dal", "lms",
                "heci", "mei", "ptt", "softsku", "icc", "pavp"
            ]

            module_funcs = {}

            for func in func_mgr.getFunctions(True):
                name = func.getName().lower()

                for pattern in module_patterns:
                    if pattern in name:
                        if pattern not in module_funcs:
                            module_funcs[pattern] = []
                        module_funcs[pattern].append({
                            "name": func.getName(),
                            "address": str(func.getEntryPoint())
                        })

            for module, funcs in module_funcs.items():
                self.results["modules"].append({
                    "name": module.upper(),
                    "functions_count": len(funcs),
                    "functions": funcs[:10]  # Limit output
                })

        except Exception as e:
            print(f"[!] Error enumerating modules: {e}")

    def _detect_telemetry(self):
        """Detect telemetry functionality"""
        try:
            if not self.program:
                return

            func_mgr = self.program.getFunctionManager()
            listing = self.program.getListing()

            # Search function names for telemetry indicators
            for func in func_mgr.getFunctions(True):
                name = func.getName().lower()

                for pattern in ME_TELEMETRY_STRINGS:
                    if pattern in name:
                        indicator = {
                            "type": "function_name",
                            "pattern": pattern,
                            "function": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "severity": "high"
                        }
                        self.results["telemetry_indicators"].append(indicator)
                        self.results["risk_score"] += 20
                        break

            # Decompile and search for telemetry patterns
            if self.decompiler:
                for func in func_mgr.getFunctions(True):
                    try:
                        results = self.decompiler.decompileFunction(func, 30, self.monitor)

                        if not results.decompileCompleted():
                            continue

                        decomp = results.getDecompiledFunction()
                        if not decomp:
                            continue

                        c_code = decomp.getC().lower()

                        for pattern in ME_TELEMETRY_STRINGS:
                            if pattern in c_code:
                                indicator = {
                                    "type": "code_pattern",
                                    "pattern": pattern,
                                    "function": func.getName(),
                                    "address": str(func.getEntryPoint()),
                                    "severity": "medium"
                                }
                                self.results["telemetry_indicators"].append(indicator)
                                self.results["risk_score"] += 10

                    except Exception as e:
                        pass

        except Exception as e:
            print(f"[!] Error detecting telemetry: {e}")

    def _check_vulnerabilities(self):
        """Check for known vulnerability indicators"""
        try:
            version = self.results["me_info"].get("version", "")

            if not version:
                self.results["vulnerability_indicators"].append({
                    "name": "Version Unknown",
                    "description": "Unable to determine ME version for vulnerability assessment",
                    "severity": "medium",
                    "recommendation": "Extract ME version using MEAnalyzer tool"
                })
                return

            # Parse major version
            major_version = version.split('.')[0] if '.' in version else version

            for cve, info in ME_VULN_PATTERNS.items():
                for affected in info["affected_versions"]:
                    if affected == "All" or major_version in affected or f"{major_version}.x" == affected:
                        self.results["vulnerability_indicators"].append({
                            "cve": cve,
                            "name": info["name"],
                            "description": info["description"],
                            "severity": info["severity"],
                            "me_version": version
                        })

                        # Add to risk score based on severity
                        if info["severity"] == "critical":
                            self.results["risk_score"] += 40
                        elif info["severity"] == "high":
                            self.results["risk_score"] += 25
                        elif info["severity"] == "medium":
                            self.results["risk_score"] += 10

        except Exception as e:
            print(f"[!] Error checking vulnerabilities: {e}")

    def _find_suspicious_functions(self):
        """Find suspicious or potentially dangerous functions"""
        try:
            if not self.program:
                return

            func_mgr = self.program.getFunctionManager()

            suspicious_patterns = [
                ("backdoor", "critical", "Potential backdoor functionality"),
                ("exploit", "critical", "Exploit-related code"),
                ("shell", "high", "Shell or command execution"),
                ("exec", "high", "Code execution functionality"),
                ("inject", "high", "Injection functionality"),
                ("hook", "medium", "Hooking functionality"),
                ("patch", "medium", "Patching functionality"),
                ("bypass", "high", "Security bypass"),
                ("override", "medium", "Override functionality"),
                ("debug", "low", "Debug functionality (may leak info)"),
                ("test", "low", "Test code (should not be in production)")
            ]

            for func in func_mgr.getFunctions(True):
                name = func.getName().lower()

                for pattern, severity, description in suspicious_patterns:
                    if pattern in name:
                        self.results["suspicious_functions"].append({
                            "name": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "pattern": pattern,
                            "severity": severity,
                            "description": description
                        })

                        if severity == "critical":
                            self.results["risk_score"] += 30
                        elif severity == "high":
                            self.results["risk_score"] += 15
                        elif severity == "medium":
                            self.results["risk_score"] += 5

        except Exception as e:
            print(f"[!] Error finding suspicious functions: {e}")

    def _extract_strings(self):
        """Extract strings of interest"""
        try:
            if not self.program:
                return

            listing = self.program.getListing()

            interesting_patterns = [
                "http", "https", "ftp",  # Network indicators (should not be in ME)
                "password", "passwd", "secret", "key", "token",  # Credentials
                "debug", "test", "dev",  # Debug indicators
                "error", "fail", "crash",  # Error handling
                "version", "build", "date"  # Version info
            ]

            # Get defined strings
            for data in listing.getDefinedData(True):
                if data.hasStringValue():
                    try:
                        string_val = data.getValue()
                        if string_val and len(str(string_val)) > 4:
                            s = str(string_val).lower()

                            for pattern in interesting_patterns:
                                if pattern in s:
                                    self.results["strings_of_interest"].append({
                                        "address": str(data.getAddress()),
                                        "value": str(string_val)[:100],
                                        "pattern": pattern
                                    })

                                    # Network strings in ME are very suspicious
                                    if pattern in ["http", "https", "ftp"]:
                                        self.results["risk_score"] += 25
                                        self.results["telemetry_indicators"].append({
                                            "type": "network_string",
                                            "value": str(string_val)[:100],
                                            "severity": "critical",
                                            "description": "Network URL found in ME firmware"
                                        })
                                    break
                    except:
                        pass

        except Exception as e:
            print(f"[!] Error extracting strings: {e}")

    def _calculate_risk(self):
        """Calculate overall risk level"""
        score = self.results["risk_score"]

        # ME presence itself is a risk
        if self.results.get("partitions"):
            score += 10

        self.results["risk_score"] = min(score, 100)  # Cap at 100

        if score >= 80:
            self.results["risk_level"] = "critical"
        elif score >= 60:
            self.results["risk_level"] = "high"
        elif score >= 40:
            self.results["risk_level"] = "medium"
        elif score >= 20:
            self.results["risk_level"] = "low"
        else:
            self.results["risk_level"] = "minimal"


def analyze_me_binary(filepath):
    """Standalone ME binary analysis without Ghidra"""
    import hashlib

    results = {
        "filename": os.path.basename(filepath),
        "filepath": filepath,
        "analysis_time": datetime.now().isoformat(),
        "partitions": [],
        "fpt_found": False,
        "risk_level": "unknown"
    }

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        results["file_size"] = len(data)
        results["sha256"] = hashlib.sha256(data).hexdigest()

        # Search for FPT signature
        fpt_offset = data.find(FPT_SIGNATURE)
        if fpt_offset >= 0:
            results["fpt_found"] = True
            results["fpt_offset"] = hex(fpt_offset)

            # Parse FPT entries
            num_entries = struct.unpack('<I', data[fpt_offset+4:fpt_offset+8])[0]

            for i in range(min(num_entries, 32)):
                entry_offset = fpt_offset + 0x30 + i * FPT_ENTRY_SIZE

                if entry_offset + FPT_ENTRY_SIZE > len(data):
                    break

                name = data[entry_offset:entry_offset+4].decode('ascii', errors='ignore')
                offset = struct.unpack('<I', data[entry_offset+8:entry_offset+12])[0]
                length = struct.unpack('<I', data[entry_offset+12:entry_offset+16])[0]

                if name.strip() and offset > 0:
                    results["partitions"].append({
                        "name": name,
                        "description": ME_PARTITIONS.get(name, "Unknown"),
                        "offset": hex(offset),
                        "length": hex(length)
                    })

        # Check for telemetry strings
        results["telemetry_strings"] = []
        for pattern in ME_TELEMETRY_STRINGS:
            if pattern.encode() in data.lower():
                results["telemetry_strings"].append(pattern)

        # Calculate basic risk
        risk_score = 0
        if results["fpt_found"]:
            risk_score += 20
        risk_score += len(results["telemetry_strings"]) * 10

        if risk_score >= 60:
            results["risk_level"] = "high"
        elif risk_score >= 30:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

        results["risk_score"] = risk_score

    except Exception as e:
        results["error"] = str(e)

    return results


def main():
    """Main entry point"""
    if GHIDRA_AVAILABLE:
        try:
            api = FlatProgramAPI(currentProgram)
            analyzer = IntelMEAnalyzer(currentProgram, api)
            results = analyzer.analyze()

            # Output results
            output_dir = "/var/lib/firmwareguard/ghidra_analysis"
            os.makedirs(output_dir, exist_ok=True)

            filename = currentProgram.getName().replace(" ", "_")
            output_file = os.path.join(
                output_dir,
                f"me_analysis_{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            print(f"\n[+] Intel ME Analysis Complete!")
            print(f"[+] Output: {output_file}")
            print(f"[+] Risk Level: {results['risk_level'].upper()}")
            print(f"[+] Risk Score: {results['risk_score']}/100")
            print(f"[+] Partitions Found: {len(results['partitions'])}")
            print(f"[+] Telemetry Indicators: {len(results['telemetry_indicators'])}")
            print(f"[+] Vulnerability Indicators: {len(results['vulnerability_indicators'])}")

        except NameError:
            print("[!] Run this script from within Ghidra")
    else:
        print("[*] Running in standalone mode (limited analysis)")
        print("[*] For full analysis, run within Ghidra")


if __name__ == "__main__":
    main()
