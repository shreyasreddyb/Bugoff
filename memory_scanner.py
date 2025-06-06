import os
import re
import mmap
import psutil
import logging
from typing import List

class MemoryScanner:
    def __init__(self):
        self.suspicious_patterns = [
            rb"MZ.*\x50\x45",  # PE header pattern
            rb"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",  # URLs
            rb"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",  # Email patterns
            rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP addresses
            rb"eval\(.*\)",  # JavaScript eval patterns
            rb"powershell",  # PowerShell patterns
            rb"cmd\.exe",  # Command prompt patterns
        ]
        # Skip these special memory regions
        self.skip_paths = {'[vvar]', '[vsyscall]', '[vdso]', '[stack]', '[heap]'}
        
    def scan_process(self, process) -> List[str]:
        """Scan a single process memory with robust error handling"""
        threats = []
        try:
            mem_regions = process.memory_maps()
            
            for region in mem_regions:
                try:
                    # Handle different psutil versions
                    if hasattr(region, 'addr'):  # Older versions
                        start_addr = region.addr
                        size = region.size
                        path = region.path
                    else:  # Newer versions (5.8.0+)
                        start_addr = region.rss
                        size = region.size
                        path = region.path
                    
                    # Skip problematic regions
                    if not size or path in self.skip_paths:
                        continue
                        
                    # Skip regions that are too large (>10MB)
                    if size > 10 * 1024 * 1024:
                        continue
                        
                    with open(f"/proc/{process.pid}/mem", "rb") as mem_file:
                        try:
                            mem_file.seek(start_addr)
                            # Read in chunks to handle large regions safely
                            chunk_size = min(size, 1024 * 1024)  # 1MB chunks
                            remaining = size
                            while remaining > 0:
                                read_size = min(chunk_size, remaining)
                                data = mem_file.read(read_size)
                                if not data:  # End of readable region
                                    break
                                    
                                # Scan the chunk for patterns
                                for pattern in self.suspicious_patterns:
                                    if re.search(pattern, data):
                                        threat_info = (
                                            f"PID {process.pid} ({process.name()}): "
                                            f"Found {pattern} in memory at {hex(start_addr)}"
                                        )
                                        threats.append(threat_info)
                                        break  # Stop after first match in this chunk
                                
                                remaining -= read_size
                                start_addr += read_size
                                
                        except (OSError, IOError) as e:
                            # Skip unreadable memory regions
                            continue
                            
                except (ValueError, OverflowError) as e:
                    # Handle invalid addresses or sizes
                    continue
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            # Process disappeared or we don't have permission
            pass
            
        return threats
        
    def scan(self) -> List[str]:
        """Scan all processes memory for suspicious patterns"""
        all_threats = []
        
        for process in psutil.process_iter():
            try:
                threats = self.scan_process(process)
                if threats:
                    all_threats.extend(threats)
            except Exception as e:
                logging.warning(f"Error scanning process {process.pid}: {str(e)}")
                continue
                
        return all_threats
        
    def scan_specific_pid(self, pid: int) -> List[str]:
        """Scan specific process by PID"""
        try:
            process = psutil.Process(pid)
            return self.scan_process(process)
        except psutil.NoSuchProcess:
            return []