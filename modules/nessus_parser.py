#!/usr/bin/env python3
"""
Nessus XML Parsing Module

This module extracts vulnerability data from Nessus XML files (.nessus format)
using pytenable library with fallback to xml.etree.ElementTree.
"""

import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

try:
    from tenable.reports import NessusReportv2
    PYTENABLE_AVAILABLE = True
except ImportError:
    PYTENABLE_AVAILABLE = False
    logging.warning("pytenable not available, falling back to xml.etree.ElementTree")


class NessusParser:
    """Parser for Nessus XML vulnerability reports"""
    
    def __init__(self):
        self.severity_mapping = {
            '0': 'Informational',
            '1': 'Low', 
            '2': 'Medium',
            '3': 'High',
            '4': 'Critical'
        }
    
    def parse_nessus_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Nessus XML file and extract vulnerability data
        
        Args:
            file_path: Path to the .nessus XML file
            
        Returns:
            List of dictionaries containing host and vulnerability data
        """
        try:
            if PYTENABLE_AVAILABLE:
                return self._parse_with_pytenable(file_path)
            else:
                return self._parse_with_elementtree(file_path)
        except Exception as e:
            logging.error(f"Error parsing Nessus file {file_path}: {e}")
            raise
    
    def _parse_with_pytenable(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse using pytenable library"""
        hosts_data = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as nessus_file:
                report = NessusReportv2(nessus_file)
                
                # Group vulnerabilities by host
                hosts_dict = {}
                
                for item in report:
                    host_ip = item.get('host-ip', 'Unknown')
                    host_name = item.get('host-fqdn', host_ip)
                    
                    if host_ip not in hosts_dict:
                        hosts_dict[host_ip] = {
                            'host_ip': host_ip,
                            'host_fqdn': item.get('host-fqdn', ''),
                            'os': item.get('operating-system', ''),
                            'scan_start': item.get('HOST_START', ''),
                            'scan_end': item.get('HOST_END', ''),
                            'vulnerabilities': []
                        }
                    
                    # Extract vulnerability details
                    vulnerability = {
                        'plugin_id': item.get('pluginID', ''),
                        'plugin_name': item.get('pluginName', ''),
                        'severity': self.severity_mapping.get(str(item.get('severity', '0')), 'Informational'),
                        'port': item.get('port', ''),
                        'protocol': item.get('protocol', ''),
                        'description': item.get('description', ''),
                        'solution': item.get('solution', ''),
                        'synopsis': item.get('synopsis', ''),
                        'cvss_score': item.get('cvss_base_score', ''),
                        'cvss_vector': item.get('cvss_vector', ''),
                        'cves': self._extract_cves(item.get('cve', '')),
                        'risk_factor': item.get('risk_factor', ''),
                        'see_also': item.get('see_also', ''),
                        'plugin_output': item.get('plugin_output', '')
                    }
                    
                    hosts_dict[host_ip]['vulnerabilities'].append(vulnerability)
                
                hosts_data = list(hosts_dict.values())
                
        except Exception as e:
            logging.error(f"Error parsing with pytenable: {e}")
            raise
        
        return hosts_data
    
    def _parse_with_elementtree(self, file_path: str) -> List[Dict[str, Any]]:
        """Fallback parsing using xml.etree.ElementTree"""
        hosts_data = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Find the Report section
            report = root.find('.//Report')
            if report is None:
                raise ValueError("No Report section found in Nessus XML")
            
            hosts_dict = {}
            
            # Process each ReportHost
            for report_host in report.findall('ReportHost'):
                host_name = report_host.get('name', 'Unknown')
                
                # Extract host properties
                host_properties = {}
                host_props_elem = report_host.find('HostProperties')
                if host_props_elem is not None:
                    for tag in host_props_elem.findall('tag'):
                        tag_name = tag.get('name')
                        if tag_name:
                            host_properties[tag_name] = tag.text or ''
                
                host_ip = host_properties.get('host-ip', host_name)
                
                if host_ip not in hosts_dict:
                    hosts_dict[host_ip] = {
                        'host_ip': host_ip,
                        'host_fqdn': host_properties.get('host-fqdn', ''),
                        'os': host_properties.get('operating-system', ''),
                        'scan_start': host_properties.get('HOST_START', ''),
                        'scan_end': host_properties.get('HOST_END', ''),
                        'vulnerabilities': []
                    }
                
                # Process vulnerabilities (ReportItems)
                for report_item in report_host.findall('ReportItem'):
                    vulnerability = {
                        'plugin_id': report_item.get('pluginID', ''),
                        'plugin_name': report_item.get('pluginName', ''),
                        'severity': self.severity_mapping.get(report_item.get('severity', '0'), 'Informational'),
                        'port': report_item.get('port', ''),
                        'protocol': report_item.get('protocol', ''),
                        'description': self._get_element_text(report_item, 'description'),
                        'solution': self._get_element_text(report_item, 'solution'),
                        'synopsis': self._get_element_text(report_item, 'synopsis'),
                        'cvss_score': self._get_element_text(report_item, 'cvss_base_score'),
                        'cvss_vector': self._get_element_text(report_item, 'cvss_vector'),
                        'cves': self._extract_cves_from_xml(report_item),
                        'risk_factor': self._get_element_text(report_item, 'risk_factor'),
                        'see_also': self._get_element_text(report_item, 'see_also'),
                        'plugin_output': self._get_element_text(report_item, 'plugin_output')
                    }
                    
                    hosts_dict[host_ip]['vulnerabilities'].append(vulnerability)
            
            hosts_data = list(hosts_dict.values())
            
        except Exception as e:
            logging.error(f"Error parsing with ElementTree: {e}")
            raise
        
        return hosts_data
    
    def _get_element_text(self, parent: ET.Element, tag_name: str) -> str:
        """Get text content from XML element"""
        element = parent.find(tag_name)
        return element.text if element is not None and element.text else ''
    
    def _extract_cves(self, cve_data: str) -> List[str]:
        """Extract CVEs from string data"""
        if not cve_data:
            return []
        
        if isinstance(cve_data, list):
            return cve_data
        
        # Split by common separators
        cves = []
        for separator in [',', '\n', ';']:
            if separator in cve_data:
                cves = [cve.strip() for cve in cve_data.split(separator) if cve.strip()]
                break
        
        if not cves and cve_data.strip():
            cves = [cve_data.strip()]
        
        return cves
    
    def _extract_cves_from_xml(self, report_item: ET.Element) -> List[str]:
        """Extract CVEs from XML ReportItem element"""
        cves = []
        
        # Find all CVE elements
        for cve_elem in report_item.findall('cve'):
            if cve_elem.text:
                cves.append(cve_elem.text.strip())
        
        return cves
    
    def get_summary_stats(self, parsed_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from parsed data
        
        Args:
            parsed_data: List of host dictionaries from parse_nessus_file
            
        Returns:
            Dictionary containing summary statistics
        """
        total_hosts = len(parsed_data)
        total_vulnerabilities = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        for host in parsed_data:
            for vuln in host.get('vulnerabilities', []):
                total_vulnerabilities += 1
                severity = vuln.get('severity', 'Informational')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return {
            'total_hosts': total_hosts,
            'total_vulnerabilities': total_vulnerabilities,
            'severity_counts': severity_counts,
            'scan_start': parsed_data[0].get('scan_start', '') if parsed_data else '',
            'scan_end': parsed_data[0].get('scan_end', '') if parsed_data else ''
        } 