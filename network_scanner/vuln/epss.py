from __future__ import annotations

import re
from typing import Optional
import requests
from lxml import etree

from network_scanner.config.settings import Settings


def get_epss_score(settings: Settings, cve: str) -> dict[str, float]:
    """Получает оценку EPSS для уязвимости через API"""
    try:
        response = requests.get(f"{settings.epss_api_url}?cve={cve}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("data") and len(data["data"]) > 0:
                item = data["data"][0]
                return {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
    except Exception as e:
        print(f"EPSS request failed for {cve}: {str(e)}")
    return {"epss": 0.0, "percentile": 0.0}


def calculate_exploit_probability(epss_scores: list[float], threshold: float) -> float:
    """Рассчитывает вероятность взлома хоста на основе EPSS scores"""
    if not epss_scores:
        return 0.0
    
    total_multiplier = 1.0
    for epss in epss_scores:
        if epss > threshold:
            risk_reduction = 1 - epss
            total_multiplier *= risk_reduction
    
    if total_multiplier == 1.0:
        return 0.0
    
    return 1 - total_multiplier


def extract_cves_from_nmap_xml(xml_path: str) -> dict[str, list[str]]:
    """Извлекает CVE из nmap XML (script vulners output)
    
    Returns: dict mapping host_ip -> list of CVE IDs
    """
    parser = etree.XMLParser(recover=True)
    root = etree.parse(xml_path, parser=parser).getroot()
    
    result: dict[str, list[str]] = {}
    
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        if not ip:
            continue
        
        cves: list[str] = []
        
        # Ищем script output в ports
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                scripts_elem = port_elem.find("script")
                if scripts_elem is not None:
                    script_id = scripts_elem.get("id", "")
                    if script_id == "vulners":
                        output = scripts_elem.get("output", "")
                        # Извлекаем CVE из вывода скрипта
                        found_cves = re.findall(r"CVE-\d{4}-\d{1,}", output)
                        cves.extend(found_cves)
        
        # Также проверяем hostscript
        hostscript_elem = host.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                script_id = script_elem.get("id", "")
                if script_id == "vulners":
                    output = script_elem.get("output", "")
                    found_cves = re.findall(r"CVE-\d{4}-\d{1,}", output)
                    cves.extend(found_cves)
        
        if cves:
            result[ip] = list(set(cves))  # Убираем дубликаты
    
    return result


def get_cvss_data(settings: Settings, cve_id: str) -> dict[str, str | float]:
    """Получает данные CVSS для уязвимости через NVD API.
    
    Args:
        settings: Настройки приложения
        cve_id: CVE идентификатор (например, "CVE-2024-1234")
    
    Returns:
        dict: {'version': str, 'baseScore': float, 'vector': str}
    """
    try:
        url = f"{settings.nvd_api_url}?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                metrics = vulnerabilities[0]["cve"].get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_metric = metrics["cvssMetricV31"][0]
                    return {
                        "version": "3.1",
                        "baseScore": float(cvss_metric["cvssData"]["baseScore"]),
                        "vector": str(cvss_metric["cvssData"]["vectorString"]),
                    }
                elif "cvssMetricV30" in metrics:
                    cvss_metric = metrics["cvssMetricV30"][0]
                    return {
                        "version": "3.0",
                        "baseScore": float(cvss_metric["cvssData"]["baseScore"]),
                        "vector": str(cvss_metric["cvssData"]["vectorString"]),
                    }
    except Exception:
        pass
    
    return {"version": "N/A", "baseScore": 0.0, "vector": "N/A"}

