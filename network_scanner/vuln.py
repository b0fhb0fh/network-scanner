from __future__ import annotations

import re
from typing import Optional
import requests
from network_scanner.config.settings import Settings


def extract_cves_from_nmap_xml(xml_path: str) -> dict[str, list[str]]:
    """Извлекает CVE из nmap XML вывода.
    
    Returns:
        dict: {host_ip: [list of CVE IDs]}
    """
    from lxml import etree
    
    host_cves: dict[str, list[str]] = {}
    
    try:
        parser = etree.XMLParser(recover=True)
        root = etree.parse(xml_path, parser=parser).getroot()
        
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            
            addr_elem = host.find("address")
            if addr_elem is None:
                continue
            host_ip = addr_elem.get("addr", "")
            if not host_ip:
                continue
            
            cves: list[str] = []
            
            # Ищем CVE в script output
            for script in host.findall(".//script"):
                output = script.get("output", "")
                if output:
                    found_cves = re.findall(r'CVE-\d{4}-\d{1,}', output)
                    cves.extend(found_cves)
            
            # Также ищем в table элементах script
            for table in host.findall(".//table"):
                for elem in table.findall(".//elem"):
                    text = elem.text or ""
                    found_cves = re.findall(r'CVE-\d{4}-\d{1,}', text)
                    cves.extend(found_cves)
            
            if cves:
                host_cves[host_ip] = list(set(cves))  # Убираем дубликаты
    
    except Exception:
        pass
    
    return host_cves


def get_epss_score(settings: Settings, cve_id: str) -> dict[str, float]:
    """Получает оценку EPSS для уязвимости через API.
    
    Args:
        settings: Настройки приложения
        cve_id: CVE идентификатор (например, "CVE-2024-1234")
    
    Returns:
        dict: {'epss': float, 'percentile': float}
    """
    try:
        url = f"{settings.epss_api_url}?cve={cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("data") and len(data["data"]) > 0:
                item = data["data"][0]
                return {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
    except Exception:
        pass
    
    return {"epss": 0.0, "percentile": 0.0}


def get_cvss_data(settings: Settings, cve_id: str) -> dict[str, str | float]:
    """Получает данные CVSS для уязвимости через NVD API.
    
    Args:
        settings: Настройки приложения
        cve_id: CVE идентификатор (например, "CVE-2024-1234")
    
    Returns:
        dict: {'version': str, 'baseScore': float, 'vector': str}
    """
    try:
        nvd_api_url = getattr(settings, "nvd_api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        url = f"{nvd_api_url}?cveId={cve_id}"
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


def calculate_exploit_probability(epss_scores: list[float], significant_threshold: float) -> float:
    """Рассчитывает вероятность взлома хоста на основе EPSS оценок.
    
    Использует формулу из scanparadis.py:
    total_multiplier = произведение (1 - epss) для всех значимых уязвимостей
    final_risk = 1 - total_multiplier
    
    Args:
        epss_scores: Список EPSS оценок (0.0-1.0)
        significant_threshold: Порог значимости EPSS (по умолчанию 0.1)
    
    Returns:
        float: Вероятность взлома (0.0-1.0)
    """
    if not epss_scores:
        return 0.0
    
    total_multiplier = 1.0
    for epss in epss_scores:
        if epss > significant_threshold:
            risk_reduction = 1 - epss
            total_multiplier *= risk_reduction
    
    if total_multiplier == 1.0:
        return 0.0
    
    return 1 - total_multiplier

