# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import re
import ssl
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver
import requests
from docxtpl import DocxTemplate

from databases.scanner_database import ScannerExecution
from s3.upload_report import UploadReport

# =========================================================
# CONFIG
# =========================================================

TIMEOUT_HTTP = 8
DNS_TIMEOUT = 6
USER_AGENT = "ColCERT-OSINT-Validator/3.0"

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "smtp", "mail", "dkim", "mx", "s1", "s2"
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

CLOUD_FINGERPRINTS = {
    "azurewebsites.net": {
        "provider": "Microsoft Azure",
        "patterns": ["404 Web Site not found", "The resource you are looking for has been removed"],
    },
    "cloudapp.azure.com": {
        "provider": "Microsoft Azure",
        "patterns": ["404", "not found"],
    },
    "amazonaws.com": {
        "provider": "Amazon Web Services",
        "patterns": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "cloudfront.net": {
        "provider": "Amazon CloudFront",
        "patterns": ["ERROR: The request could not be satisfied"],
    },
    "github.io": {
        "provider": "GitHub Pages",
        "patterns": ["There isn't a GitHub Pages site here."],
    },
    "herokuapp.com": {
        "provider": "Heroku",
        "patterns": ["no such app"],
    },
    "netlify.app": {
        "provider": "Netlify",
        "patterns": ["Not Found", "Page not found"],
    },
    "pantheonsite.io": {
        "provider": "Pantheon",
        "patterns": ["404 error unknown site"],
    },
    "firebaseapp.com": {
        "provider": "Firebase",
        "patterns": ["404", "Page Not Found"],
    },
}

# =========================================================
# CVE / NVD
# =========================================================
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CVES_PER_FINGERPRINT = 5

TECH_KEYWORDS = {
    "apache_http_server": "Apache HTTP Server",
    "nginx": "nginx",
    "microsoft_iis": "Microsoft IIS",
    "php": "PHP",
    "openresty": "OpenResty",
    "jetty": "Jetty",
    "tomcat": "Apache Tomcat",
}

# =========================================================
# UTILIDADES
# =========================================================
def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clean_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    return value.strip(" .")

def read_domains(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo: {path}")
    data = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = clean_domain(line)
        if line:
            data.append(line)
    seen = set()
    result = []
    for d in data:
        if d not in seen:
            seen.add(d)
            result.append(d)
    return result

def command_exists(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })
    return s

def dns_query(name: str, rtype: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(name, rtype)
        values = []
        for r in answers:
            if rtype == "TXT":
                if hasattr(r, "strings"):
                    values.append("".join(x.decode(errors="ignore") for x in r.strings))
                else:
                    values.append(str(r).strip('"'))
            else:
                values.append(str(r).rstrip("."))
        return values
    except Exception:
        return []

def resolve_ips(host: str) -> List[str]:
    ips = []
    ips.extend(dns_query(host, "A"))
    ips.extend(dns_query(host, "AAAA"))
    return ips

def get_cname(host: str) -> Optional[str]:
    values = dns_query(host, "CNAME")
    return values[0] if values else None

def run_command(cmd: List[str], timeout: int = 90) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return (proc.stdout or "").strip()
    except Exception:
        return ""

# =========================================================
# ENUMERACIÓN
# =========================================================
def enumerate_crtsh(domain: str, session: requests.Session) -> Set[str]:
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = session.get(url, timeout=20)
        r.raise_for_status()
        data = r.json()
        for item in data:
            for entry in str(item.get("name_value", "")).splitlines():
                entry = clean_domain(entry.replace("*.", ""))
                if entry.endswith(domain):
                    found.add(entry)
    except Exception:
        pass
    return found

def enumerate_amass(domain: str) -> Set[str]:
    found = set()
    if not command_exists("amass"):
        return found
    output = run_command(["amass", "enum", "-passive", "-d", domain], timeout=180)
    for line in output.splitlines():
        line = clean_domain(line)
        if line.endswith(domain):
            found.add(line)
    return found

def enumerate_subfinder(domain: str) -> Set[str]:
    found = set()
    if not command_exists("subfinder"):
        return found
    output = run_command(["subfinder", "-silent", "-d", domain], timeout=120)
    for line in output.splitlines():
        line = clean_domain(line)
        if line.endswith(domain):
            found.add(line)
    return found

def enumerate_assetfinder(domain: str) -> Set[str]:
    found = set()
    if not command_exists("assetfinder"):
        return found
    output = run_command(["assetfinder", "--subs-only", domain], timeout=120)
    for line in output.splitlines():
        line = clean_domain(line)
        if line.endswith(domain):
            found.add(line)
    return found

def enumerate_all_subdomains(domain: str, session: requests.Session) -> List[str]:
    found = {domain}
    found.update(enumerate_crtsh(domain, session))
    found.update(enumerate_amass(domain))
    found.update(enumerate_subfinder(domain))
    found.update(enumerate_assetfinder(domain))
    return sorted(found)

# =========================================================
# HTTP / TLS
# =========================================================
def head_or_get(url: str, session: requests.Session) -> Tuple[Optional[requests.Response], str]:
    try:
        r = session.head(url, timeout=TIMEOUT_HTTP, allow_redirects=True, verify=True)
        if r.status_code >= 400 or not r.headers:
            r = session.get(url, timeout=TIMEOUT_HTTP, allow_redirects=True, verify=True)
        return r, ""
    except requests.exceptions.RequestException as e:
        return None, str(e)

def try_http_https(host: str, session: requests.Session) -> Dict[str, Any]:
    result = {
        "reachable": False,
        "scheme": None,
        "url": None,
        "status_code": None,
        "headers": {},
        "body_snippet": "",
        "error": "",
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        resp, err = head_or_get(url, session)
        if resp is not None:
            body = ""
            try:
                body = resp.text[:1200]
            except Exception:
                pass
            result.update({
                "reachable": True,
                "scheme": scheme,
                "url": resp.url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": body,
                "error": "",
            })
            return result
        result["error"] = err
    return result

def extract_tls_cert(host: str, port: int = 443) -> Dict[str, Any]:
    data = {
        "success": False,
        "issuer": "No disponible",
        "subject": "No disponible",
        "san": [],
        "valid_from": "No disponible",
        "valid_to": "No disponible",
        "observation": "No fue posible recuperar el certificado.",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = []
                subject = []
                for item in cert.get("issuer", []):
                    issuer.extend(item)
                for item in cert.get("subject", []):
                    subject.extend(item)

                data["success"] = True
                data["issuer"] = ", ".join(f"{k}={v}" for k, v in issuer) or "No disponible"
                data["subject"] = ", ".join(f"{k}={v}" for k, v in subject) or "No disponible"
                data["san"] = [x[1] for x in cert.get("subjectAltName", []) if len(x) > 1]
                data["valid_from"] = cert.get("notBefore", "No disponible")
                data["valid_to"] = cert.get("notAfter", "No disponible")
                data["observation"] = "Certificado recuperado correctamente."
    except Exception as e:
        data["observation"] = f"No fue posible recuperar el certificado: {e}"
    return data

# =========================================================
# CORREO
# =========================================================
def evaluate_spf(domain: str) -> Dict[str, str]:
    txts = dns_query(domain, "TXT")
    spf_records = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf_records:
        return {
            "consulta": f"TXT {domain}",
            "resultado": "No se observó registro SPF",
            "evaluacion": "No se identifica política SPF publicada.",
            "recomendacion": "Publicar un registro SPF alineado con la infraestructura institucional.",
        }
    spf = spf_records[0]
    if "~all" in spf:
        eval_txt = "Registro SPF presente con política SoftFail (~all)."
        rec = "Evaluar endurecimiento gradual hacia -all si la operación lo permite."
    elif "-all" in spf:
        eval_txt = "Registro SPF presente con política restrictiva (-all)."
        rec = "Mantener monitoreo y actualización de orígenes autorizados."
    else:
        eval_txt = "Registro SPF presente."
        rec = "Verificar alineación con la infraestructura real de correo."
    return {
        "consulta": f"TXT {domain}",
        "resultado": spf,
        "evaluacion": eval_txt,
        "recomendacion": rec,
    }

def evaluate_dmarc(domain: str) -> Dict[str, str]:
    name = f"_dmarc.{domain}"
    txts = dns_query(name, "TXT")
    dmarc_records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {
            "consulta": f"TXT {name}",
            "resultado": "No se observó registro DMARC",
            "evaluacion": "No se identifica política DMARC publicada.",
            "recomendacion": "Publicar un registro DMARC con fase inicial de monitoreo controlado.",
        }
    dmarc = dmarc_records[0]
    m = re.search(r"\bp=([a-z]+)", dmarc, re.I)
    policy = m.group(1).lower() if m else "desconocida"
    if policy == "none":
        eval_txt = "Política DMARC en modo monitoreo (p=none)."
        rec = "Evaluar transición a quarantine o reject."
    elif policy in ("quarantine", "reject"):
        eval_txt = f"Política DMARC con enforcement ({policy})."
        rec = "Mantener monitoreo de alineación SPF/DKIM."
    else:
        eval_txt = "Registro DMARC presente."
        rec = "Validar consistencia de la política publicada."
    return {
        "consulta": f"TXT {name}",
        "resultado": dmarc,
        "evaluacion": eval_txt,
        "recomendacion": rec,
    }

def evaluate_dkim(domain: str) -> Dict[str, str]:
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        txts = dns_query(name, "TXT")
        matches = [t for t in txts if "DKIM" in t.upper()]
        if matches:
            found.append((selector, matches[0]))
    if not found:
        return {
            "selector": "No identificado",
            "consulta": f"TXT <selector>._domainkey.{domain}",
            "resultado": "No se identificó DKIM con selectores comunes",
            "evaluacion": "La ausencia con selectores comunes no confirma ausencia total de DKIM.",
            "recomendacion": "Validar selectores DKIM reales de la plataforma de correo.",
        }
    selector, record = found[0]
    return {
        "selector": selector,
        "consulta": f"TXT {selector}._domainkey.{domain}",
        "resultado": record,
        "evaluacion": "Se observó un registro DKIM con selector común.",
        "recomendacion": "Verificar vigencia y alineación del selector identificado.",
    }

# =========================================================
# FINGERPRINT / CVE
# =========================================================
def safe_lower(value: Optional[str]) -> str:
    return (value or "").strip().lower()

def extract_version(text: str) -> str:
    if not text:
        return ""
    patterns = [
        r"/(\d+(?:\.\d+){1,3})",
        r"\((\d+(?:\.\d+){1,3})",
        r"\b(\d+(?:\.\d+){1,3})\b",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return ""

def normalize_banner_to_fingerprint(banner: str) -> Optional[Dict[str, str]]:
    b = safe_lower(banner)
    if not b:
        return None

    version = extract_version(banner)

    if "apache" in b and "tomcat" not in b:
        return {
            "producto_clave": "apache_http_server",
            "producto": "Apache HTTP Server",
            "version": version,
            "fuente": banner,
        }
    if "nginx" in b:
        return {
            "producto_clave": "nginx",
            "producto": "nginx",
            "version": version,
            "fuente": banner,
        }
    if "microsoft-iis" in b or "iis" in b:
        return {
            "producto_clave": "microsoft_iis",
            "producto": "Microsoft IIS",
            "version": version,
            "fuente": banner,
        }
    if "php" in b:
        return {
            "producto_clave": "php",
            "producto": "PHP",
            "version": version,
            "fuente": banner,
        }
    if "openresty" in b:
        return {
            "producto_clave": "openresty",
            "producto": "OpenResty",
            "version": version,
            "fuente": banner,
        }
    if "jetty" in b:
        return {
            "producto_clave": "jetty",
            "producto": "Jetty",
            "version": version,
            "fuente": banner,
        }
    if "tomcat" in b:
        return {
            "producto_clave": "tomcat",
            "producto": "Apache Tomcat",
            "version": version,
            "fuente": banner,
        }
    return None

def extract_technology_fingerprints(http_info: Dict[str, Any]) -> List[Dict[str, str]]:
    fingerprints: List[Dict[str, str]] = []
    headers = http_info.get("headers", {}) or {}
    body = http_info.get("body_snippet", "") or ""

    candidates = []
    server = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")

    if server:
        candidates.append(server)
    if x_powered:
        candidates.append(x_powered)

    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        body,
        re.I
    )
    if m:
        candidates.append(m.group(1))

    for c in candidates:
        fp = normalize_banner_to_fingerprint(c)
        if fp and fp.get("version"):
            fingerprints.append(fp)

    seen = set()
    result = []
    for fp in fingerprints:
        key = (fp["producto_clave"], fp["version"], fp["fuente"])
        if key not in seen:
            seen.add(key)
            result.append(fp)
    return result

def parse_nvd_cvss(cve_obj: Dict[str, Any]) -> Tuple[str, str]:
    metrics = cve_obj.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key, [])
        if items:
            metric = items[0]
            cvss_data = metric.get("cvssData", {}) or {}
            score = str(cvss_data.get("baseScore", "N/A"))
            severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "N/A"
            return score, severity
    return "N/A", "N/A"

def parse_nvd_description(cve_obj: Dict[str, Any]) -> str:
    descs = cve_obj.get("descriptions", []) or []
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")[:900]
    return ""

def infer_attack_vector_text(description: str, severity: str) -> str:
    d = safe_lower(description)

    if "remote code execution" in d or "arbitrary code execution" in d:
        return "Interacción remota con el servicio vulnerable que podría derivar en ejecución de código, sujeto a versión y configuración."
    if "sql injection" in d:
        return "Interacción remota con entradas de la aplicación que podría permitir manipulación de consultas, sujeto a validación interna."
    if "cross-site scripting" in d or "xss" in d:
        return "Interacción con contenido web procesado por la aplicación que podría facilitar ejecución de scripts en navegador."
    if "directory traversal" in d or "path traversal" in d:
        return "Solicitudes especialmente construidas hacia rutas procesadas por el servicio podrían exponer archivos no previstos."
    if "denial of service" in d:
        return "Interacción remota con el servicio que podría afectar disponibilidad bajo condiciones vulnerables."
    if "authentication bypass" in d:
        return "Interacción remota con mecanismos de autenticación que podría debilitar controles de acceso."
    if severity.upper() in ("CRITICAL", "HIGH"):
        return "Ataque remoto potencial contra el componente expuesto, sujeto a confirmación de versión, configuración y superficie alcanzable."
    return "Exposición potencial dependiente de la versión exacta, configuración efectiva y condiciones del despliegue."

def infer_mitigation_text(producto: str, version: str, severity: str) -> str:
    sev = severity.upper()
    base = f"Validar internamente si {producto} versión {version} corresponde al componente realmente desplegado y contrastar con boletines del fabricante."
    if sev in ("CRITICAL", "HIGH"):
        return base + " Priorizar actualización, endurecimiento de configuración, segmentación y controles compensatorios temporales."
    return base + " Revisar actualización, hardening y exposición del servicio."

def query_nvd_cves(keyword: str, session: requests.Session, max_results: int = MAX_CVES_PER_FINGERPRINT) -> List[Dict[str, Any]]:
    params = {
        "keywordSearch": keyword,
        "keywordExactMatch": "",
        "noRejected": "",
        "resultsPerPage": max_results,
    }
    try:
        resp = session.get(NVD_CVE_API, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", []) or []
    except Exception:
        return []

def build_cve_entries_for_fingerprint(
    subdomain: str,
    ip_text: str,
    fingerprint: Dict[str, str],
    session: requests.Session,
) -> List[Dict[str, str]]:
    producto = fingerprint["producto"]
    version = fingerprint["version"]
    fuente = fingerprint["fuente"]

    if not version:
        return []

    keyword = f"{producto} {version}"
    vulns = query_nvd_cves(keyword, session=session, max_results=MAX_CVES_PER_FINGERPRINT)

    results = []
    seen = set()

    for item in vulns:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id", "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)

        desc = parse_nvd_description(cve)
        cvss, severity = parse_nvd_cvss(cve)
        kev = "Sí" if cve.get("cisaExploitAdd") else "No"
        confianza = "Alta" if version else "Baja"

        results.append({
            "activo": subdomain,
            "tecnologia": producto,
            "version": version,
            "cve_id": cve_id,
            "severidad": severity,
            "cvss": cvss,
            "descripcion": desc or "Descripción no disponible en la respuesta analizada.",
            "significado": (
                f"La tecnología observada expone una versión visible ({version}) potencialmente compatible con "
                f"el registro {cve_id}. Se requiere validación interna de versión efectiva, módulos habilitados y configuración."
            ),
            "vector_ataque": infer_attack_vector_text(desc, severity),
            "impacto": (
                "El impacto depende de la versión exacta, configuración, controles compensatorios "
                "y exposición real del componente en producción."
            ),
            "evidencia": f"Fingerprint observado: {fuente}",
            "confianza": confianza,
            "recomendacion": infer_mitigation_text(producto, version, severity),
            "fuente": "NVD API 2.0",
            "kev": kev,
            "ip": ip_text,
        })

    return results

# =========================================================
# CLASIFICACIÓN / EVIDENCIA
# =========================================================
def detect_provider_from_cname(cname: Optional[str]) -> Tuple[str, str]:
    if not cname:
        return "No identificado", "No identificado"
    cname_l = cname.lower()
    for suffix, meta in CLOUD_FINGERPRINTS.items():
        if suffix in cname_l:
            return meta["provider"], suffix
    return "No identificado", "No identificado"

def classify_headers(headers: Dict[str, str]) -> Tuple[str, str]:
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if not missing:
        return (
            "Cabeceras de seguridad presentes en la muestra evaluada.",
            "Hardening adecuado"
        )
    return (
        f"Cabeceras ausentes o no observadas: {', '.join(missing)}",
        "Hallazgo de hardening"
    )

def detect_orphan(subdomain: str, cname: Optional[str], http_info: Dict[str, Any]) -> Optional[Dict[str, str]]:
    provider_name, provider_suffix = detect_provider_from_cname(cname)
    if provider_name == "No identificado":
        return None

    status = str(http_info.get("status_code") or "Sin respuesta")
    body = (http_info.get("body_snippet") or "")[:1000]
    matched = False

    for pat in CLOUD_FINGERPRINTS.get(provider_suffix, {}).get("patterns", []):
        if pat.lower() in body.lower():
            matched = True
            break

    possible = False
    if status in ("404", "410", "400", "403", "Sin respuesta"):
        possible = True
    if matched:
        possible = True

    if not possible:
        return None

    return {
        "subdominio": subdomain,
        "resolucion_dns": cname or "No disponible",
        "proveedor": provider_name,
        "estado_http": status,
        "observacion": "El subdominio continúa delegado a infraestructura externa sin evidencia clara de servicio institucional activo.",
        "riesgo": "Posible subdomain takeover / gestión de activos",
        "recomendacion": "Validar propiedad del recurso o retirar el registro DNS si no es requerido.",
        "fecha": now_str(),
    }

def build_inventory_entry(
    subdomain: str,
    ips: List[str],
    cname: Optional[str],
    http_info: Dict[str, Any],
    orphan: Optional[Dict[str, str]],
) -> Dict[str, str]:
    provider_name, _ = detect_provider_from_cname(cname)
    server = (http_info.get("headers") or {}).get("Server", "No identificado")

    if orphan:
        hallazgo = "Subdominio huérfano o con indicios de reutilización del recurso."
        tecnologia = provider_name if provider_name != "No identificado" else server
    elif http_info.get("reachable"):
        hallazgo = "Activo con respuesta observable."
        tecnologia = server
    else:
        hallazgo = "Registro observado sin respuesta HTTP en la validación."
        tecnologia = provider_name if provider_name != "No identificado" else "No identificado"

    criticidad = "Alta" if http_info.get("reachable") and ips else "Media" if ips else "Baja"

    return {
        "subdominio": subdomain,
        "ip": ", ".join(ips) if ips else "No resuelve",
        "estado": "Activo" if http_info.get("reachable") else "Sin respuesta HTTP",
        "puerto": "443/80",
        "tecnologia": tecnologia,
        "criticidad": criticidad,
        "hallazgo": hallazgo,
    }

def build_header_entry(subdomain: str, http_info: Dict[str, Any]) -> Dict[str, str]:
    headers = http_info.get("headers", {}) or {}
    obs, clasif = classify_headers(headers)
    return {
        "activo": subdomain,
        "url": http_info.get("url") or f"https://{subdomain}",
        "hsts": headers.get("Strict-Transport-Security", "No presente"),
        "csp": headers.get("Content-Security-Policy", "No presente"),
        "xframe": headers.get("X-Frame-Options", "No presente"),
        "xcontent": headers.get("X-Content-Type-Options", "No presente"),
        "referrer": headers.get("Referrer-Policy", "No presente"),
        "observacion": obs,
        "clasificacion": clasif,
        "recomendacion": "Evaluar incorporación de cabeceras según compatibilidad de la aplicación.",
        "fecha": now_str(),
    }

def build_ssl_entry(subdomain: str, cert: Dict[str, Any]) -> Dict[str, str]:
    return {
        "activo": subdomain,
        "host": subdomain,
        "emisor": cert.get("issuer", "No disponible"),
        "valido_desde": cert.get("valid_from", "No disponible"),
        "valido_hasta": cert.get("valid_to", "No disponible"),
        "versiones": "Validación básica de certificado. La verificación exhaustiva de protocolos/cifrados requiere módulo especializado.",
        "san": ", ".join(cert.get("san", [])) if cert.get("san") else "No disponible",
        "observacion": cert.get("observation", "No disponible"),
        "impacto": "La configuración TLS observable influye en la postura de seguridad del servicio expuesto.",
        "recomendacion": "Revisar vigencia, cobertura SAN y endurecimiento TLS.",
        "fecha": now_str(),
    }

def evidence_entry(
    tipo: str,
    activo: str,
    subdominio: str,
    ip: str,
    severidad: str,
    descripcion: str,
    metodo: str,
    consulta: str,
    resultado: str,
    interpretacion: str,
    impacto: str,
    recomendacion: str,
) -> Dict[str, str]:
    return {
        "tipo": tipo,
        "activo": activo,
        "subdominio": subdominio,
        "ip": ip,
        "severidad": severidad,
        "descripcion": descripcion,
        "metodo": metodo,
        "consulta": consulta,
        "resultado": resultado,
        "interpretacion": interpretacion,
        "impacto": impacto,
        "recomendacion": recomendacion,
        "fecha": now_str(),
    }

# =========================================================
# ANÁLISIS
# =========================================================
def analyze_domain(domain: str, session: requests.Session) -> Dict[str, Any]:
    print(f"[+] Analizando: {domain}")
    subdomains = enumerate_all_subdomains(domain, session)
    print(f"    [-] Subdominios encontrados: {len(subdomains)}")

    inventario = []
    huerfanos = []
    headers_seguridad = []
    ssl_tls = []
    evidencias = []
    tecnologias = set()
    cves_detectadas = []

    activos_http = 0
    activos_criticos = 0

    for sub in subdomains:
        ips = resolve_ips(sub)
        cname = get_cname(sub)
        http_info = try_http_https(sub, session)
        orphan = detect_orphan(sub, cname, http_info)

        inventario_item = build_inventory_entry(sub, ips, cname, http_info, orphan)
        inventario.append(inventario_item)

        if http_info.get("reachable"):
            activos_http += 1
            if inventario_item["criticidad"] == "Alta":
                activos_criticos += 1

            headers_item = build_header_entry(sub, http_info)
            headers_seguridad.append(headers_item)

            evidencias.append(evidence_entry(
                tipo="Cabeceras HTTP",
                activo=sub,
                subdominio=sub,
                ip=", ".join(ips) if ips else "N/A",
                severidad=headers_item["clasificacion"],
                descripcion="Revisión de cabeceras HTTP/HTTPS observables públicamente.",
                metodo="Solicitud HTTP/HTTPS no intrusiva",
                consulta=http_info.get("url") or f"https://{sub}",
                resultado=json.dumps(http_info.get("headers", {}), ensure_ascii=False)[:1500],
                interpretacion=headers_item["observacion"],
                impacto="La ausencia de hardening HTTP puede incrementar exposición a riesgos de seguridad web.",
                recomendacion=headers_item["recomendacion"],
            ))

            server = (http_info.get("headers") or {}).get("Server")
            if server:
                tecnologias.add(server)

            fingerprints = extract_technology_fingerprints(http_info)
            for fp in fingerprints:
                cve_items = build_cve_entries_for_fingerprint(
                    subdomain=sub,
                    ip_text=", ".join(ips) if ips else "N/A",
                    fingerprint=fp,
                    session=session,
                )

                for cve_item in cve_items:
                    cves_detectadas.append(cve_item)

                    evidencias.append(evidence_entry(
                        tipo="CVE potencialmente aplicable",
                        activo=sub,
                        subdominio=sub,
                        ip=", ".join(ips) if ips else "N/A",
                        severidad=cve_item["severidad"],
                        descripcion=(
                            f"Correlación entre fingerprint tecnológico visible y el registro "
                            f"{cve_item['cve_id']} publicado en NVD."
                        ),
                        metodo="Fingerprint pasivo + consulta NVD",
                        consulta=f"{cve_item['tecnologia']} {cve_item['version']}",
                        resultado=(
                            f"{cve_item['cve_id']} | CVSS={cve_item['cvss']} | "
                            f"KEV={cve_item['kev']} | Evidencia={cve_item['evidencia']}"
                        ),
                        interpretacion=cve_item["significado"],
                        impacto=cve_item["impacto"],
                        recomendacion=cve_item["recomendacion"],
                    ))

        cert = extract_tls_cert(sub)
        if cert.get("success"):
            ssl_item = build_ssl_entry(sub, cert)
            ssl_tls.append(ssl_item)
            evidencias.append(evidence_entry(
                tipo="SSL/TLS",
                activo=sub,
                subdominio=sub,
                ip=", ".join(ips) if ips else "N/A",
                severidad="Riesgo de configuración",
                descripcion="Validación del certificado digital expuesto por el servicio.",
                metodo="Negociación TLS básica",
                consulta=f"TLS handshake contra {sub}:443",
                resultado=(
                    f"Emisor: {ssl_item['emisor']} | "
                    f"Desde: {ssl_item['valido_desde']} | "
                    f"Hasta: {ssl_item['valido_hasta']} | "
                    f"SAN: {ssl_item['san']}"
                ),
                interpretacion=ssl_item["observacion"],
                impacto=ssl_item["impacto"],
                recomendacion=ssl_item["recomendacion"],
            ))

        if orphan:
            huerfanos.append(orphan)
            evidencias.append(evidence_entry(
                tipo="Subdominio huérfano",
                activo=sub,
                subdominio=sub,
                ip=", ".join(ips) if ips else "N/A",
                severidad="Riesgo de configuración",
                descripcion="Registro DNS delegado a infraestructura externa sin evidencia clara de servicio institucional activo.",
                metodo="Resolución DNS + validación HTTP/HTTPS",
                consulta=f"CNAME/A/AAAA + validación web sobre {sub}",
                resultado=f"CNAME={cname or 'N/A'} | HTTP={http_info.get('status_code') or 'Sin respuesta'}",
                interpretacion=orphan["observacion"],
                impacto="Puede facilitar shadow IT, desalineación de inventario o reutilización indebida del recurso.",
                recomendacion=orphan["recomendacion"],
            ))

    spf = evaluate_spf(domain)
    dmarc = evaluate_dmarc(domain)
    dkim = evaluate_dkim(domain)

    evidencias.append(evidence_entry(
        tipo="SPF",
        activo="Correo institucional",
        subdominio=domain,
        ip="N/A",
        severidad="Observación técnica",
        descripcion="Validación del registro SPF del dominio institucional.",
        metodo="Consulta DNS TXT",
        consulta=spf["consulta"],
        resultado=spf["resultado"],
        interpretacion=spf["evaluacion"],
        impacto="La política SPF contribuye a reducir suplantación del dominio en correo.",
        recomendacion=spf["recomendacion"],
    ))

    evidencias.append(evidence_entry(
        tipo="DMARC",
        activo="Correo institucional",
        subdominio=domain,
        ip="N/A",
        severidad="Observación técnica",
        descripcion="Validación del registro DMARC del dominio institucional.",
        metodo="Consulta DNS TXT",
        consulta=dmarc["consulta"],
        resultado=dmarc["resultado"],
        interpretacion=dmarc["evaluacion"],
        impacto="DMARC fortalece controles frente a spoofing y alineación de autenticación.",
        recomendacion=dmarc["recomendacion"],
    ))

    evidencias.append(evidence_entry(
        tipo="DKIM",
        activo="Correo institucional",
        subdominio=domain,
        ip="N/A",
        severidad="Observación técnica",
        descripcion="Búsqueda de DKIM mediante selectores comunes.",
        metodo="Consulta DNS TXT",
        consulta=dkim["consulta"],
        resultado=dkim["resultado"],
        interpretacion=dkim["evaluacion"],
        impacto="DKIM apoya integridad y autenticidad de mensajes firmados.",
        recomendacion=dkim["recomendacion"],
    ))

    return {
        "domain": domain,
        "inventario": inventario,
        "huerfanos": huerfanos,
        "headers_seguridad": headers_seguridad,
        "ssl_tls": ssl_tls,
        "evidencias": evidencias,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "tecnologias_detectadas": sorted(tecnologias),
        "cves_detectadas": cves_detectadas,
        "metricas": {
            "total_activos": len(subdomains),
            "hosts_activos": activos_http,
            "total_subdominios": len(subdomains),
            "subdominios_huerfanos": len(huerfanos),
            "vulnerabilidades_criticas": 0,
            "vulnerabilidades_altas": len([x for x in inventario if x["criticidad"] == "Alta"]),
            "vulnerabilidades_medias": len([x for x in inventario if x["criticidad"] == "Media"]),
            "vulnerabilidades_bajas": len([x for x in inventario if x["criticidad"] == "Baja"]),
            "activos_criticos": activos_criticos,
            "total_cves_detectadas": len(cves_detectadas),
            "cves_criticas": len([x for x in cves_detectadas if str(x.get("severidad", "")).upper() == "CRITICAL"]),
            "cves_altas": len([x for x in cves_detectadas if str(x.get("severidad", "")).upper() == "HIGH"]),
            "cves_medias": len([x for x in cves_detectadas if str(x.get("severidad", "")).upper() == "MEDIUM"]),
            "cves_bajas": len([x for x in cves_detectadas if str(x.get("severidad", "")).upper() == "LOW"]),
        },
    }

# =========================================================
# CONTEXTO WORD
# =========================================================
def build_context(result: Dict[str, Any]) -> Dict[str, Any]:
    all_inventario = []
    all_huerfanos = []
    all_headers = []
    all_ssl = []
    all_evidencias = []
    all_cves = []
    all_tech = set()

    total_activos = 0
    hosts_activos = 0
    total_subdominios = 0
    subdominios_huerfanos = 0
    vulns_crit = 0
    vulns_alt = 0
    vulns_med = 0
    vulns_baj = 0
    activos_crit = 0

    total_cves_detectadas = 0
    cves_criticas = 0
    cves_altas = 0
    cves_medias = 0
    cves_bajas = 0

    domains = []

    domains.append(result["domain"])
    all_inventario.extend(result["inventario"])
    all_huerfanos.extend(result["huerfanos"])
    all_headers.extend(result["headers_seguridad"])
    all_ssl.extend(result["ssl_tls"])
    all_evidencias.extend(result["evidencias"])
    all_cves.extend(result.get("cves_detectadas", []))
    all_tech.update(result["tecnologias_detectadas"])

    m = result["metricas"]
    total_activos += m["total_activos"]
    hosts_activos += m["hosts_activos"]
    total_subdominios += m["total_subdominios"]
    subdominios_huerfanos += m["subdominios_huerfanos"]
    vulns_crit += m["vulnerabilidades_criticas"]
    vulns_alt += m["vulnerabilidades_altas"]
    vulns_med += m["vulnerabilidades_medias"]
    vulns_baj += m["vulnerabilidades_bajas"]
    activos_crit += m["activos_criticos"]

    total_cves_detectadas += m.get("total_cves_detectadas", 0)
    cves_criticas += m.get("cves_criticas", 0)
    cves_altas += m.get("cves_altas", 0)
    cves_medias += m.get("cves_medias", 0)
    cves_bajas += m.get("cves_bajas", 0)

    return {
        "titulo_informe": "INFORME TÉCNICO DE EXPOSICIÓN EXTERNA Y GESTIÓN DE VULNERABILIDADES OSINT",
        "cliente": "Entidad evaluada",
        "dominio_principal": ", ".join(domains),
        "fecha": datetime.now().strftime("%Y-%m-%d"),
        "analista": "Equipo técnico",
        "version": "1.0",
        "clasificacion": "Uso oficial",

        "objetivo": "Identificar activos expuestos públicamente, configuraciones observables y brechas de seguridad asociadas a la superficie externa del dominio autorizado.",
        "alcance": "Revisión no intrusiva de dominios y subdominios públicos derivados del dominio en alcance. El análisis se limita a información observable públicamente.",
        "metodologia": "Enumeración pasiva de subdominios, validación DNS, revisión HTTP/HTTPS, inspección de cabeceras, validación de certificados, fingerprinting tecnológico y correlación de CVE potencialmente aplicables.",
        "fuentes_osint": "crt.sh, DNS público, respuestas HTTP/HTTPS, metadatos de certificados y NVD API 2.0.",

        "resumen_ejecutivo": (
            f"Se realizó una revisión OSINT defensiva sobre {len(domains)} dominio(s) autorizado(s), "
            f"identificando {total_subdominios} activos observados y {hosts_activos} con respuesta HTTP/HTTPS. "
            f"Se observaron {subdominios_huerfanos} posibles subdominios huérfanos, además de oportunidades de mejora "
            f"en hardening HTTP, certificados digitales y autenticación de correo. "
            f"Adicionalmente, se correlacionaron {total_cves_detectadas} CVE potencialmente aplicables "
            f"con base en fingerprints tecnológicos visibles públicamente."
        ),

        "total_activos": total_activos,
        "hosts_activos": hosts_activos,
        "total_subdominios": total_subdominios,
        "subdominios_huerfanos": subdominios_huerfanos,
        "vulnerabilidades_criticas": vulns_crit,
        "vulnerabilidades_altas": vulns_alt,
        "vulnerabilidades_medias": vulns_med,
        "vulnerabilidades_bajas": vulns_baj,
        "activos_criticos": activos_crit,

        "total_cves_detectadas": total_cves_detectadas,
        "cves_criticas": cves_criticas,
        "cves_altas": cves_altas,
        "cves_medias": cves_medias,
        "cves_bajas": cves_bajas,

        "activos": all_inventario,
        "subdominios_huerfanos_lista": [x["subdominio"] for x in all_huerfanos],
        "subdominios_huerfanos_detalle": all_huerfanos,
        "huerfanos": all_huerfanos,

        "spf_consulta": result["spf"]["consulta"] if result else "",
        "spf_resultado": result["spf"]["resultado"] if result else "",
        "spf_evaluacion": result["spf"]["evaluacion"] if result else "",
        "spf_recomendacion": result["spf"]["recomendacion"] if result else "",

        "dkim_selector": result["dkim"]["selector"] if result else "",
        "dkim_consulta": result["dkim"]["consulta"] if result else "",
        "dkim_resultado": result["dkim"]["resultado"] if result else "",
        "dkim_evaluacion": result["dkim"]["evaluacion"] if result else "",
        "dkim_recomendacion": result["dkim"]["recomendacion"] if result else "",

        "dmarc_consulta": result["dmarc"]["consulta"] if result else "",
        "dmarc_resultado": result["dmarc"]["resultado"] if result else "",
        "dmarc_evaluacion": result["dmarc"]["evaluacion"] if result else "",
        "dmarc_recomendacion": result["dmarc"]["recomendacion"] if result else "",

        "tls_estado": "Validación básica completada",
        "tls_versiones": "La verificación exhaustiva de protocolos y cifrados requiere validación especializada adicional.",
        "tls_observaciones": "Se consolidan certificados recuperados en la sección de detalle.",
        "tls_recomendaciones": "Revisar vigencia, cobertura SAN y endurecimiento criptográfico.",

        "headers_seguridad": all_headers,
        "ssl_tls": all_ssl,
        "tecnologias_detectadas": sorted(all_tech),
        "cves_detectadas": all_cves,

        "metodologia_validacion": (
            "Las verificaciones fueron realizadas mediante técnicas de análisis pasivo y consultas sobre "
            "información públicamente observable. La validación incluyó revisión de DNS, autenticación de correo, "
            "cabeceras HTTP, certificados digitales, resolución de subdominios y correlación de fingerprints "
            "tecnológicos con CVE potencialmente aplicables."
        ),
        "criterio_clasificacion": (
            "Los hallazgos se clasifican como Vulnerabilidad, Riesgo de configuración, Hallazgo de hardening u "
            "Observación técnica. La correlación con CVE se reporta como potencialmente aplicable, no como "
            "confirmación de explotación."
        ),
        "fecha_validacion": now_str(),
        "fuente_datos": "Consultas DNS, respuestas HTTP/HTTPS, metadatos de certificados, enumeración pasiva y NVD API 2.0.",
        "observaciones_generales_evidencia": "Los resultados corresponden al estado observado en la fecha de validación.",
        "evidencias": all_evidencias,

        "recomendaciones_generales": (
            "Mantener inventario actualizado de activos expuestos, retirar registros DNS obsoletos, fortalecer "
            "cabeceras HTTP, revisar certificados digitales, evolucionar controles de autenticación de correo "
            "y validar internamente versiones de componentes correlacionados con CVE."
        ),
        "conclusion": (
            "La superficie externa evaluada evidencia oportunidades de mejora en gestión de activos, hardening web "
            "y gobierno de configuraciones públicas. La corrección priorizada de estos hallazgos reduce riesgo operativo."
        ),

        "fecha_analisis": now_str(),
        "herramientas_utilizadas": "Python, DNS público, HTTP/HTTPS, crt.sh, amass, subfinder, assetfinder, validación TLS básica y NVD API 2.0.",
        "revision": "Automatizada con revisión analítica posterior.",
    }

def render_docx(template_path: Path, output_path: Path, context: Dict[str, Any]) -> None:
    if not template_path.exists():
        raise FileNotFoundError(f"No existe la plantilla Word: {template_path}")
    doc = DocxTemplate(str(template_path))
    doc.render(context)
    doc.save(str(output_path))


def scan(scanner_db: ScannerExecution, domain: str, template: str) -> None:

    template_path = Path(template)
    if not template_path.exists():
        raise FileNotFoundError(f"No existe {template_path}")

    session = make_session()
    
    try:
        result = analyze_domain(domain, session)
    except Exception as e:
        print(f"[!] Error analizando {domain}: {e}")

    if not result:
        raise RuntimeError("No fue posible analizar ningún dominio.")

    context = build_context(result)

    filename = f"report_{clean_domain(domain).replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

    output_file = Path(f"./outputs/{filename}")

    render_docx(template_path, output_file, context)
    print(f"✅ Informe generado: {output_file.resolve()}")
    
    s3 = UploadReport()
    s3_url = s3.upload_report(output_file)
    print(f"✅ Informe subido a S3: {s3_url}")

    scanner_db.mark_done(s3_url)
