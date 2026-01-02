from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Literal, Optional, Tuple
import os
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

import requests

print("LOADED app.py VERSION=2026-01-02+checks")

app = FastAPI()

# --- Config ---
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

# Домены, которым разрешено проходить проверку (поддомены тоже разрешены)
WHITELISTED_DOMAINS = {
    "urlchecker-n49c.onrender.com",
    # добавляйте сюда нужные домены:
    # "python.org",
    # "sdamgia.ru",
    # "www.virustotal.com",
}

SUSPICIOUS_SUBSTRINGS = [
    "..", "<", ">", "{", "}", "|", "^", "`", '"', "'", "\u200b", "\u200c", "\u200d"
]

SUSPICIOUS_WORDS = [
    "oplata", "login", "update", "payment", "pay", "bill", "account", "auth"
]

URL_PATTERNS = re.compile(r"https?://|ftp://", re.IGNORECASE)


class URLCheckRequest(BaseModel):
    url: str


@app.get("/", response_class=HTMLResponse)
def root():
    with open("index.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)


@app.get("/health")
def health():
    return {"status": "ok"}


def is_domain_allowed(domain: str) -> bool:
    d = (domain or "").lower().strip()

    # domain может прийти как hostname или как netloc с портом
    # urlparse().netloc может быть "example.com:443"
    if ":" in d:
        d = d.split(":", 1)[0]

    for allowed in WHITELISTED_DOMAINS:
        a = allowed.lower().strip()
        if d == a or d.endswith("." + a):
            return True
    return False


def contains_nested_url(params: dict) -> bool:
    for values in params.values():
        for v in values:
            decoded = unquote(v)
            if URL_PATTERNS.search(decoded):
                return True
    return False


def is_url_safe(url: str) -> Tuple[bool, str, int]:
    issues = []
    violations = 0
    try:
        parsed = urlparse(url)

        # 1) Протокол
        if not parsed.scheme:
            issues.append("Отсутствует протокол (http/https)")
            violations += 1
            return False, "; ".join(issues), violations

        # 2) Домен
        if not parsed.netloc:
            issues.append("Отсутствует домен")
            violations += 1
            return False, "; ".join(issues), violations

        if not is_domain_allowed(parsed.netloc):
            issues.append(f"Домен {parsed.netloc} не в белом списке")
            violations += 1

        # 3) Двойные слеши в пути
        if "//" in parsed.path:
            issues.append("Обнаружены двойные слеши в пути")
            violations += 1

        # 4) Подозрительные символы
        if any(s in url for s in SUSPICIOUS_SUBSTRINGS):
            issues.append("Обнаружены подозрительные символы")
            violations += 1

        # 5) Вложенные URL в параметрах
        if parsed.query:
            params = parse_qs(parsed.query)
            if contains_nested_url(params):
                issues.append("Обнаружены вложенные URL в параметрах")
                violations += 1

        if issues:
            return False, "; ".join(issues), violations
        return True, "OK", 0

    except Exception as e:
        return False, f"Ошибка парсинга URL: {e}", 1


def check_suspicious_words(url: str) -> Tuple[bool, str, int]:
    violations = 0
    try:
        # Протокол
        if url.startswith("http://"):
            violations += 1
            return False, "Используется небезопасный протокол HTTP", violations
        if not url.startswith("https://"):
            violations += 1
            return False, "Неизвестный или отсутствующий протокол", violations

        url_lower = url.lower()
        suspicious_found = [w for w in SUSPICIOUS_WORDS if w in url_lower]

        if suspicious_found:
            violations += len(suspicious_found)
            return (
                False,
                f"Обнаружены подозрительные слова: {', '.join(suspicious_found)}",
                violations,
            )

        return True, "OK", 0

    except Exception as e:
        return False, f"Ошибка проверки: {e}", 1


def check_virustotal(url: str) -> Tuple[Optional[bool], str, int]:
    """
    Возвращает:
      - True/False если удалось получить результат
      - None если VT недоступен/ключ не задан
    violations_count:
      - 0 если чисто или VT недоступен
      - >0 если есть детекты/ошибка VT
    """
    if not VT_API_KEY:
        return None, "VirusTotal API ключ не настроен (VT_API_KEY)", 0

    scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    report_url = "https://www.virustotal.com/vtapi/v2/url/report"

    try:
        params = {"apikey": VT_API_KEY, "url": url}
        r = requests.post(scan_url, data=params, timeout=15)
        if r.status_code != 200:
            return None, f"Ошибка VirusTotal API (scan): {r.status_code}", 1

        scan_id = r.json().get("scan_id")
        if not scan_id:
            return None, "Не удалось получить scan_id", 1

        # Небольшая пауза, VT может не сразу подготовить отчёт
        time.sleep(12)

        report_params = {"apikey": VT_API_KEY, "resource": url}
        rr = requests.get(report_url, params=report_params, timeout=15)
        if rr.status_code != 200:
            return None, f"Ошибка VirusTotal API (report): {rr.status_code}", 1

        data = rr.json()
        positives = int(data.get("positives", 0) or 0)
        total = int(data.get("total", 0) or 0)
        permalink = data.get("permalink", "")

        if total <= 0:
            return None, "VirusTotal не вернул данные о сканировании", 1

        detection_rate = (positives / total) * 100.0
        details = f"Detection rate: {detection_rate:.1f}% ({positives}/{total})"
        if permalink:
            details += f", Link: {permalink}"

        if positives == 0:
            return True, f"OK - {details}", 0

        # нарушения можно считать = positives
        return False, f"Обнаружены угрозы - {details}", positives

    except Exception as e:
        return None, f"Ошибка VirusTotal: {e}", 1


def comprehensive_website_check(url: str) -> dict:
    results = []
    overall_status = "SAFE"
    overall_issues = []
    security_violations = 0

    # 1) URL safety
    is_safe, url_issues, url_violations = is_url_safe(url)
    security_violations += url_violations
    results.append(
        {
            "module": "url_safety",
            "safe": is_safe,
            "details": url_issues,
            "violations": url_violations,
        }
    )
    if not is_safe:
        overall_status = "REVIEW"
        overall_issues.append(f"URL: {url_issues}")

    # 2) Suspicious words
    word_safe, word_issues, word_violations = check_suspicious_words(url)
    security_violations += word_violations
    results.append(
        {
            "module": "suspicious_words",
            "safe": word_safe,
            "details": word_issues,
            "violations": word_violations,
        }
    )
    if not word_safe:
        overall_status = "REVIEW"
        overall_issues.append(f"Words: {word_issues}")

    # 3) VirusTotal (с весом)
    vt_safe, vt_issues, vt_violations = check_virustotal(url)
    vt_weighted = vt_violations * 20
    security_violations += vt_weighted
    results.append(
        {
            "module": "virustotal",
            "safe": vt_safe,  # True/False/None
            "details": vt_issues,
            "violations": vt_weighted,
            "raw_violations": vt_violations,
        }
    )
    if vt_safe is False:
        overall_status = "DANGEROUS"
        overall_issues.append(f"VT: {vt_issues}")

    return {
        "url": url,
        "status": overall_status,
        "issues_count": len(overall_issues),
        "issues": overall_issues,
        "security_violations_score": security_violations,
        "modules": results,
    }


@app.post("/check")
def check_url(data: URLCheckRequest):
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    # Сохраняем совместимость со старым контрактом: status ok/blocked
    report = comprehensive_website_check(url)
    status: Literal["ok", "blocked"] = "ok" if report["status"] == "SAFE" else "blocked"
    return {"status": status, "report": report}


@app.get("/check")
def check_url_get(url: str):
    url = (url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    return comprehensive_website_check(url)
