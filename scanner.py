import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScannerBot/1.0"}
        self.results = {
            "sensitive_files": [],
            "xss_vulnerabilities": [],
            "sqli_vulnerabilities": []
        }

    def scan_sensitive_files(self):
        """فحص وجود ملفات أو مسارات حساسة مكشوفة"""
        sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", 
            "/config.php", "/admin/", "/backup.zip", 
            "/.git/HEAD", "/phpinfo.php"
        ]
        
        for path in sensitive_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    self.results["sensitive_files"].append({
                        "path": path,
                        "url": full_url,
                        "status": response.status_code
                    })
            except requests.exceptions.RequestException:
                continue

    def get_forms(self, url):
        """استخراج جميع النماذج (Forms) الموجودة في الصفحة"""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def submit_form(self, form, url, value):
        """إرسال نموذج (Form) بقيمة معينة لفحص الثغرات"""
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        target_action_url = urljoin(url, action)
        
        inputs = form.find_all(["input", "textarea"])
        data = {}
        for input_tag in inputs:
            input_name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            if input_name:
                if input_type in ["text", "search", "password"]:
                    data[input_name] = value
                else:
                    data[input_name] = "test"

        try:
            if method == "post":
                return self.session.post(target_action_url, data=data, timeout=5)
            else:
                return self.session.get(target_action_url, params=data, timeout=5)
        except:
            return None

    def scan_xss(self):
        """فحص مبدئي لثغرات Cross-Site Scripting (XSS)"""
        xss_payload = "<script>alert('XSS_TEST')</script>"
        forms = self.get_forms(self.target_url)
        
        for form in forms:
            response = self.submit_form(form, self.target_url, xss_payload)
            if response and xss_payload in response.text:
                self.results["xss_vulnerabilities"].append({
                    "url": self.target_url,
                    "details": "تم العثور على انعكاس لبيانات مدخلة غير معقمة (Reflected XSS)"
                })
                break

    def scan_sqli(self):
        """فحص مبدئي لثغرات SQL Injection عبر رسائل الخطأ الشائعة"""
        sqli_payload = "'"
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "pg_query():"
        ]
        
        forms = self.get_forms(self.target_url)
        for form in forms:
            response = self.submit_form(form, self.target_url, sqli_payload)
            if response:
                response_lower = response.text.lower()
                for error in sql_errors:
                    if error in response_lower:
                        self.results["sqli_vulnerabilities"].append({
                            "url": self.target_url,
                            "details": f"خطأ قاعدة بيانات محتمل يظهر عند إدخال علامة اقتباس: {error}"
                        })
                        break

    def run_scanner(self):
        """تشغيل جميع عمليات الفحص"""
        self.scan_sensitive_files()
        self.scan_xss()
        self.scan_sqli()
        return self.results