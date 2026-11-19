# 📚 مصادر ReconX

هذا الملف يوثّق **كل المصادر الخارجية** التي تعتمد عليها الأداة: واجهات API، خوادم DNS/WHOIS،
الأدوات الخارجية الاختيارية، القوائم والتوقيعات المدمجة في الكود، والمراجع التقنية.

**المبدأ الأساسي:** ReconX مكتوب بـ Python stdlib فقط. لا يوجد اعتماد إلزامي على أي مكتبة أو
أداة خارجية؛ كل ما في قسم «اختياري» يعمل بدونه البرنامج مع نتائج أقل.

- [1. واجهات API ومصادر بيانات خارجية](#1-واجهات-api-ومصادر-بيانات-خارجية)
- [2. خوادم DNS وWHOIS](#2-خوادم-dns-وwhois)
- [3. الأدوات الخارجية الاختيارية](#3-الأدوات-الخارجية-الاختيارية)
- [4. مكتبات Python الاختيارية](#4-مكتبات-python-الاختيارية)
- [5. القوائم والتوقيعات المدمجة](#5-القوائم-والتوقيعات-المدمجة)
- [6. المراجع التقنية والمعايير](#6-المراجع-التقنية-والمعايير)
- [7. جدول: كل وحدة ومصادرها](#7-جدول-كل-وحدة-ومصادرها)
- [8. حدود الاستخدام والتراخيص](#8-حدود-الاستخدام-والتراخيص)

---

## 1. واجهات API ومصادر بيانات خارجية

كلها مجانية ولا تحتاج مفتاح API (No key required).

### 1.1 تعداد النطاقات الفرعية (Passive DNS)

| المصدر | نقطة النهاية | ما يقدّمه | الوحدة |
|---|---|---|---|
| **crt.sh** | `https://crt.sh/?q=%25.<domain>&output=json` | سجلات Certificate Transparency (RFC 6962) — أسماء من الشهادات الموقّعة | `subfinder_clone.py`, `domain_osint.py` |
| **HackerTarget** | `https://api.hackertarget.com/hostsearch/?q=<domain>` | بحث مضيفين مجاني | `subfinder_clone.py` |
| **RapidDNS** | `https://rapiddns.io/subdomain/<domain>?full=1` | تجميع سجلات DNS التاريخية (صفحة HTML تُحلَّل بتعبير نمطي) | `subfinder_clone.py` |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns` | Passive DNS من مجتمع OTX | `subfinder_clone.py` |
| **urlscan.io** | `https://urlscan.io/api/v1/search/?q=domain:<domain>&size=1000` | نتائج فحوصات صفحات مسجّلة | `subfinder_clone.py` |
| **Wayback Machine (CDX)** | `https://web.archive.org/cdx/search/cdx?url=*.<domain>&output=json&fl=original&collapse=urlkey&limit=1000` | أرشيف الويب — استخراج أسماء المضيفين من الروابط المؤرشفة | `subfinder_clone.py` |
| **ThreatCrowd** | `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=<domain>` | تقارير نطاقات (الخدمة متوقفة/غير مستقرة حالياً — الفشل يُتجاهل بهدوء) | `subfinder_clone.py` |

> ملاحظة: أي مصدر يفشل يُسجَّل في `errors` ويُستكمل بالباقي. لا توقف الأداة عند تعذّر مصدر واحد.

### 1.2 تحديد موقع IP (Geolocation)

| المصدر | نقطة النهاية | ملاحظات |
|---|---|---|
| **ip-api.com** | `http://ip-api.com/json/<ip>?fields=status,country,countryCode,...` | مجاني للاستخدام غير التجاري، حد ~45 طلب/دقيقة من نفس العنوان |
| **ipwho.is** | `https://ipwho.is/<ip>` | مجاني بدون مفتاح، HTTPS |

يُجمع الناتج في `consensus` (توافق بين المصادر) بدل الاعتماد على مصدر واحد.

### 1.3 قاعدة بيانات الثغرات

| المصدر | نقطة النهاية | ملاحظات |
|---|---|---|
| **NIST NVD API 2.0** | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>` | بدون مفتاح: ~5 طلبات/30 ثانية، لذلك يستخدم الكود تأخير 6 ثوانٍ بين الطلبات + كاش محلي 30 يوماً في `~/.reconx/cve_cache/` |

تُستخدم فقط عند استدعاء `modules.vuln.cve_lookup` لتحويل معرّفات CVE إلى درجة CVSS ووصف ومراجع.

### 1.4 نقاط نهاية السحابة والتخزين (لا تحتاج مفاتيح)

| المصدر | نقطة النهاية | الوحدة |
|---|---|---|
| **AWS EC2 IMDS** | `http://169.254.169.254/latest/meta-data/` و`/iam/security-credentials/` | `advanced/cloud_metadata.py` |
| **GCP metadata** | `http://metadata.google.internal/computeMetadata/v1/instance/` و`169.254.169.254/computeMetadata/v1/` | `advanced/cloud_metadata.py` |
| **Azure IMDS** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `advanced/cloud_metadata.py` |
| **OCI metadata** | `http://169.254.169.254/opc/v2/instance/` | `advanced/cloud_metadata.py` |
| **Alibaba metadata** | `http://100.100.100.200/latest/meta-data/` | `advanced/cloud_metadata.py` |
| **DigitalOcean metadata** | `http://169.254.169.254/metadata/v1/` | `advanced/cloud_metadata.py` |
| **Kubernetes API** | `https://kubernetes.default.svc/api/v1/...` | `advanced/cloud_metadata.py` |
| **AWS S3** | `https://<bucket>.s3.amazonaws.com/?max-keys=2` | `advanced/bucket_checker.py` |
| **Azure Blob** | `https://<account>.blob.core.windows.net/?comp=list` | `advanced/bucket_checker.py` |
| **GCP Storage** | `https://storage.googleapis.com/storage/v1/b/<bucket>/o?maxResults=2` | `advanced/bucket_checker.py` |

> فحص التخزين **قراءة فقط**: لا يرفع أي ملف ولا يختبر الكتابة العامة، لأن ذلك تعديل غير مصرّح به.
> عناوين metadata تُطلب فقط عبر معامل SSRF في هدف مصرّح بفحصه.

---

## 2. خوادم DNS وWHOIS

### 2.1 DNS-over-HTTPS (DoH)

| المزوّد | نقطة النهاية |
|---|---|
| **Cloudflare** | `https://cloudflare-dns.com/dns-query` |
| **Google Public DNS** | `https://dns.google/resolve` |

الأول هو الافتراضي والثاني احتياطي؛ يُجرَّب بالترتيب لكل استعلام (A, AAAA, NS, MX, TXT, CNAME, SOA, CAA, PTR, و`_dmarc`).
هذا يغني عن الحاجة إلى `dig` أو `nslookup`.

### 2.2 WHOIS عبر المنفذ 43

استعلام WHOIS يتم عبر مقبس TCP مباشرة على المنفذ 43 (بدون أمر `whois`)، مع اختيار الخادم حسب
امتداد النطاق (TLD) — مثل `whois.verisign-grs.com` لـ `.com` و`.net` — والقائمة الكاملة في
`WHOIS_SERVERS` داخل `modules/web/domain_osint.py`.

### 2.3 DNS التقليدي

- تحليل A/AAAA عبر `socket.getaddrinfo` (مُحلّل نظام التشغيل).
- محاولة AXFR (نقل المنطقة) تُبنى يدوياً بـ `struct` وتُرسَل إلى المنفذ 53/TCP لأول خادم أسماء.

---

## 3. الأدوات الخارجية الاختيارية

تُستدعى عبر `subprocess` فقط إذا كانت مثبّتة (`shutil.which`)؛ وإلا تُعلن الأداة عدم توفّرها وتُكمل.

| الأداة | الغرض | التثبيت | الترخيص | الموقع |
|---|---|---|---|---|
| **DIRB** | كشف المحتوى/المجلدات المخفية | `sudo apt install dirb` | GPLv2 | https://gitlab.com/kalilinux/packages/dirb |
| **Nikto** | فحص ثغرات الويب (Chris Sullo & David Lodge) | `sudo apt install nikto` | GPLv2 | https://github.com/sullo/nikto |
| **sqlmap** | تأكيد حقن SQL | `sudo apt install sqlmap` | GPLv2 | https://github.com/sqlmapproject/sqlmap |
| **dalfox** | تحسين كشف XSS | `go install github.com/hahwul/dalfox/v2@latest` | MIT | https://github.com/hahwul/dalfox |

قوائم كلمات DIRB تُقرأ من:
`/usr/share/dirb/wordlists`، `/usr/share/wordlists/dirb`، `/opt/dirb/wordlists`
(الافتراضي `common.txt`).

---

## 4. مكتبات Python الاختيارية

مذكورة في `requirements.txt` ولا تؤثر على أدوات الويب إن غابت:

| المكتبة | الترخيص | الاستخدام |
|---|---|---|
| **phonenumbers** | Apache-2.0 | تحليل أرقام الهواتف في مكوّنات OSINT القديمة (يُكتشف وجودها في `env_detect`) |
| **Pillow** | MIT-CMU (HPND) | معالجة الصور في مكوّنات OSINT القديمة |
| **Playwright** | Apache-2.0 | فحص DOM XSS ولقطات الشاشة في Chromium بلا واجهة (اختياري تماماً؛ بدونه يُستخدم التحليل الساكن أو Chrome المثبّت) |

---

## 5. القوائم والتوقيعات المدمجة

كل ما يلي مكتوب داخل المستودع (لم يُنسخ حرفياً من مشروع آخر)، ومستند إلى المعرفة العامة بأسماء
المسارات والخدمات الشائعة:

| الملف | المحتوى | العدد |
|---|---|---|
| `modules/web/dir_buster.py` → `COMMON_PATHS` | مسارات ومجلدات شائعة (admin, .env, .git, backups, api …) | ~110 |
| `modules/web/dir_buster.py` → `SENSITIVE_PATHS` | مسارات تُصنَّف حساسة عند ظهورها | ~35 |
| `modules/web/dir_buster.py` → `SOFT_404_MARKERS` | عبارات تدل على صفحة «غير موجود» تُعاد بحالة 200 | 15 |
| `modules/web/subfinder_clone.py` → `WORDLIST` | بادئات نطاقات فرعية شائعة (www, mail, dev, staging, api …) | ~150 |
| `modules/web/login_finder.py` → `LOGIN_PATHS` | مسارات تسجيل الدخول، متعددة اللغات | 87 |
| `modules/web/register_finder.py` → `REGISTER_PATHS` | مسارات التسجيل/إنشاء الحساب | ~55 |
| `modules/web/param_finder.py` → `COMMON_PARAMS` | أسماء معاملات URL شائعة | 101 |
| `modules/web/waf_detector.py` → `WAF_SIGNATURES` | بصمات WAF (رؤوس، كوكيز، جسم الصفحة) | 17 WAF |
| `modules/web/web_fingerprint.py` → `TECH_SIGNATURES` | بصمات تقنيات (CMS، أطر JS، خوادم، CDN، تحليلات) | 60+ |
| `modules/web/web_fingerprint.py` / `modules/vuln/custom_checks.py` → `SECURITY_HEADERS` | رؤوس أمان يجب فحصها/وجودها | 11 / 9 |
| `modules/vuln/custom_checks.py` → `SENSITIVE_PATHS` | ملفات حساسة محتملة مع درجة خطورة لكل منها | 50+ |
| `modules/network/port_scan.py` | قوائم المنافذ: `common`, `top100`, `web`, `db`, `windows`, `all` | منسّقة داخلياً |
| `modules/vuln/cve_lookup.py` | تخزين مؤقت لنتائج NVD | TTL = 30 يوماً |
| `modules/vuln/advanced/graphql_scanner.py` → `GRAPHQL_PATHS` | مسارات GraphQL شائعة | 10 |
| `modules/vuln/advanced/api_fuzzer.py` → `API_SPEC_PATHS` | مسارات swagger/openapi/Postman | 26 |
| `modules/vuln/advanced/api_fuzzer.py` → `TYPE_PAYLOADS` | قيم اختبار عدم تطابق الأنواع | 10 |
| `modules/vuln/advanced/mass_assignment.py` → `HIDDEN_FIELDS` | حقول صلاحيات/فوترة مخفية | 22 |
| `modules/vuln/advanced/deserialization.py` → `SIGNATURES` | بصمات كائنات متسلسلة (Java/PHP/Pickle/.NET/Ruby/Node...) | 12 |
| `modules/vuln/advanced/xxe_lfi.py` → `LFI_PAYLOADS` / `XXE_PAYLOADS` | حمولات LFI وتجاوز WAF، وحمولات XXE (generic/SOAP/SVG/parameter entity) | 15 / 4 |
| `modules/vuln/advanced/cloud_metadata.py` → `CLOUD_TARGETS` / `INTERNAL_PORTS` | نقاط metadata ومنافذ داخلية | 10 / 16 |
| `modules/vuln/advanced/bucket_checker.py` → `SUFFIXES` | لاحقات أسماء حاويات التخزين | 24 |
| `modules/utils/http_client.py` → `MUTATORS` | ترميزات تجاوز WAF (URL/مزدوج/hex/Unicode/HTML/null/overlong) | 9 |

بصمات WAF والتقنيات **مستقلة**، لكنها تستند إلى أسماء رؤوس/كوكيز/مسارات موثّقة علناً من كل
مزوّد (مثلاً `CF-RAY` لـ Cloudflare، `X-Iinfo` لـ Imperva، `__cf_bm` …).

---

## 6. المراجع التقنية والمعايير

| المرجع | يُستخدم في |
|---|---|
| **RFC 1035** (DNS) و **RFC 8484** (DNS-over-HTTPS) | `dns_deep.py`, `domain_osint.py` |
| **RFC 6962** (Certificate Transparency) | مصدر crt.sh |
| **RFC 7208** (SPF) و **RFC 7489** (DMARC) | فحص SPF/DMARC |
| **RFC 9110/9112** (HTTP semantics) ورموز الحالة | كل وحدات HTTP |
| **OWASP Secure Headers Project** | تقييم الرؤوس الأمنية |
| **OWASP Web Security Testing Guide (WSTG)** | منهجية فحص XSS/SSRF/SSTI/CMDi |
| **FIRST CVSS v2/v3.1** | قراءة درجات NVD |
| **IANA Service Name and Transport Protocol Port Number Registry** | تسمية الخدمات في ماسح المنافذ |
| **AWS/GCP/Alibaba metadata endpoints** (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) | أهداف فحص SSRF |

---

## 7. جدول: كل وحدة ومصادرها

| الوحدة | المصادر الخارجية |
|---|---|
| `web/domain_osint.py` | Cloudflare DoH، Google DoH، WHOIS:43، socket DNS، crt.sh |
| `network/ip_osint.py` | ip-api.com، ipwho.is |
| `network/port_scan.py` | TCP connect + banner grabbing (مباشر، بلا طرف ثالث) |
| `network/dns_deep.py` | Cloudflare DoH، Google DoH، AXFR:53 |
| `network/ssl_analyzer.py` | TLS handshake مباشر عبر `ssl` (بلا طرف ثالث) |
| `web/subfinder_clone.py` | crt.sh، HackerTarget، RapidDNS، AlienVault OTX، urlscan.io، Wayback CDX، ThreatCrowd، bruteforce |
| `web/web_fingerprint.py` | طلب HTTP مباشر + بصمات مدمجة |
| `web/dir_buster.py` | طلب HTTP مباشر + قائمة مسارات مدمجة |
| `web/login_finder.py` | طلب HTTP مباشر + قائمة مسارات مدمجة |
| `web/register_finder.py` | طلب HTTP مباشر + قائمة مسارات مدمجة |
| `web/param_finder.py` | طلب HTTP مباشر + قائمة معاملات مدمجة |
| `web/waf_detector.py` | طلب HTTP مباشر + بصمات WAF مدمجة + 3 حِمولات اختبار |
| `web/web_monitor.py` | طلب HTTP مباشر + تخزين أساس محلي في `~/.reconx/monitor/` |
| `web/live_probe.py` | طلب HTTP/HTTPS مباشر (`http.client` + `ssl`) — مكافئ httpx/httprobe بلا أدوات خارجية |
| `web/aquatone_clone.py` | متصفح محلي فقط: Playwright Chromium أو Chrome/Chromium/Edge بوضع headless — مكافئ Aquatone |
| `vuln/dirb_engine.py` | DIRB (اختياري) + قوائم كلمات DIRB |
| `vuln/bugbounty_nikto.py` / `network/nikto_scan.py` | Nikto (اختياري) |
| `vuln/web/sqli_scanner.py` | sqlmap (اختياري) |
| `vuln/web/xss_scanner.py` | dalfox (اختياري) + فحص انعكاس مدمج |
| `vuln/web/ssrf_scanner.py` | حمولات مدمجة (loopback، metadata clouds) |
| `vuln/web/ssti_scanner.py` | حمولات مدمجة (16 محرّك قوالب) |
| `vuln/web/cmdi_scanner.py` | حمولات مدمجة (time-based + output-based) |
| `vuln/web/jwt_scanner.py` | تحليل JWT محلياً (بلا طرف ثالث) |
| `vuln/cve_lookup.py` | NIST NVD API 2.0 |
| `vuln/custom_checks.py` | طلب HTTP مباشر + قوائم مدمجة |
| `vuln/bounty_checks.py` | طلب HTTP مباشر (VCS، API docs، CORS، open redirect، GraphQL، JWT) |
| `report/html_report.py` | توليد HTML محلياً (لا CDN، لا خطوط خارجية) |
| `vuln/advanced/graphql_scanner.py` | طلب HTTP مباشر إلى الهدف (اكتشاف، introspection، batching، اقتراحات الحقول) |
| `vuln/advanced/api_fuzzer.py` | طلب HTTP مباشر + مواصفات OpenAPI/Swagger/Postman |
| `vuln/advanced/mass_assignment.py` | طلب HTTP مباشر + تحليل فروق الاستجابات |
| `vuln/advanced/bola_mapper.py` | طلب HTTP مباشر بجلستين (A/B) |
| `vuln/advanced/race_condition.py` | طلب HTTP متزامن متعدد الخيوط (حاجز threads) |
| `vuln/advanced/deserialization.py` | تحليل سلبي لكوكيز/حقول/رؤوس الاستجابة |
| `vuln/advanced/xxe_lfi.py` | طلب HTTP مباشر + محرك تجاوز WAF |
| `vuln/advanced/cloud_metadata.py` | طلب HTTP مباشر إلى metadata السحابية + مقارنة منافذ داخلية |
| `vuln/advanced/bucket_checker.py` | واجهات S3/Azure/GCP العامة (قراءة فقط) |
| `vuln/web/dom_xss.py` | تحليل ساكن للصفحة/السكربتات + Playwright Chromium اختياري |
| `utils/http_client.py` | طبقة HTTP مشتركة: تحليل فروق + محرك تحوير الحمولات |

---

## 8. حدود الاستخدام والتراخيص

- **ReconX** نفسه: MIT (انظر `LICENSE`).
- كل مصدر خارجي تحكُمه سياسة موفّره وحدوده:
  - ip-api.com مجاني للاستخدام **غير التجاري** فقط.
  - NVD بلا مفتاح محدود بـ ~5 طلبات/30 ثانية.
  - crt.sh وWayback قد يبطؤان أو يحدّان الطلبات.
  - urlscan.io وAlienVault OTX يخضعان لشروط استخدامهما.
- بعض الخدمات (مثل ThreatCrowd) قد تكون متوقفة؛ غياب النتائج منها ليس خطأً في الأداة.
- القوائم المدمجة تُنتج حركة شبكة مرئية على الهدف. استخدم الأداة على أنظمة تملكها أو لديك
  تفويض كتابي بفحصها فقط.

### كيف تتحقق من هذه المصادر بنفسك

```bash
# DoH — استعلام مباشر
curl -s "https://cloudflare-dns.com/dns-query?name=example.com&type=NS" \
     -H "accept: application/dns-json"

# crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | head -c 500

# NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" | head -c 500
```

### تحديث المصادر

عند إضافة مصدر جديد أو تغيير نقطة نهاية، حدّث:
1. الكود في الوحدة المعنية،
2. الجدول في [القسم 1](#1-واجهات-api-ومصادر-بيانات-خارجية) أو [القسم 7](#7-جدول-كل-وحدة-ومصادرها) هنا،
3. سطر الشكر في `README.md` إن كان المصدر جديداً بالكامل.
