#!/usr/bin/env python3
"""phone-spyware-check: look for stalkerware signs on YOUR OWN Android phone or iPhone.

Read-only. Nothing is installed, changed or uploaded. The result is a markdown report.

  python3 spyware_check.py --android        # phone on USB, USB debugging on
  python3 spyware_check.py --ios            # guided checklist for iPhone / iPad
  python3 spyware_check.py --demo           # sample report, no phone needed
"""
import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
import urllib.request

__version__ = "0.1.0"

HERE = os.path.dirname(os.path.abspath(__file__))
KEYWORDS_FILE = os.path.join(HERE, "indicators.txt")
IOC_FILE = os.path.join(HERE, "ioc.yaml")
IOC_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
ICON = {HIGH: "🔴", MEDIUM: "🟡", INFO: "⚪"}

# App stores. Anything installed some other way counts as sideloaded.
TRUSTED_INSTALLERS = {
    "com.android.vending",            # Google Play
    "com.google.android.feedback",
    "com.sec.android.app.samsungapps",
    "com.huawei.appmarket",
    "com.xiaomi.market",
    "com.xiaomi.mipicks",
    "com.amazon.venezia",
    "com.heytap.market",
    "com.oppo.market",
    "com.bbk.appstore",
    "com.vivo.appstore",
    "com.oneplus.backuprestore",
    "com.google.android.apps.restore",  # restored by Google from a backup
    "com.android.managedprovisioning",
}

# Permissions a spy app needs to do its job.
RISKY_PERMS = {
    "android.permission.READ_SMS": "read SMS",
    "android.permission.RECEIVE_SMS": "receive SMS",
    "android.permission.READ_CALL_LOG": "call history",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.CAMERA": "camera",
    "android.permission.ACCESS_FINE_LOCATION": "precise location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location in background",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.READ_EXTERNAL_STORAGE": "photos and files",
    "android.permission.READ_MEDIA_IMAGES": "photos",
}


class Finding:
    def __init__(self, level, title, detail="", fix=""):
        self.level, self.title, self.detail, self.fix = level, title, detail, fix


# ---------------------------------------------------------------- indicators

def load_keywords():
    """indicators.txt: '<HIGH|MEDIUM> <substring>' per line."""
    rules = []
    if not os.path.exists(KEYWORDS_FILE):
        return rules
    with open(KEYWORDS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            level, _, word = line.partition(" ")
            if word:
                rules.append((level.upper(), word.strip().lower()))
    return rules


def load_ioc(path):
    """Read package names from the Echap stalkerware-indicators ioc.yaml (no PyYAML needed)."""
    packages, app = {}, None
    in_packages, key_indent = False, 0
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = re.match(r"^- name:\s*(.+)$", line)
            if m:
                app, in_packages = m.group(1).strip(), False
                continue
            m = re.match(r"^(\s*)packages:\s*$", line)
            if m:
                in_packages, key_indent = True, len(m.group(1))
                continue
            if in_packages:
                m = re.match(r"^(\s*)-\s+(\S+)\s*$", line)
                if m and len(m.group(1)) >= key_indent:
                    packages[m.group(2).strip("'\"")] = app or "known stalkerware"
                else:
                    in_packages = False
    return packages


def update_ioc():
    print("Downloading the public stalkerware list from Echap...")
    urllib.request.urlretrieve(IOC_URL, IOC_FILE)
    n = len(load_ioc(IOC_FILE))
    print("Saved %d package names to %s" % (n, IOC_FILE))


# ---------------------------------------------------------------- android

def adb(serial, *args):
    cmd = ["adb"] + (["-s", serial] if serial else []) + ["shell"] + list(args)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return ""
    return out.stdout


def pick_device(serial):
    if not shutil.which("adb"):
        sys.exit("adb not found. Install it first:\n"
                 "  macOS:   brew install android-platform-tools\n"
                 "  Windows: winget install Google.PlatformTools\n"
                 "  Linux:   sudo apt install adb")
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout
    devices = [l.split("\t") for l in out.splitlines()[1:] if "\t" in l]
    ready = [d[0] for d in devices if d[1] == "device"]
    if any(d[1] == "unauthorized" for d in devices):
        sys.exit("The phone is connected but not trusted. Unlock it and tap 'Allow USB debugging'.")
    if not ready:
        sys.exit("No phone found. Plug it in by USB and turn on USB debugging:\n"
                 "Settings > About phone > tap 'Build number' 7 times > Developer options > USB debugging.")
    if serial:
        if serial not in ready:
            sys.exit("Device %s not found. Connected: %s" % (serial, ", ".join(ready)))
        return serial
    if len(ready) > 1:
        sys.exit("Several devices connected (%s). Pick one with --serial." % ", ".join(ready))
    return ready[0]


def parse_component_list(value):
    """'pkg/cls:pkg2/cls2' -> {'pkg', 'pkg2'}"""
    value = (value or "").strip()
    if not value or value == "null":
        return set()
    return {part.split("/")[0] for part in value.split(":") if "/" in part}


def scan_android(serial, keywords, ioc):
    s = pick_device(serial)
    info = {
        "Device": "%s %s" % (adb(s, "getprop", "ro.product.manufacturer").strip(),
                             adb(s, "getprop", "ro.product.model").strip()),
        "Android": adb(s, "getprop", "ro.build.version.release").strip(),
        "Security patch": adb(s, "getprop", "ro.build.version.security_patch").strip(),
    }
    print("Checking %s (Android %s)..." % (info["Device"], info["Android"]))

    # third-party apps + who installed them
    apps = {}
    for line in adb(s, "pm", "list", "packages", "-3", "-i").splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if m:
            apps[m.group(1)] = m.group(2)
        elif line.startswith("package:"):
            apps[line[8:].strip()] = "null"

    launchable = set(re.findall(r"^\s*([\w.]+)/", adb(
        s, "cmd", "package", "query-activities", "--brief",
        "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"), re.M))

    accessibility = parse_component_list(adb(s, "settings", "get", "secure", "enabled_accessibility_services"))
    notif = parse_component_list(adb(s, "settings", "get", "secure", "enabled_notification_listeners"))
    policy = adb(s, "dumpsys", "device_policy")
    admins = set(re.findall(r"admin=ComponentInfo\{([^/}]+)/", policy))
    owner = re.search(r"Device Owner:?\s*\n\s*admin=ComponentInfo\{([^/}]+)/", policy)
    profile_owner = set(re.findall(r"Profile Owner[^\n]*\n\s*admin=ComponentInfo\{([^/}]+)/", policy))
    battery_free = set(re.findall(r"^user,([\w.]+),", adb(s, "dumpsys", "deviceidle", "whitelist"), re.M))
    vpn = adb(s, "settings", "get", "secure", "always_on_vpn_app").strip()

    findings = []

    if owner:
        findings.append(Finding(
            HIGH, "Phone is managed (MDM device owner): %s" % owner.group(1),
            "A device owner can see and control almost everything on the phone. "
            "Normal for a work phone. Not normal for a personal one.",
            "If this is not your employer's phone: back up photos, then factory reset."))
    for p in sorted(profile_owner):
        findings.append(Finding(
            MEDIUM, "Managed work profile: %s" % p,
            "A work profile is controlled by an organisation.",
            "If you never set up a work profile: Settings > Accounts > Work profile > Remove."))
    if vpn and vpn != "null":
        findings.append(Finding(
            MEDIUM, "Always-on VPN: %s" % vpn,
            "All internet traffic goes through this app.",
            "If you did not set this up: Settings > Network > VPN > remove it."))

    suspects = set(apps) | accessibility | notif | admins | battery_free
    for pkg in sorted(suspects):
        third_party = pkg in apps
        signals, level = [], None

        if pkg in ioc:
            signals.append("on the public stalkerware list (%s)" % ioc[pkg])
            level = HIGH
        for kw_level, kw in keywords:
            if kw in pkg.lower():
                signals.append("name contains '%s'" % kw)
                level = HIGH if HIGH in (level, kw_level) else MEDIUM
                break

        sideloaded = third_party and apps[pkg] not in TRUSTED_INSTALLERS
        hidden = third_party and launchable and pkg not in launchable
        power = []
        if pkg in accessibility:
            power.append("accessibility (can read the screen and taps)")
        if pkg in admins:
            power.append("device admin (hard to uninstall)")
        if pkg in notif:
            power.append("notification access (reads your messages)")

        if sideloaded:
            signals.append("installed outside an app store (installer: %s)" % apps[pkg])
        if hidden:
            signals.append("no icon on the home screen")
        signals += power
        if pkg in battery_free:
            signals.append("allowed to run in the background without battery limits")

        if not signals:
            continue
        if level is None:
            if sideloaded and (power or hidden):
                level = HIGH
            elif power and third_party:
                level = MEDIUM
            elif sideloaded or (hidden and pkg in battery_free):
                level = MEDIUM
            elif not third_party:
                continue  # system app with normal system rights
            else:
                level = INFO

        perms = []
        if level in (HIGH, MEDIUM):
            dump = adb(s, "dumpsys", "package", pkg)
            perms = [label for perm, label in RISKY_PERMS.items()
                     if re.search(re.escape(perm) + r": granted=true", dump)]
        detail = "; ".join(signals)
        if perms:
            detail += ". Has access to: " + ", ".join(perms)
        fix = ""
        if level != INFO:
            fix = "If you don't recognise it: Settings > Apps > %s > Uninstall." % pkg
            if pkg in admins:
                fix += " Uninstall is greyed out until you remove it under Settings > Security > Device admin apps."
        findings.append(Finding(level, pkg, detail, fix))

    manual = [
        "Battery: Settings > Battery > Battery usage. Look for an app you don't know near the top.",
        "Data: Settings > Network & internet > Data usage (or Connections > Data usage). "
        "Look for an unknown app sending a lot in the background.",
        "Google account: myaccount.google.com > Security > Your devices. Sign out devices you don't know.",
        "Google Play Protect: Play Store > profile picture > Play Protect > Scan.",
        "When done: turn USB debugging off again (Developer options > USB debugging).",
    ]
    stats = {"Third-party apps": len(apps), "Accessibility services": len(accessibility),
             "Device admins": len(admins), "Notification listeners": len(notif)}
    return info, stats, findings, manual


# ---------------------------------------------------------------- iphone

IOS_QUESTIONS = [
    (HIGH, "Settings > General > VPN & Device Management: is there a profile you did not install?",
     "A configuration or MDM profile can route your traffic and control the phone.",
     "Tap the profile > Remove Management / Remove Profile. Then change your Apple ID password."),
    (HIGH, "Settings > [your name] (scroll down to the device list): is there a device you don't own?",
     "Someone else is signed in to your Apple ID and can see iCloud photos, messages and backups.",
     "Tap the device > Remove from Account. Change your Apple ID password right after."),
    (HIGH, "Settings > Privacy & Security > Safety Check > Manage Sharing & Access: "
           "is anyone getting your location or app data that you didn't approve?",
     "Safety Check lists people and apps that can see your data.",
     "Stop sharing there. Use 'Emergency Reset' if you think you are in danger."),
    (HIGH, "Do you see apps named Cydia, Sileo, Zebra or Filza, or did someone have your phone unlocked for a while?",
     "These apps mean the phone is jailbroken. Jailbreak is how real spyware gets onto an iPhone.",
     "Back up photos, then update iOS or restore the phone in Finder / iTunes."),
    (MEDIUM, "Find My > People: are you sharing your location with someone unexpected?",
     "", "Swipe left on the person > Stop Sharing My Location."),
    (MEDIUM, "Does anyone else know your Apple ID password or your phone passcode?",
     "With both, a person can read iCloud backups from any computer.",
     "Change both. Do it from a device only you use."),
    (MEDIUM, "Settings > [your name] > Sign-In & Security: is two-factor authentication OFF?",
     "", "Turn it on. It stops logins from new devices without your approval."),
    (MEDIUM, "Settings > Battery: does an app you don't know use a lot of battery or background activity?",
     "", "Delete the app if you don't know what it does."),
    (MEDIUM, "Settings > Cellular (Mobile Data): does an unknown app use a lot of data?",
     "", "Turn its data off, then delete it."),
    (MEDIUM, "Settings > Privacy & Security > Location Services / Microphone / Camera: "
             "does an app you don't know have access?",
     "", "Switch access off and delete the app."),
    (MEDIUM, "Do you see the orange or green dot (mic / camera in use) when you are not using them?",
     "", "Open Control Center right away: it names the app that used the mic or camera."),
]


def ios_apps(keywords):
    """If libimobiledevice is installed, list user apps and match them against keywords."""
    if not shutil.which("ideviceinstaller"):
        return [], None
    out = subprocess.run(["ideviceinstaller", "-l"], capture_output=True, text=True).stdout
    rows = [l for l in out.splitlines() if "," in l and not l.startswith("CFBundleIdentifier")]
    findings = []
    for row in rows:
        bundle = row.split(",")[0].strip()
        for level, kw in keywords:
            if kw in row.lower():
                findings.append(Finding(level, bundle, "app name contains '%s'" % kw,
                                        "Delete it if you didn't install it."))
                break
    return findings, len(rows)


def ask(question):
    while True:
        a = input("\n%s\n  [y]es / [n]o / [s]kip: " % question).strip().lower()
        if a in ("y", "yes", "n", "no", "s", "skip", ""):
            return a[:1] or "s"


def scan_ios(keywords):
    print("iPhone / iPad check. Answer each question while looking at the phone.")
    print("'y' means you found a problem. Takes about 5 minutes.")
    findings, skipped = [], []
    app_findings, app_count = ios_apps(keywords)
    findings += app_findings
    for level, q, detail, fix in IOS_QUESTIONS:
        a = ask(q)
        if a == "y":
            findings.append(Finding(level, q, detail, fix))
        elif a == "s":
            skipped.append(q)
    info = {"Device": "iPhone / iPad (guided check)"}
    stats = {"Questions answered": len(IOS_QUESTIONS) - len(skipped)}
    if app_count is not None:
        stats["User apps listed over USB"] = app_count
    manual = ["Skipped: " + q for q in skipped] + [
        "For a deep forensic scan (Pegasus-class spyware) use Amnesty's MVT: https://github.com/mvt-project/mvt",
        "Keep iOS updated: Settings > General > Software Update.",
    ]
    return info, stats, findings, manual


# ---------------------------------------------------------------- demo

def demo():
    info = {"Device": "samsung SM-S918B (demo data)", "Android": "14", "Security patch": "2026-09-01"}
    stats = {"Third-party apps": 87, "Accessibility services": 2,
             "Device admins": 2, "Notification listeners": 3}
    findings = [
        Finding(HIGH, "com.systemservice",
                "on the public stalkerware list (TheTruthSpy); installed outside an app store "
                "(installer: null); no icon on the home screen; accessibility (can read the screen and taps); "
                "device admin (hard to uninstall). Has access to: read SMS, microphone, precise location",
                "If you don't recognise it: Settings > Apps > com.systemservice > Uninstall. If uninstall is "
                "greyed out, first remove it under Settings > Security > Device admin apps."),
        Finding(MEDIUM, "com.example.flashlight",
                "installed outside an app store (installer: com.android.chrome); "
                "allowed to run in the background without battery limits",
                "If you don't recognise it: Settings > Apps > com.example.flashlight > Uninstall."),
        Finding(INFO, "com.whatsapp", "allowed to run in the background without battery limits", ""),
    ]
    manual = ["Battery: Settings > Battery > Battery usage. Look for an app you don't know near the top."]
    return info, stats, findings, manual


# ---------------------------------------------------------------- report

def write_report(path, mode, info, stats, findings, manual):
    order = {HIGH: 0, MEDIUM: 1, INFO: 2}
    findings.sort(key=lambda f: order[f.level])
    count = {lvl: sum(f.level == lvl for f in findings) for lvl in (HIGH, MEDIUM, INFO)}
    if count[HIGH]:
        verdict = "🔴 Signs of stalkerware found. Read 'Before you delete anything' first."
    elif count[MEDIUM]:
        verdict = "🟡 Nothing certain, but some apps have more power than they need. Review them."
    else:
        verdict = "🟢 No signs of stalkerware found by this check."

    L = ["# Phone spyware check", "",
         "Generated %s by phone-spyware-check %s (%s mode)." % (
             datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), __version__, mode), "",
         "**%s**" % verdict, "",
         "| | |", "|---|---|"]
    L += ["| %s | %s |" % (k, v) for k, v in list(info.items()) + list(stats.items())]
    L += ["", "🔴 %d high · 🟡 %d medium · ⚪ %d info" % (count[HIGH], count[MEDIUM], count[INFO]), ""]

    for lvl, title in ((HIGH, "High risk"), (MEDIUM, "Review"), (INFO, "For information")):
        items = [f for f in findings if f.level == lvl]
        if not items:
            continue
        L += ["## %s %s" % (ICON[lvl], title), ""]
        for f in items:
            L.append("- **%s**" % f.title)
            if f.detail:
                L.append("  - Why: %s" % f.detail)
            if f.fix:
                L.append("  - What to do: %s" % f.fix)
        L.append("")

    if manual:
        L += ["## Check by hand", ""] + ["- [ ] %s" % m for m in manual] + [""]
    L += ["## Before you delete anything", "",
          "- Removing a spy app can alert the person who installed it. "
          "If you think you are in danger, talk to a support line first: https://stopstalkerware.org",
          "- Take screenshots of what you found. They can be evidence.",
          "- Change your passwords from a different device that only you use.",
          "- A factory reset removes almost all stalkerware. Back up photos first, not apps.", "",
          "_This check looks for common signs. It cannot prove a phone is clean._", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return count


def main():
    p = argparse.ArgumentParser(
        description="Check YOUR OWN phone for stalkerware. Read-only. Writes a markdown report.",
        epilog="Only check devices you own or are allowed to check.")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--android", action="store_true", help="scan an Android phone over USB (needs adb)")
    mode.add_argument("--ios", action="store_true", help="guided checklist for iPhone / iPad")
    mode.add_argument("--demo", action="store_true", help="write a sample report without a phone")
    mode.add_argument("--update-ioc", action="store_true",
                      help="download the public stalkerware package list (Echap) next to this script")
    p.add_argument("--serial", help="Android device serial if several are connected")
    p.add_argument("--ioc", default=IOC_FILE, help="path to ioc.yaml (default: next to this script)")
    p.add_argument("-o", "--output", help="report path (default: spyware-report-<date>.md)")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args()

    if a.update_ioc:
        update_ioc()
        return

    keywords = load_keywords()
    ioc = load_ioc(a.ioc) if os.path.exists(a.ioc) else {}
    if a.android and not ioc:
        print("Tip: run with --update-ioc once to add the public list of 600+ known spy app packages.")

    if a.demo:
        m, result = "demo", demo()
    elif a.android:
        m, result = "android", scan_android(a.serial, keywords, ioc)
    else:
        m, result = "ios", scan_ios(keywords)

    out = a.output or "spyware-report-%s.md" % datetime.datetime.now().strftime("%Y%m%d-%H%M")
    count = write_report(out, m, *result)
    print("\nDone: %d high, %d medium, %d info." % (count[HIGH], count[MEDIUM], count[INFO]))
    print("Report: %s" % os.path.abspath(out))


if __name__ == "__main__":
    main()
