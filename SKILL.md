---
name: phone-spyware-check
description: Check the user's OWN Android phone or iPhone for stalkerware step by step (suspicious apps, accessibility and admin rights, MDM profiles, battery and data use) and write a markdown report. Use when the user says "check my phone for spyware", "is someone tracking my phone", "stalkerware check".
---

# Phone spyware check

You help a person check **their own** phone for stalkerware. Defensive only.

## Rules

- Before starting, ask: "Is this your own phone, or one you are allowed to check?" If the answer is no
  (a partner's, an ex's, an employee's phone without consent), stop and explain you can only help
  check the user's own device.
- The script is read-only. Never run commands that uninstall apps, change settings or copy the user's data.
- Do not upload the report anywhere. It stays on the user's computer.
- If the user says they feel unsafe, share https://stopstalkerware.org **before** suggesting they delete
  anything: removing a spy app can alert the person who installed it.

## Steps

1. Ask which phone: Android or iPhone.
2. **Android**
   - Check `adb` is installed (`adb version`). If not, give the install command for their OS
     (macOS `brew install android-platform-tools`, Windows `winget install Google.PlatformTools`,
     Linux `sudo apt install adb`).
   - Walk them through USB debugging: Settings > About phone > tap Build number 7 times >
     Developer options > USB debugging > plug in > tap "Allow".
   - Run once: `python3 <skill dir>/spyware_check.py --update-ioc` (downloads the public stalkerware list).
   - Run: `python3 <skill dir>/spyware_check.py --android`
3. **iPhone**
   - Run `python3 <skill dir>/spyware_check.py --ios` in a terminal the user can type into, or ask the
     same questions yourself one by one and write the report in the same format.
4. Open the report and explain it in plain words:
   - start with the verdict line;
   - for each 🔴 item: what the app can do and the exact tap path to remove it;
   - for 🟡 items: ask the user if they recognise the app before calling it suspicious.
5. Go through the "Check by hand" list together (battery, data, accounts).
6. Remind them to turn USB debugging off at the end (Android).

## What this check can and can't do

- It finds common stalkerware and apps with too much power. It cannot prove a phone is clean.
- On iPhone, real spyware needs a jailbreak or the Apple ID password. Most "iPhone spying" is iCloud
  access, so the Apple ID questions matter most.
- For Pegasus-class spyware point to Amnesty's MVT: https://github.com/mvt-project/mvt
