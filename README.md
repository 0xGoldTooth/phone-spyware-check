# phone-spyware-check

**Is someone reading your phone?** This checks your own Android phone or iPhone for stalkerware, step by step,
and gives you a plain-English report with what to do next.

It is a [Claude Code](https://claude.com/claude-code) skill plus one Python script. Read-only: it does not
install, delete or upload anything.

> Built from my X post: https://x.com/0xGoldTooth/status/2112619624114090402
> More AI + security builds: [x.com/0xGoldTooth](https://x.com/0xGoldTooth)

## Who it's for

- You think a partner, an ex or "a friend who fixed your phone" can see your messages or location.
- Your battery or data use suddenly went up and you don't know why.
- You bought a used phone, or you got a phone from someone else.
- You help friends and family with their phones.

## What it checks

| Check | Android (automatic, over USB) | iPhone (guided, ~5 min) |
|---|---|---|
| Known spy apps | 600+ package names from the public [Echap stalkerware list](https://github.com/AssoEchap/stalkerware-indicators) + name patterns | App list over USB if `ideviceinstaller` is installed |
| Apps installed outside an app store | ✅ | — (needs a jailbreak on iPhone) |
| Apps with no home-screen icon | ✅ | — |
| Accessibility rights (can read the screen) | ✅ | — |
| Device admin (hard to uninstall) | ✅ | — |
| Notification access (reads messages) | ✅ | — |
| MDM / device owner / work profile / configuration profiles | ✅ | ✅ |
| Always-on VPN | ✅ | ✅ (profiles) |
| Apps allowed to run without battery limits | ✅ | — |
| Battery and data use by app | checklist | ✅ |
| Unknown devices on your Apple ID / Google account | checklist | ✅ |
| Location sharing, Safety Check, jailbreak signs | — | ✅ |

## Install in 3 steps

```bash
# 1. Get it (as a Claude Code skill)
git clone https://github.com/0xGoldTooth/phone-spyware-check ~/.claude/skills/phone-spyware-check

# 2. Android only: install adb and the public spy-app list
brew install android-platform-tools        # Windows: winget install Google.PlatformTools
python3 ~/.claude/skills/phone-spyware-check/spyware_check.py --update-ioc

# 3. Run it
claude "check my phone for spyware"
```

No Claude Code? Run the script directly:

```bash
python3 spyware_check.py --android     # phone on USB with USB debugging on
python3 spyware_check.py --ios         # guided iPhone / iPad checklist
python3 spyware_check.py --demo        # sample report, no phone needed
```

Python 3.8+, no extra packages.

**USB debugging on Android:** Settings > About phone > tap *Build number* 7 times > Developer options >
USB debugging. Plug the phone in and tap *Allow*. Turn it off again when you're done.

## Example output

```text
$ python3 spyware_check.py --android
Checking Google Pixel 8 (Android 15)...

Done: 2 high, 2 medium, 1 info.
Report: /Users/me/spyware-report-20261031-1145.md
```

The report (`spyware-report-*.md`):

```text
# Phone spyware check

🔴 Signs of stalkerware found. Read 'Before you delete anything' first.

🔴 2 high · 🟡 2 medium · ⚪ 1 info

## 🔴 High risk
- com.systemservice
  - Why: on the public stalkerware list (TheTruthSpy); installed outside an app store
    (installer: null); no icon on the home screen; accessibility (can read the screen and taps);
    device admin (hard to uninstall). Has access to: read SMS, precise location
  - What to do: If you don't recognise it: Settings > Apps > com.systemservice > Uninstall.
    Uninstall is greyed out until you remove it under Settings > Security > Device admin apps.

## 🟡 Review
- com.cool.flashlight
  - Why: installed outside an app store (installer: com.android.chrome);
    allowed to run in the background without battery limits

## Check by hand
- [ ] Battery: Settings > Battery > Battery usage. Look for an app you don't know near the top.
- [ ] Google account: myaccount.google.com > Security > Your devices.

## Before you delete anything
- Removing a spy app can alert the person who installed it. If you think you are in danger,
  talk to a support line first: https://stopstalkerware.org
```

## The honest part

- A clean report is not proof. New spy apps rename themselves. This finds the common ones and anything
  with suspicious power.
- 🟡 does not mean "spyware". Password managers use accessibility, messengers skip battery limits.
  It means "make sure you know this app".
- On iPhone, real spyware needs a jailbreak or your Apple ID password. In practice most iPhone spying is
  someone logged into your iCloud. That's why the iPhone check is mostly about your Apple ID.
- For state-level spyware (Pegasus and friends) use Amnesty's [MVT](https://github.com/mvt-project/mvt).
- Only check phones you own or have permission to check.

## Files

- `SKILL.md` — instructions Claude Code follows
- `spyware_check.py` — the scanner and report writer
- `indicators.txt` — name patterns, edit freely
- `ioc.yaml` — downloaded by `--update-ioc`, not stored in this repo

## License

MIT. Spy-app list © [Echap](https://github.com/AssoEchap/stalkerware-indicators), downloaded at runtime.
