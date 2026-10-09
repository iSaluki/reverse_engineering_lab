"""Compact APK manifest/attack-surface summary. usage: apk_summary.py <apk>"""
import sys
import zipfile
import logging

from loguru import logger  # androguard logs through loguru

logger.remove()
logging.disable(logging.CRITICAL)

from androguard.core.apk import APK  # noqa: E402

NS = "{http://schemas.android.com/apk/res/android}"
DANGEROUS = {"READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA",
             "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES",
             "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
             "BIND_DEVICE_ADMIN", "READ_PHONE_STATE", "BIND_NOTIFICATION_LISTENER_SERVICE", "USE_FULL_SCREEN_INTENT"}


def main(path):
    a = APK(path)
    print(f"package      {a.get_package()}  version={a.get_androidversion_name()} ({a.get_androidversion_code()})")
    print(f"sdk          min={a.get_min_sdk_version()} target={a.get_target_sdk_version()}")
    print(f"app          label={a.get_app_name()!r} class={a.get_attribute_value('application', 'name')}")
    print(f"main         {a.get_main_activity()}")
    m = a.get_android_manifest_xml()
    app = m.find("application")
    flags = []
    for attr in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "extractNativeLibs"):
        v = app.get(NS + attr) if app is not None else None
        if v is not None:
            flags.append(f"{attr}={v}")
    if flags:
        print(f"flags        {' '.join(flags)}")
    perms = sorted(a.get_permissions())
    short = [p.split(".")[-1] for p in perms]
    dang = [p for p in short if p in DANGEROUS]
    print(f"permissions  {len(perms)} total; notable: {', '.join(dang) or '-'}")
    custom = [p for p in perms if not p.startswith("android.permission.") and not p.startswith("com.google.")]
    if custom:
        print(f"custom perms {', '.join(custom[:10])}")
    # exported components (explicit exported=true or has intent-filter w/o exported=false)
    print("exported components:")
    n = 0
    if app is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for c in app.findall(tag):
                name = c.get(NS + "name")
                exp = c.get(NS + "exported")
                filters = c.findall("intent-filter")
                if exp == "true" or (exp is None and filters and tag != "provider"):
                    acts, schemes = [], []
                    for f in filters:
                        acts += [x.get(NS + "name", "").replace("android.intent.action.", "") for x in f.findall("action")]
                        for d in f.findall("data"):
                            sch, host, pth = d.get(NS + "scheme"), d.get(NS + "host"), d.get(NS + "path") or d.get(NS + "pathPrefix") or d.get(NS + "pathPattern")
                            if sch or host:
                                schemes.append(f"{sch or '*'}://{host or '*'}{pth or ''}")
                    perm = c.get(NS + "permission")
                    extra = []
                    if acts:
                        extra.append("actions=" + ",".join(acts[:4]))
                    if schemes:
                        extra.append("deeplinks=" + ",".join(sorted(set(schemes))[:5]))
                    if perm:
                        extra.append("perm=" + perm)
                    if tag == "provider":
                        extra.append("authorities=" + str(c.get(NS + "authorities")))
                    print(f"  {tag:<9} {name}  {' '.join(extra)}")
                    n += 1
    if not n:
        print("  (none)")
    try:
        certs = a.get_certificates()
        for c in certs[:1]:
            print(f"signer       {c.subject.human_friendly}  sha256={c.sha256_fingerprint.replace(' ', '')[:32]}...")
    except Exception:  # noqa: BLE001
        pass
    z = zipfile.ZipFile(path)
    libs = sorted({n.split("/")[-1] for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")})
    if libs:
        print(f"native libs  {', '.join(libs[:30])}")
    assets = [n for n in z.namelist() if n.startswith("assets/")]
    if assets:
        print(f"assets       {len(assets)} files, e.g. {', '.join(assets[:8])}")


if __name__ == "__main__":
    main(sys.argv[1])
