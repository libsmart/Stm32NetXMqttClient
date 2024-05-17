import subprocess
import re
from datetime import datetime


def return_version_maj_min(branch_name):
    # Regex-Pattern, um nach einem SemVer 2.0-konformen Branch-Namen zu suchen
    semver_pattern = r'^\d+\.\d+\.(\d+|x)$'
    if re.match(semver_pattern, branch_name):
        # Splitte den Branch-Namen am ersten Punkt
        parts = branch_name.split('.', 2)
        # Return the first 2 parts of the version (MAJ.MIN)
        return f"{parts[0]}.{parts[1]}"
    else:
        return f"0.0"


def calc_next_version(prefix):
    try:
        if not re.match(r'^\d+\.\d+$', prefix):
            return f""

        # Git-Befehl, um Tags zu filtern und nach der höchsten Nummer nach dem zweiten Punkt zu sortieren
        result = subprocess.run(['git', 'tag', '--list', f'{prefix}.*', '--sort=-v:refname'], capture_output=True,
                                text=True, check=True)
        tags = result.stdout.strip().split('\n')
        if tags:
            # Splitte die Ausgabe, um nur den neuesten Tag zu erhalten
            latest_tag = tags[0]
            # Extrahiere den Patch-Level aus dem neuesten Tag
            tag_parts = latest_tag.split('.')
            if len(tag_parts) >= 3:
                patch_level = int(tag_parts[2])
                # Erhöhe den Patch-Level um eins
                patch_level += 1
            else:
                patch_level = 0
            return f"{prefix}.{patch_level}"
        else:
            # Falls keine Tags gefunden wurden, setze den Patch-Level auf Null
            return f"{prefix}.0"
    except subprocess.CalledProcessError:
        # Falls ein Fehler auftritt, setze den Patch-Level auf Null
        return f"ERROR"


revision = (
    subprocess.check_output(["git", "rev-parse", "HEAD"])
    .strip()
    .decode("utf-8")
)
hash = (
    subprocess.check_output(["git", "log", "-1", "--format=%h"])
    .strip()
    .decode("utf-8")
)
branch = (
    subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    .strip()
    .decode("utf-8")
)

print("-DGIT_REV=\"%s\"" % revision)
print("-DGIT_HASH=\"%s\"" % hash)
print("-DGIT_BRANCH=\"%s\"" % branch)
# branch = "0.1.x"
# branch = "main"
ver_short = return_version_maj_min(branch)
print("-DVER_MAJ_MIN=\"%s\"" % ver_short)
ver_next = calc_next_version(ver_short)
print("-DVER_NEXT=\"%s\"" % ver_next)
timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
print("-DBUILD_TIME=\"%s\"" % timestamp)
print("-DVER_NEXT_ALPHA=\"%s-alpha.%s+%s\"" % (ver_next, hash, timestamp))
