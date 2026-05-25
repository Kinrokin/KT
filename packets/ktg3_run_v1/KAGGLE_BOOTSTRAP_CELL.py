from pathlib import Path
import zipfile

packet_zip = next(Path("/kaggle/input").rglob("ktg3_run_v1.zip"))
work = Path("/kaggle/working/ktg3_run_v1")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet_zip) as zf:
    for member in zf.namelist():
        target = (work / member).resolve()
        if not str(target).startswith(str(work.resolve())):
            raise RuntimeError(f"Unsafe zip member path: {member}")
        if member.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
exec((work / "KTG3_TARGETED_REPAIR_RUNNER.py").read_text(encoding="utf-8"), {"__name__": "__main__"})
