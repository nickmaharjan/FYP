"""Run installed MVT with case-local configuration and networking disabled.

appdirs on Windows uses known-folder APIs rather than APPDATA environment overrides.
Redirect its two MVT directory lookups before importing MVT's configuration module.
"""
import os
import sys
from pathlib import Path


def main():
    import appdirs
    private = Path(os.environ["MOBILE_DF_MVT_SETTINGS"]).resolve()
    private.mkdir(parents=True, exist_ok=True)
    for name in ("user_config_dir", "user_data_dir"):
        original = getattr(appdirs, name)
        def local_directory(appname=None, *args, _original=original, **kwargs):
            if appname == "mvt":
                return str(private)
            return _original(appname, *args, **kwargs)
        setattr(appdirs, name, local_directory)
    os.environ["MVT_NETWORK_ACCESS_ALLOWED"] = "false"
    from mvt.android.cli import main as mvt_main
    mvt_main()


if __name__ == "__main__":
    main()
