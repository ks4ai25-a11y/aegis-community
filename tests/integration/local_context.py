"""Shared local test context. No production credential fallback."""
import os,pathlib,tempfile
credential_root=pathlib.Path('/private/tmp') if pathlib.Path('/private/tmp').is_dir() else pathlib.Path(tempfile.gettempdir())
CREDENTIAL_FILE=pathlib.Path(os.environ.get('AEGIS_TEST_CREDENTIAL_FILE',str(credential_root/'aegis-demo-test-credential')))
