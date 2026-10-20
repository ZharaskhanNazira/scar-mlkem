#!/usr/bin/env python3
"""Read-only source lineage and exact integration checks."""
from pathlib import Path
import hashlib,json,subprocess,sys
HERE=Path(__file__).resolve().parent
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def verify():
 parent=HERE.parent/'packed_controller'
 assert H(parent/'source_manifest.json')=='7f9b527d20131a1e1421f7ac0d5f74130eed49472dcf498610a5c1030c90cc10'
 m=json.loads((parent/'source_manifest.json').read_text())
 assert all(H(parent/n)==h for n,h in m['files'].items())
 subprocess.run([sys.executable,str(parent/'verify_dependencies.py')],check=True)
 own=json.loads((HERE/'source_manifest.json').read_text())
 assert all(H(HERE/n)==h for n,h in own['files'].items())
 for package,filename,expected in own['qualified_dependencies']:
  root=HERE.parents[2]
  p=root/filename
  assert H(p)==expected,package
  f=json.loads(p.read_text())
  for group in ['files','parent_files']:
   assert all(H(root/n)==h for n,h in f.get(group,{}).items()),package
 assert (HERE/'secret_core.h').read_bytes()==(HERE.parent/'secret_core/secret_core.h').read_bytes()
 for name in ['joint_controller.h','causal_policy.inc','deadline_wait.inc','joint_trace.c','public_matrix.h']:
  assert (HERE/name).read_bytes()==(parent/name).read_bytes(),name
 for name in ['joint_controller.c','fixtures/reference/joint_controller.c']:
  assert (HERE/name).read_text()==(parent/name).read_text().replace('#define SECRET_BYTES 2400u','#define SECRET_BYTES 1152u'),name
 print('pinned_integration_verified=1 policies_unchanged=1 secret_core_bytes=1152')
if __name__=='__main__':verify()
