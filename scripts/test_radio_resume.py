"""Run resume script with isolated files; no device or modem access."""
import hashlib, os, pathlib, subprocess, tempfile, unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'firmware/overlay/usr/local/libexec/nassimhub-radio-resume'

class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.sys = self.root / 'remoteproc'; self.sys.mkdir()
        self.bundle = self.root / 'bundle'; self.bundle.mkdir()
        self.dest = self.root / 'firmware'; self.dest.mkdir()
        payload=b'test-owned-firmware'
        (self.dest / 'modem.mdt').write_bytes(payload)
        (self.bundle / 'SHA256SUMS').write_text(hashlib.sha256(payload).hexdigest()+'  modem.mdt\n')
        self.bin=self.root/'bin'; self.bin.mkdir()
        cat=self.bin/'cat'
        cat.write_text('#!/usr/bin/python3\nimport pathlib,sys\np=pathlib.Path(sys.argv[1]);s=p.read_text()\nprint("running" if p.name=="state" and s=="start" else s.strip())\n')
        cat.chmod(0o755)
        self.env=dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'])
        self.check='true'

    def tearDown(self): self.tmp.cleanup()

    def proc(self, index, name, state):
        p=self.sys/('remoteproc'+str(index));p.mkdir()
        (p/'name').write_text(name);(p/'state').write_text(state)
        return p/'state'

    def run_script(self):
        text=SCRIPT.read_text().replace('/var/lib/nassimhub/.private-firmware',str(self.bundle)).replace('/sys/class/remoteproc',str(self.sys)).replace('/usr/lib/firmware',str(self.dest)).replace('/usr/local/libexec/nassimhub-device-firmware --check',self.check)
        p=self.root/'resume';p.write_text(text)
        return subprocess.run(['sh',str(p)],env=self.env,capture_output=True,text=True)

    def test_running_processors_are_not_restarted(self):
        a=self.proc(0,'4080000.remoteproc','running');b=self.proc(1,'a204000.remoteproc','running')
        self.assertEqual(self.run_script().returncode,0)
        self.assertEqual(a.read_text(),'running');self.assertEqual(b.read_text(),'running')

    def test_only_known_offline_processors_started(self):
        a=self.proc(0,'4080000.remoteproc','offline');b=self.proc(1,'a204000.remoteproc','offline');c=self.proc(2,'foreign.remoteproc','offline')
        r=self.run_script();self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(a.read_text(),'start');self.assertEqual(b.read_text(),'start');self.assertEqual(c.read_text(),'offline')

    def test_invalid_bundle_does_not_start_radio(self):
        a=self.proc(0,'4080000.remoteproc','offline');self.proc(1,'a204000.remoteproc','offline')
        (self.dest/'modem.mdt').write_bytes(b'corrupt')
        self.assertNotEqual(self.run_script().returncode,0)
        self.assertEqual(a.read_text(),'offline')

    def test_crashed_processor_is_not_forced(self):
        a=self.proc(0,'4080000.remoteproc','crashed');b=self.proc(1,'a204000.remoteproc','offline')
        self.assertNotEqual(self.run_script().returncode,0)
        self.assertEqual(a.read_text(),'crashed');self.assertEqual(b.read_text(),'offline')

    def test_missing_bundle_is_noop(self):
        self.bundle.rename(self.root/'not-provisioned')
        a=self.proc(0,'4080000.remoteproc','offline')
        self.assertEqual(self.run_script().returncode,0)
        self.assertEqual(a.read_text(),'offline')

if __name__=='__main__': unittest.main()
