import sys
from pathlib import Path

# Make the project root importable when this test file is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import threading
import time
import unittest
import unittest.mock
import tempfile
from scanner_lib.parser import parse_targets
from scanner_lib.scanner import scan_targets
from scanner_lib.models import HostResult,ScanReport,ScanConfig
from scanner_lib.reports import records_for,csv_bytes
from backend import db
class CoreTests(unittest.TestCase):
 def test_parse_dedupe_and_ranges(self):
  self.assertEqual(parse_targets("192.0.2.1-3,192.0.2.2"),["192.0.2.1","192.0.2.2","192.0.2.3"])
 def test_bad_and_limit(self):
  with self.assertRaises(ValueError):parse_targets("999.1.1.1")
  with self.assertRaises(ValueError):parse_targets("192.0.2.0/29",2)
 def test_categories_and_csv_bom(self):
  # Exclusive classification buckets (no double-counting):
  # .1 8291 open / 8728 timeout → winbox_open_api_closed
  # .2 no open ports, ping → potential_non_mikrotik
  # .3 8291 open / 8728 refused → winbox_open_api_closed
  # .4 8291 open / 8728 closed → winbox_open_api_closed
  # .5 both open → mikrotik_candidate
  # .6 no open ports, ping → potential_non_mikrotik
  rows=[
   HostResult("192.0.2.1",True,{8291:"open",8728:"timeout"}),
   HostResult("192.0.2.2",True,{8291:"refused",8728:"refused"}),
   HostResult("192.0.2.3",True,{8291:"open",8728:"refused"}),
   HostResult("192.0.2.4",True,{8291:"open",8728:"closed"}),
   HostResult("192.0.2.5",True,{8291:"open",8728:"open"}),
   HostResult("192.0.2.6",True,{8291:"closed",8728:"refused"}),
  ]
  report=ScanReport(rows,6,6,6)
  self.assertEqual(len(records_for(report,"mikrotik_candidates")),1)
  self.assertEqual(len(records_for(report,"potential_non_mikrotik")),2)
  self.assertEqual([r.ip for r in records_for(report,"winbox_open_api_closed")],["192.0.2.1","192.0.2.3","192.0.2.4"])
  self.assertEqual(len(records_for(report,"ping_responders")),6)
  self.assertTrue(csv_bytes(report,"ping_responders").startswith(b"\xef\xbb\xbf"))
 def test_sqlite_upsert_deduplicates_and_merges_ports(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/"devices.db"
   db.init_db(path)
   db.upsert_device("192.0.2.25",True,[8291],{"8291":"open"},"mikrotik_candidate",db_path=path)
   db.upsert_device("192.0.2.25",True,[8728],{"8728":"refused"},"non_mikrotik",db_path=path)
   result=db.query_devices(db_path=path)
   self.assertEqual(result["total"],1)
   device=result["devices"][0]
   self.assertEqual(device["open_ports"],[8291,8728])
   self.assertEqual(device["seen_count"],2)
   self.assertEqual(device["classification"],"mikrotik_candidate")
   self.assertEqual(device["port_states"],{"8291":"open","8728":"refused"})
   self.assertTrue(device["first_seen"]<=device["last_seen"])

class ScanTargetsWithCancel(unittest.TestCase):
 class _Config:
  ports=(8291,)
  workers=2
  ping_timeout_ms=100
  port_timeout=.1

 def _run(self,cancel_event,targets):
  def progress(info): pass
  return scan_targets(targets,self._Config(),progress,cancel_event)

 def test_cooperative_cancellation_returns_partial_report(self):
  cancel_event=threading.Event()
  results=[]
  def slow_probe(ip,port,timeout):
   time.sleep(.2)
   return "open"
  with unittest.mock.patch("scanner_lib.scanner.ping_host",lambda ip,ms:(True,None)),\
       unittest.mock.patch("scanner_lib.scanner.probe_port",slow_probe):
   thread=threading.Thread(target=lambda:results.append(self._run(cancel_event,["10.0.0.1"]*20)))
   thread.start()
   # Give workers time to start, then request cooperative cancellation.
   time.sleep(.3)
   cancel_event.set()
   thread.join(timeout=5)
  self.assertFalse(thread.is_alive())
  self.assertEqual(len(results),1)
  report=results[0]
  self.assertIsInstance(report,ScanReport)
  self.assertTrue(report.canceled)
  # Partial: fewer than all targets were scanned before cancel.
  self.assertLess(report.completed,20)
  # Records only contain hosts actually scanned.
  self.assertEqual(len(report.records),report.completed)

 def test_scan_without_cancellation_completes(self):
  report=self._run(threading.Event(),["10.0.0.1","10.0.0.2"])
  self.assertIsInstance(report,ScanReport)
  self.assertFalse(report.canceled)
  self.assertEqual(report.completed,2)
  self.assertEqual(len(report.records),2)


if __name__=="__main__":unittest.main()
