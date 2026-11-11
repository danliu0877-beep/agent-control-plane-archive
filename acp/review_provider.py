"""Fresh-process deterministic test-only reviewer, no tools or canonical DB."""
import json
import os
from pathlib import Path
import subprocess
import sys

from .decision_provider import ProviderOutput
from .domain import require
from .review import PROVIDER


class TerminalReviewRejection(Exception):
    """Test adapter's explicit terminal nondelivery, never timeout/status inference."""


class SyntheticReviewProvider:
    def __init__(self,*,testing=False):
        require(testing is True,'Synthetic independent review is test-only')

    def durable_profile(self):return dict(PROVIDER)

    def propose(self,inputs):
        require(inputs.get('test_only') is True and inputs.get('operation_kind')=='review','Exact test-only review input')
        env={k:v for k,v in os.environ.items() if k in {'SystemRoot','WINDIR','PATH','TEMP','TMP'}}
        child=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve().parents[1]/'tests/fixtures/m11_reviewer.py')],
            input=json.dumps(inputs),capture_output=True,text=True,encoding='utf-8',env=env,timeout=30)
        require(child.returncode==0,'Independent reviewer process failed')
        native=json.loads(child.stderr) if getattr(child,'stderr','') else None
        return ProviderOutput(child.stdout,{**PROVIDER,'native_metadata':native})
