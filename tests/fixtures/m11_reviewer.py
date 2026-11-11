"""Input-only fresh reviewer fixture. Reads stdin, writes stdout; no tools."""
import json
import sys
import os
import uuid


def proposal(inputs):
    results=[]
    for c in inputs['criteria']:
        evidence=[]; outcome='UNKNOWN'
        for m in inputs['manifest']:
            data=m['record']; content=data.get('content',{})
            if m['class']!='independent_result' or m['trust']!='independently_verified':continue
            if c['level']=='execution' and content.get('attempt_id')==inputs['attempt_id'] and content.get('passed') is True:
                outcome='PASS'; evidence=[m['id']]
            elif c['level']=='source' and content.get('subject_attempt')==inputs['attempt_id']:
                check=content.get('checks',{}).get(c['validator'])
                if check in {'PASS','FAIL'}:outcome=check; evidence=[m['id']]
        results.append({'id':c['id'],'result':outcome,'evidence':evidence,'explanation':'Independent sealed synthetic document rubric '+c['validator']})
    failure=any(c['result']=='FAIL' for c in results)
    missing=[c['id'] for c in results if c['result']=='UNKNOWN']
    return {'verdict':'FAIL' if failure else 'NEEDS_EVIDENCE' if missing else 'PASS','criteria':results,
            'reason_codes':['IMPLEMENTATION_DEFECT'] if failure else ['MISSING_EVIDENCE'] if missing else [],
            'missing_evidence':missing,'uncertainty':'NONE'}


if __name__=='__main__':
    inputs=json.loads(sys.stdin.read(131073))
    print(json.dumps(proposal(inputs)))
    print(json.dumps({'process_id':os.getpid(),'context_id':str(uuid.uuid4()),'transport':'fresh-input-only-process','tools':[]}),file=sys.stderr)
