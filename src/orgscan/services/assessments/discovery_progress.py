"""Durable discovery stages within the existing queue operation."""
from contextlib import contextmanager
from datetime import UTC,datetime
from orgscan.cancellation import CancellationRequested


class DiscoveryProgress:
    def __init__(self,storage,job=None):
        self.storage=storage;self.job=job
        self.states={}

    def save(self):
        if self.job is not None:
            self.job.scope_json={**(self.job.scope_json or {}),'stages':dict(self.states)}
            self.storage.session.commit()

    def queued(self,names):
        now=datetime.now(UTC).isoformat()
        for name in names:self.states.setdefault(name,{'status':'queued','result_count':0,'queued_at':now,'updated_at':now})
        self.save()

    @contextmanager
    def stage(self,name):
        previous=self.states.get(name,{})
        now=datetime.now(UTC).isoformat()
        value={'status':'running','result_count':previous.get('result_count',0),'input_count':previous.get('input_count',0),'queued_at':previous.get('queued_at'),
               'started_at':now,'updated_at':now}
        self.states[name]=value;self.save()
        try:yield value
        except Exception as exc:
            self.storage.session.rollback()
            value['status']='cancelled' if isinstance(exc,CancellationRequested) else 'failed';value['completed_at']=datetime.now(UTC).isoformat();value['updated_at']=value['completed_at'];value['error']='Operation cancelled by operator' if isinstance(exc,CancellationRequested) else 'Discovery stage failed; inspect connection/provider readiness and retry the target'
            self.states[name]=value;self.save();raise
        else:
            value['status']='failed' if previous.get('status')=='failed' else 'completed';value['completed_at']=datetime.now(UTC).isoformat();value['updated_at']=value['completed_at']
            self.states[name]=value;self.save()
