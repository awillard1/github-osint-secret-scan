"""Durable discovery stages within the existing queue operation."""
from contextlib import contextmanager
from datetime import UTC,datetime


class DiscoveryProgress:
    def __init__(self,storage,job=None):
        self.storage=storage;self.job=job
        self.states={}

    def save(self):
        if self.job is not None:
            self.job.scope_json={**(self.job.scope_json or {}),'stages':dict(self.states)}
            self.storage.session.commit()

    def queued(self,names):
        for name in names:self.states.setdefault(name,{'status':'queued','result_count':0})
        self.save()

    @contextmanager
    def stage(self,name):
        previous=self.states.get(name,{})
        value={'status':'running','result_count':previous.get('result_count',0),'started_at':datetime.now(UTC).isoformat()}
        self.states[name]=value;self.save()
        try:yield value
        except Exception:
            self.storage.session.rollback()
            value['status']='failed';value['error']='Discovery stage failed; inspect connection/provider readiness and retry the target'
            self.states[name]=value;self.save();raise
        else:
            value['status']='failed' if previous.get('status')=='failed' else 'completed';value['completed_at']=datetime.now(UTC).isoformat()
            self.states[name]=value;self.save()
