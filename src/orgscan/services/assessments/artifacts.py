"""Tenant-authorized encrypted upload staging, independent of protected findings."""
import hashlib
import os
import re
from pathlib import Path
from tempfile import mkstemp
from contextlib import contextmanager
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.storage.assessments import AssessmentStorage,fields
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.artifact_service import _safe_artifact_name, prepare_artifact


class AssessmentArtifacts(AssessmentService):
    def _root(self):
        root=self.settings.data_dir.resolve()/'assessment-artifacts'
        if root.is_symlink():raise ValueError('Artifact storage must not be a symlink')
        root.mkdir(mode=0o700,parents=True,exist_ok=True)
        return root

    def _key(self):
        path=self._root()/'staging.key'
        flags=getattr(os,'O_NOFOLLOW',0)
        try:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|flags,0o600)
        except FileExistsError:pass
        else:
            with os.fdopen(fd,'wb') as stream:stream.write(os.urandom(32))
        with os.fdopen(os.open(path,os.O_RDONLY|flags),'rb') as stream:key=stream.read(33)
        if len(key)!=32:raise ValueError('Artifact staging key is unavailable')
        return key

    def _path(self,identity,digest):
        if type(identity) is not int or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('Invalid staged artifact identity')
        return self._root()/(str(identity)+'-'+digest+'.enc')

    def upload(self,identity,filename,content):
        if not content or len(content)>10_000_000:raise ValueError('Upload must contain between 1 and 10 MB of data')
        name=_safe_artifact_name(filename);digest=hashlib.sha256(content).hexdigest()
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            if a.status not in ('draft','ready','paused'):raise ValueError('Pause the assessment before adding uploads')
            target=s.scalar(select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.identity==digest))
            if target and target.validation_status=='valid':return st.safe({'target':fields(target),'duplicate':True},a.tenant_key)
            # Validate archives in a temporary private workspace before retaining them.
            with self._prepare(content,name):pass
            path=self._path(identity,digest)
            nonce=os.urandom(12)
            aad=f'{a.tenant_key}:{identity}:{digest}'.encode()
            encrypted=nonce+AESGCM(self._key()).encrypt(nonce,content,aad)
            fd,temporary=mkstemp(prefix='staging-',suffix='.tmp',dir=self._root())
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write(encrypted);stream.flush();os.fsync(stream.fileno())
                os.replace(temporary,path)
            finally:Path(temporary).unlink(missing_ok=True)
            repo,_=Storage(s).get_or_create_repository(f'artifact-{identity}/{digest[:24]}',organization_id=a.organization_id,provider='artifact',metadata_json={'artifact_digest':digest,'artifact_name':name})
            link=st.link(a,'repository',repo.id,source='upload',confidence='verified',reasons=['Operator uploaded artifact'])
            link.included=True
            if target is None:
                target=m.AssessmentTarget(assessment_id=identity,identity=digest,raw_input=name,normalized_value='upload:'+digest,target_type='artifact')
                s.add(target)
            target.validation_status='valid';target.metadata_json={'repository_id':repo.id,'artifact_digest':digest}
            s.flush();result=st.safe({'target':fields(target),'duplicate':False},a.tenant_key);s.commit();return result

    @contextmanager
    def _prepare(self,content,name):
        with prepare_artifact(content,name,prefix='orgscan-assessment-upload-') as (path,_,_):
            yield path

    @contextmanager
    def materialize(self,assessment,repo):
        digest=(repo.metadata_json or {}).get('artifact_digest','')
        path=self._path(assessment.id,digest)
        try:
            with os.fdopen(os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)),'rb') as stream:blob=stream.read(10_000_029)
            if len(blob)>10_000_028:raise ValueError
            content=AESGCM(self._key()).decrypt(blob[:12],blob[12:],f'{assessment.tenant_key}:{assessment.id}:{digest}'.encode())
            if hashlib.sha256(content).hexdigest()!=digest:raise ValueError
        except Exception:raise ValueError('Staged upload is unavailable or failed integrity validation') from None
        with self._prepare(content,_safe_artifact_name(repo.metadata_json['artifact_name'])) as path:yield path
