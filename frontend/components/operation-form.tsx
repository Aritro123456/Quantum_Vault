"use client";
import { useState } from 'react';
import { ArrowRight, File, FileUp, LockKeyhole, ShieldCheck, Download, CheckCircle2 } from 'lucide-react';
import { modeNames, postForm, saveDownload } from '@/lib/api';
export type Action = 'encrypt'|'decrypt'|'sign'|'verify';
const labels:Record<Action,string> = {encrypt:'Encrypt file',decrypt:'Decrypt file',sign:'Sign envelope',verify:'Verify signature'};
export function FileField({name,label,required=true,hint}:{name:string;label:string;required?:boolean;hint?:string}) {
  const [filename,setFilename] = useState('');
  return <label className="file-field"><span className="field-label">{label}{required?<span className="required"> *</span>:null}</span><span className={`file-control ${filename?'selected':''}`}><FileUp size={20}/><span><strong>{filename||'Click to select a file'}</strong><small>{hint||'Files stay in memory during this operation'}</small></span><File size={16}/><input type="file" name={name} required={required} onChange={e=>setFilename(e.target.files?.[0]?.name||'')}/></span></label>;
}
export default function OperationForm({initial='encrypt',initialMode='postquantum',onComplete}:{initial?:Action;initialMode?:string;onComplete:(label:string)=>void}) {
  const [action,setAction]=useState<Action>(initial),[mode,setMode]=useState(initialMode);
  const [requireSignature,setRequireSignature]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState(''),[success,setSuccess]=useState(''),[reset,setReset]=useState(0);
  async function submit(event:React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form=event.currentTarget;setBusy(true);setError('');setSuccess('');
    try {
      const data=new FormData(form);data.set('mode',mode);data.set('require_signature',String(requireSignature));
      const response=await postForm(`/api/crypto/${action}`,data);
      if(action==='verify'){const result=await response.json();setSuccess(`Signature verified. Signer fingerprint: ${result.fingerprint}`);}
      else {const filename=await saveDownload(response,action==='encrypt'?'encrypted.qv':action==='sign'?'envelope.qvsig':'decrypted.bin');setSuccess(`${labels[action]} completed. Downloaded ${filename}.`);}
      onComplete(labels[action]);form.reset();setReset(value=>value+1);
    }catch(err){setError(err instanceof Error?err.message:'Operation failed.');}finally{setBusy(false);}
  }
  return <div className="workspace-grid"><section className="panel operation-panel"><div className="operation-tabs" role="group" aria-label="File operation">{(Object.keys(labels) as Action[]).map(value=><button key={value} disabled={busy} className={action===value?'active':''} onClick={()=>{setAction(value);setError('');setSuccess('');setReset(v=>v+1);}}>{labels[value]}</button>)}</div>
    <form onSubmit={submit} key={`${action}-${reset}`}><div className="form-heading"><span className="icon-box"><LockKeyhole size={22}/></span><div><h2>{labels[action]}</h2><p>{action==='encrypt'?'Protect a file for your recipient.':action==='decrypt'?'Recover your file after cryptographic validation.':action==='sign'?'Bind your identity to an encrypted envelope.':'Validate an envelope against a trusted signer.'}</p></div></div>
    {(action==='encrypt'||action==='decrypt')?<label className="field-label">Encryption mode<select value={mode} disabled={busy} onChange={e=>setMode(e.target.value)}>{Object.entries(modeNames).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>:<div className="inline-info"><ShieldCheck size={16}/>ML-DSA-65 · independent signing keys</div>}
    <FileField name="file" label={action==='encrypt'?'File to protect':'Encrypted envelope'} hint={action==='encrypt'?'Any file type · maximum 16 MiB':'QuantumVault .qv envelope · maximum 23 MiB'}/>
    <FileField name="key" label={action==='encrypt'?'Recipient public key':action==='decrypt'?'Recipient private key':action==='sign'?'Signing private key':'Trusted signer public key'} hint={action==='encrypt'||action==='verify'?'Use a public key whose fingerprint you have verified':'Password-encrypted PEM or hybrid JSON key'}/>
    {action==='decrypt'||action==='sign'?<label className="field-label">Private-key password<input name="password" type="password" required autoComplete="off" placeholder="Enter your private-key password"/></label>:null}
    {action==='decrypt'?<label className="checkbox"><input type="checkbox" checked={requireSignature} onChange={e=>setRequireSignature(e.target.checked)}/><span>Require a valid sender signature <small>Recommended · verify before releasing plaintext</small></span></label>:null}
    {action==='verify'||(action==='decrypt'&&requireSignature)?<FileField name="signature" label="Detached signature" hint="QuantumVault .qvsig file"/>:null}
    {action==='decrypt'&&requireSignature?<FileField name="signer_key" label="Trusted signer public key" hint="Raw ML-DSA-65 .pub key · 1952 bytes"/>:null}
    {error?<div className="notice error" role="alert">{error}</div>:null}{success?<div className="notice success" role="status"><CheckCircle2 size={18}/><span>{success}</span></div>:null}
    <button className="primary wide" type="submit" disabled={busy}>{busy?'Processing securely…':labels[action]}{busy?<span className="spinner"/>:<ArrowRight size={17}/>}</button>
    <p className="form-footnote"><Download size={13}/> Results download to your device. Uploaded files are not saved by Django.</p>
    </form></section><aside className="workspace-aside"><div className="dark-card"><ShieldCheck size={30}/><h3>Protection, with proof.</h3><p>Every envelope binds its metadata to authenticated encryption. Optional signatures let you verify the sender before decryption.</p><div className="dark-divider"/><span className="eyebrow">YOUR WORKFLOW</span><ol><li>Verify your recipient’s public key</li><li>Choose the matching encryption mode</li><li>Download the protected envelope</li><li>Sign it for sender verification</li></ol></div><div className="note-card"><strong>One key. One purpose.</strong><p>Encryption keys and signing keys are separate. Modes never silently fall back to a weaker algorithm.</p></div></aside></div>;
}
