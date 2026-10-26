"use client";
import { useState } from 'react';
import { ArrowUpRight, ChartNoAxesCombined } from 'lucide-react';
import { Run, modeColors, modeNames, bytes } from '@/lib/api';
export default function BenchmarkPanel({run, full = false, runId}:{run:Run|null;full?:boolean;runId?:string}) {
  const [operation,setOperation] = useState('encrypt_envelope');
  const rows = run?.timings.filter(row => row.operation === operation && row.payload_bytes !== null) || [];
  const sizes = [...new Set(rows.map(row=>row.payload_bytes!))].sort((a,b)=>a-b);
  const max = Math.max(...rows.map(row=>row.median_ms),0.001)*1.15;
  const x = (i:number)=>64+i*(650/Math.max(sizes.length-1,1));
  const y = (value:number)=>220-value/max*180;
  return <section className="panel benchmark-panel">
    <div className="panel-head"><div><div className="eyebrow">MEASURED, NOT ASSUMED</div><h2>Performance comparison <span className="subtle-tag">Median latency</span></h2></div><select aria-label="Benchmark operation" value={operation} onChange={e=>setOperation(e.target.value)}><option value="encrypt_envelope">Encryption</option><option value="decrypt_envelope">Decryption</option><option value="sign_envelope">Signing</option><option value="verify_envelope">Verification</option></select></div>
    {run ? <><div className="legend">{run.configuration.modes.map(mode=><span key={mode}><i style={{background:modeColors[mode]}}/>{modeNames[mode]}</span>)}<span className="legend-note">{run.configuration.repetitions} samples / case</span></div>
    <figure className="chart"><svg viewBox="0 0 760 265" role="img" aria-label={`Median ${operation.replaceAll('_',' ')} latency by payload size; milliseconds`}>
      {[0,1,2,3,4].map(i=><g key={i}><line x1="64" x2="714" y1={40+i*45} y2={40+i*45} stroke="#e9ece9" strokeDasharray="4 5"/><text x="49" y={44+i*45} textAnchor="end">{(max*(1-i/4)).toFixed(1)}</text></g>)}
      <text x="16" y="19">ms</text>
      {sizes.map((size,i)=><text key={size} x={x(i)} y="249" textAnchor="middle">{bytes(size)}</text>)}
      {run.configuration.modes.map(mode=>{const points=sizes.map((size,i)=>({x:x(i),row:rows.find(row=>row.mode===mode&&row.payload_bytes===size)})).filter(p=>p.row);return <g key={mode}><polyline fill="none" stroke={modeColors[mode]} strokeWidth="2.5" points={points.map(p=>`${p.x},${y(p.row!.median_ms)}`).join(' ')}/>{points.map(p=><circle key={p.x} cx={p.x} cy={y(p.row!.median_ms)} r="4" fill="white" stroke={modeColors[mode]} strokeWidth="2"><title>{modeNames[mode]}: {p.row!.median_ms.toFixed(3)} ms</title></circle>)}</g>})}
    </svg><figcaption>In-memory workflows · payload sizes spaced categorically · lower is faster</figcaption></figure>
    <div className="chart-footer"><span><i className="tiny-dot"/>Actual local measurements. Machine load affects results.</span>{runId ? <a href={`/api/benchmarks/${runId}/report`}>Download report <ArrowUpRight size={14}/></a>:null}</div>
    {full ? <div className="table-scroll"><table><thead><tr><th>Mode</th><th>Payload</th><th>Median</th><th>p95</th><th>Range</th></tr></thead><tbody>{rows.map(row=><tr key={`${row.mode}-${row.payload_bytes}`}><td><span className="mode-dot" style={{background:modeColors[row.mode]}}/>{modeNames[row.mode]}</td><td>{bytes(row.payload_bytes!)}</td><td>{row.median_ms.toFixed(3)} ms</td><td>{row.p95_ms.toFixed(3)} ms</td><td>{row.min_ms.toFixed(3)}–{row.max_ms.toFixed(3)} ms</td></tr>)}</tbody></table></div>:null}</>:
    <div className="empty"><ChartNoAxesCombined size={30}/><h3>No benchmark measurements yet</h3><p>Run a comparison to see actual performance across all three modes.</p></div>}
  </section>;
}
