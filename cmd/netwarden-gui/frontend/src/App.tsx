import { useCallback, useEffect, useMemo, useState } from 'react'

type Adapter = { name: string; systemName: string; description: string; mac: string; prefixes: string[] }
type Device = { ip: string; mac: string; name: string; vendor: string; role: string; lastSeen: string; online: boolean }
type Conflict = { gatewayIP: string; claimedMAC: string; firstSeen: string; lastSeen: string; count: number; active: boolean }
type Status = { Running: boolean; Scanning: boolean; PeriodicScanEnabled: boolean; DeviceCount: number; Rebuilding: boolean; ConflictCount: number }
const api = () => window.go.main.GUIApp

export default function App() {
  const [adapters, setAdapters] = useState<Adapter[]>([]), [selected, setSelected] = useState('')
  const [devices, setDevices] = useState<Device[]>([]), [conflicts, setConflicts] = useState<Conflict[]>([]), [status, setStatus] = useState<Status | null>(null)
  const [error, setError] = useState(''), [loading, setLoading] = useState(true), [query, setQuery] = useState('')
  const [view, setView] = useState<'devices' | 'integrity'>('devices')

  const refresh = useCallback(async () => {
    const [nextStatus, nextDevices, nextConflicts] = await Promise.all([api().Status(), api().Devices(), api().Conflicts()])
    setStatus(nextStatus); setDevices(nextDevices); setConflicts(nextConflicts)
  }, [])

  useEffect(() => {
    api().Bootstrap().then((data) => { setAdapters(data.interfaces); setSelected(data.selectedInterface || data.interfaces[0]?.name || '') }).catch(showError).finally(() => setLoading(false))
    const offEvent = window.runtime.EventsOn('network:event', refresh)
    const offChanged = window.runtime.EventsOn('runtime:changed', refresh)
    const offError = window.runtime.EventsOn('runtime:error', (message: string) => { setError(message); refresh() })
    return () => { offEvent(); offChanged(); offError() }
  }, [refresh])

  const run = async (task: () => Promise<any>) => { setError(''); try { await task(); await refresh() } catch (reason) { showError(reason) } }
  const visible = useMemo(() => devices.filter(d => `${d.name} ${d.ip} ${d.mac} ${d.vendor}`.toLowerCase().includes(query.toLowerCase())), [devices, query])
  const online = devices.filter(d => d.online).length
  const running = Boolean(status?.Running || status?.Rebuilding)

  function showError(reason: unknown) { setError(reason instanceof Error ? reason.message : String(reason)) }
  async function nickname(device: Device) { const next = prompt(`Nickname for ${device.ip}`, device.name === device.ip ? '' : device.name); if (next !== null) await run(() => api().SetNickname(device.mac, next.trim())) }

  return <main>
    <header><div className="brand"><span className="mark">N</span><div><h1>NetWarden</h1><p>Local network visibility</p></div></div><nav><button className={view === 'devices' ? 'selected' : ''} onClick={() => setView('devices')}>Devices</button><button className={view === 'integrity' ? 'selected' : ''} onClick={() => setView('integrity')}>Integrity {status?.ConflictCount ? <b>{status.ConflictCount}</b> : null}</button></nav><span className={`state ${running ? 'active' : ''}`}><i />{running ? 'Monitoring' : 'Stopped'}</span></header>
    <section className="hero">
      <div><span className="eyebrow">NETWORK OVERVIEW</span><h2>Know what’s on your network.</h2><p>Discover devices and watch gateway integrity from one calm, local dashboard.</p></div>
      <div className="controls"><select disabled={running || loading} value={selected} onChange={e => setSelected(e.target.value)}>{adapters.map(a => <option key={a.name} value={a.name}>{a.systemName || a.name} · {a.prefixes.join(', ')}</option>)}</select>
        <button className={running ? 'danger' : 'primary'} disabled={!selected} onClick={() => run(() => running ? api().StopMonitoring() : api().StartMonitoring(selected))}>{running ? 'Stop monitoring' : 'Start monitoring'}</button></div>
    </section>
    {error && <aside className="error"><strong>Couldn’t complete that action</strong><span>{error}</span><button onClick={() => setError('')}>×</button></aside>}
    <section className="stats"><article><span>Known devices</span><strong>{devices.length}</strong></article><article><span>Online now</span><strong>{online}</strong></article><article><span>Current scan</span><strong>{status?.Scanning ? 'Running' : 'Idle'}</strong></article><article><span>Gateway alerts</span><strong className={status?.ConflictCount ? '' : 'safe'}>{status?.ConflictCount || 'Clear'}</strong></article></section>
    {view === 'devices' ? <section className="panel"><div className="panelHead"><div><h3>Devices</h3><p>Live and previously observed hosts</p></div><div className="actions"><input aria-label="Search devices" placeholder="Search devices…" value={query} onChange={e => setQuery(e.target.value)} /><button disabled={!running || status?.Scanning} onClick={() => run(() => api().ScanNow())}>↻ Scan now</button></div></div>
      <div className="table"><div className="row labels"><span>DEVICE</span><span>ADDRESS</span><span>VENDOR</span><span>ROLE</span><span>STATUS</span><span /></div>
      {visible.length ? visible.map(d => <div className="row" key={d.mac}><span className="device"><i className={d.online ? 'online' : ''} /><b>{d.name || d.ip}</b><small>{d.mac}</small></span><span>{d.ip}</span><span>{d.vendor || 'Unknown'}</span><span><em>{d.role}</em></span><span className={d.online ? 'up' : 'down'}>{d.online ? 'Online' : 'Offline'}</span><span><button className="more" onClick={() => nickname(d)}>•••</button></span></div>) : <div className="empty"><div>⌁</div><h4>{running ? 'Listening for devices…' : 'Ready when you are'}</h4><p>{running ? 'Discovered hosts will appear here.' : 'Choose an adapter and start monitoring.'}</p></div>}</div>
    </section> : <section className="panel"><div className="panelHead"><div><h3>Gateway integrity</h3><p>Claims that differed from the trusted gateway identity</p></div><span className={`integrityState ${conflicts.some(c => c.active) ? 'warning' : ''}`}>{conflicts.some(c => c.active) ? 'Active warning' : 'No active warnings'}</span></div>
      <div className="table"><div className="conflictRow labels"><span>CLAIMED IDENTITY</span><span>GATEWAY</span><span>FIRST SEEN</span><span>LAST SEEN</span><span>OBSERVATIONS</span><span>STATE</span></div>
      {conflicts.length ? conflicts.map(c => <div className="conflictRow" key={`${c.claimedMAC}-${c.firstSeen}`}><span className="device"><i className={c.active ? 'alertDot' : ''}/><b>{c.claimedMAC}</b><small>Unexpected gateway MAC</small></span><span>{c.gatewayIP}</span><span>{new Date(c.firstSeen).toLocaleString()}</span><span>{new Date(c.lastSeen).toLocaleString()}</span><span>{c.count}</span><span className={c.active ? 'alertText' : 'safe'}>{c.active ? 'Active' : 'Restored'}</span></div>) : <div className="empty"><div>✓</div><h4>No gateway conflicts observed</h4><p>NetWarden will record unexpected gateway identity claims here.</p></div>}</div>
    </section>}
    <footer><span>NetWarden runs locally. Network data stays on this device.</span><label><input type="checkbox" checked={Boolean(status?.PeriodicScanEnabled)} disabled={!running} onChange={e => run(() => api().SetPeriodicScanEnabled(e.target.checked))} /> Periodic discovery</label></footer>
  </main>
}
