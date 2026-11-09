import { useCallback, useEffect, useRef, useState } from 'react'
async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
  const j = await r.json().catch(() => ({}))
  if (r.status === 401) { window.location.reload(); throw new Error('login required') }
  if (!r.ok) throw new Error(j.error || String(r.status))
  return j
}
const TABS = ['Overview', 'System', 'Power', 'Logs', 'Settings']
const POWER = [['On','Power on'],['GracefulShutdown','Graceful shutdown'],['PushPowerButton','Push power button'],['GracefulRestart','Graceful restart'],['ForceRestart','Force restart'],['ForceOff','Force off'],['Nmi','NMI']]
function KV({ rows }) {
  const shown = rows.filter(([, v]) => v !== undefined && v !== null && v !== '')
  if (!shown.length) return <p className="mut">Nothing reported.</p>
  return <table><tbody>{shown.map(([k, v]) => <tr key={k}><th>{k}</th><td>{String(v)}</td></tr>)}</tbody></table>
}
function AuthScreen({ mode }) {
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  async function submit(ev) {
    ev.preventDefault(); setErr('')
    const r = await fetch(`/api/auth/${mode === 'setup' ? 'setup' : 'login'}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) })
    const j = await r.json().catch(() => ({}))
    if (r.ok) window.location.reload(); else setErr(j.error || 'failed')
  }
  return <div style={{ maxWidth: 360, margin: '12vh auto', background: 'var(--panel)', border: '1px solid var(--line)', borderRadius: 12, padding: 24 }}>
    <h1 style={{ fontSize: 20, margin: '0 0 6px' }}>iLO 4 Console</h1>
    <p className="mut" style={{ marginTop: 0 }}>{mode === 'setup' ? 'First visit - create the console password. It protects this page and the saved iLO logins.' : 'Enter the console password.'}</p>
    <form onSubmit={submit}>
      <input type="password" value={pw} onChange={e => setPw(e.target.value)} placeholder="Console password" autoFocus style={{ width: '100%', padding: 9, borderRadius: 8, border: '1px solid var(--line)', background: 'var(--bg)', color: 'var(--txt)', marginBottom: 10 }} />
      {err && <p className="err">{err}</p>}
      <button className="primary" type="submit" style={{ width: '100%' }}>{mode === 'setup' ? 'Set password & enter' : 'Log in'}</button>
    </form></div>
}

export default function App() {
  const [auth, setAuth] = useState(null)
  const [servers, setServers] = useState([])
  const [fleet, setFleet] = useState(null)
  const [sel, setSel] = useState(null)
  const [tab, setTab] = useState('Overview')
  const [query, setQuery] = useState('')
  const [details, setDetails] = useState({})
  const [thermals, setThermals] = useState({})
  const [logsBy, setLogsBy] = useState({})
  const [creds, setCreds] = useState(null)
  const [revealPw, setRevealPw] = useState(false)
  const [dlg, setDlg] = useState(null)
  const dlgRef = useRef(null)
  const loadFleet = useCallback(async () => {
    try {
      const [sv, fl] = await Promise.all([api('GET', '/api/servers'), api('GET', '/api/fleet')])
      setServers(sv); setFleet(fl)
    } catch { /* keep last good state */ }
  }, [])
  const loadDetail = useCallback(async (id) => {
    setDetails(d => ({ ...d, [id]: { ...(d[id] || {}), loading: !(d[id] && d[id].data), updating: !!(d[id] && d[id].data), error: null } }))
    try {
      const data = await api('GET', `/api/servers/${id}/status?detail=1`)
      setDetails(d => ({ ...d, [id]: { data, error: null, loading: false, updating: false } }))
    } catch (e) {
      setDetails(d => ({ ...d, [id]: { ...(d[id] || {}), error: String(e.message || e), loading: false, updating: false } }))
    }
  }, [])
  useEffect(() => { fetch('/api/auth/me').then(r => r.json()).then(j => setAuth(j.authed ? 'ok' : (j.setup_needed ? 'setup' : 'login'))).catch(() => setAuth('login')) }, [])
  useEffect(() => { if (auth !== 'ok') return; loadFleet(); const t = setInterval(loadFleet, 30000); return () => clearInterval(t) }, [auth, loadFleet])
  const loadThermal = useCallback(async (id) => {
    setThermals(t => (t[id] ? t : { ...t, [id]: { loading: true } }))
    try { const data = await api('GET', `/api/servers/${id}/thermal`); setThermals(t => ({ ...t, [id]: { data, loading: false } })) }
    catch { setThermals(t => ({ ...t, [id]: { data: null, loading: false } })) }
  }, [])
  const loadLogs = useCallback(async (id) => {
    setLogsBy(t => (t[id] && t[id].data ? t : { ...t, [id]: { ...(t[id] || {}), loading: true } }))
    try { const j = await api('GET', `/api/servers/${id}/logs`); setLogsBy(t => ({ ...t, [id]: { data: j.logs || [], loading: false } })) }
    catch { setLogsBy(t => ({ ...t, [id]: { data: [], loading: false } })) }
  }, [])
  useEffect(() => { if (sel) { loadDetail(sel); loadThermal(sel) } }, [sel, loadDetail, loadThermal])
  useEffect(() => { if (sel && tab === 'Logs') loadLogs(sel) }, [sel, tab, loadLogs])
  useEffect(() => { if (!revealPw) return; const t = setTimeout(() => setRevealPw(false), 15000); return () => clearTimeout(t) }, [revealPw])
  useEffect(() => { if (dlg && dlgRef.current && !dlgRef.current.open) dlgRef.current.showModal() }, [dlg])
  const server = servers.find(s => s.id === sel) || null
  const det = sel ? details[sel] : null
  const statusOf = id => fleet && fleet.servers ? fleet.servers.find(s => s.id === id) : null
  async function doPower(action) {
    if (!server) return
    if (!confirm(`${action} - send to ${server.name || server.host}?`)) return
    try { await api('POST', `/api/servers/${server.id}/power`, { action }); alert('Sent: ' + action); setTimeout(() => { loadFleet(); loadDetail(server.id) }, 2000) }
    catch (e) { alert('Failed: ' + e.message) }
  }
  async function showCreds() {
    try { setCreds(await api('GET', `/api/servers/${server.id}/credentials`)); setTab('Settings') } catch (e) { alert('Failed: ' + e.message) }
  }
  async function saveDlg(ev) {
    ev.preventDefault()
    const f = new FormData(ev.target)
    const body = Object.fromEntries(['name','host','username','password','group','location','model_note'].map(k => [k, f.get(k) || '']))
    if (!body.host || !body.username) { alert('iLO IP and username are required'); return }
    try {
      if (dlg === 'add') await api('POST', '/api/servers', body); else await api('PUT', `/api/servers/${dlg.id}`, body)
      setDlg(null); if (dlgRef.current) dlgRef.current.close(); loadFleet()
    } catch (e) { alert('Save failed: ' + e.message) }
  }
  async function removeServer() {
    if (!server || !confirm('Remove this server from the console? The iLO itself is untouched.')) return
    await api('DELETE', `/api/servers/${server.id}`); setSel(null); loadFleet()
  }
  function renderTab() {
    if (!det) return <p className="skel">Loading live Redfish data...</p>
    if (det.loading && !det.data) return <p className="skel">Loading live Redfish data...</p>
    if (!det.data && det.error) return <p className="err">Unreachable: {det.error}</p>
    const d = det.data
    if (!d.reachable) return <><p className="err">Unreachable from this container: {d.error || 'no Redfish reply'}</p><p className="mut">Check the iLO IP, LAN/VLAN reachability, credentials, and that iLO firmware is 2.30+ for Redfish.</p></>
    const dd = d.detail || {}, sys = dd.system || {}, th = (sel && thermals[sel] && thermals[sel].data) || {}
    if (tab === 'Overview') {
      const temps = (th.Temperatures || []).filter(t => t.ReadingCelsius != null)
      const fans = (th.Fans || []).filter(f => f.Reading != null)
      return <>
        <KV rows={[['Power', d.power], ['Health', d.health], ['Model', d.model], ['Serial', d.serial], ['BIOS', d.bios], ['CPU', d.cpu], ['Memory (GiB)', d.memory_gib], ['Power draw (W)', d.power_watts], ['Redfish latency (ms)', d.latency_ms]]} />
        {sel && thermals[sel] && thermals[sel].loading && <p className="mut">Loading temperatures and fans...</p>}
        {temps.length > 0 && <><h3>Temperatures</h3><div className="grid">{temps.map((t, i) => <div className="tile" key={i}><b>{t.ReadingCelsius} C</b><i>{t.Name || 'sensor'}</i></div>)}</div></>}
        {fans.length > 0 && <><h3>Fans</h3><div className="grid">{fans.map((f, i) => <div className="tile" key={i}><b>{f.Reading}{f.ReadingUnits === 'Percent' ? ' %' : ''}</b><i>{f.FanName || f.Name || 'fan'}</i></div>)}</div></>}
      </>
    }
    if (tab === 'System') return <KV rows={['Manufacturer','Model','SerialNumber','SKU','BiosVersion','PowerState','IndicatorLED','AssetTag'].map(k => [k, sys[k]])} />
    if (tab === 'Power') {
      const allowed = sys.Actions && sys.Actions['#ComputerSystem.Reset'] && sys.Actions['#ComputerSystem.Reset']['ResetType@Redfish.AllowableValues']
      const acts = POWER.filter(([a]) => !allowed || allowed.includes(a))
      const noGraceful = allowed && !allowed.includes('GracefulShutdown')
      return <>
      <p className="mut">Sent live via Redfish ComputerSystem.Reset</p>
      {acts.map(([a, l]) => <button key={a} style={{ margin: '0 6px 8px 0' }} onClick={() => doPower(a)}>{l}</button>)}
      {noGraceful && <p className="mut">This iLO offers no Graceful shutdown / Graceful restart over Redfish. <b>Push power button</b> sends the ACPI power-button signal - the OS shuts down gracefully, same as pressing the physical button.</p>}
      {d.power_watts != null && <p>Current draw: <b>{d.power_watts} W</b></p>}
    </>
    }
    if (tab === 'Logs') {
      const logs = (sel && logsBy[sel] && logsBy[sel].data) || []
      if (sel && logsBy[sel] && logsBy[sel].loading && !logs.length) return <p className="skel">Loading event log...</p>
      if (!logs.length) return <p className="mut">No log entries returned by this iLO Redfish log services. Use Open original iLO for the full IML / Event Log.</p>
      return <table><thead><tr><th>When</th><th>Severity</th><th>Message</th></tr></thead><tbody>{logs.map((l, i) => <tr key={i}><td>{l.created || ''}</td><td>{l.severity || ''}</td><td>{l.message || ''}</td></tr>)}</tbody></table>
    }
    return <>
      <KV rows={[['Name', server.name], ['iLO host', server.host], ['Username', server.username], ['Password saved', server.has_password ? 'yes' : 'no'], ['Group', server.group], ['Location', server.location], ['Model / notes', server.model_note]]} />
      {creds && <>
        <KV rows={[['Saved username', creds.username]]} />
        <table><tbody><tr><th>Saved password</th><td>
          <span style={{ fontFamily: 'monospace' }}>{revealPw ? creds.password : '••••••••••'}</span>
          <button style={{ marginLeft: 10 }} onClick={() => setRevealPw(r => !r)}>{revealPw ? 'Hide' : 'Reveal'}</button>
          <button style={{ marginLeft: 6 }} onClick={() => { if (navigator.clipboard) navigator.clipboard.writeText(creds.password) }}>Copy</button>
        </td></tr></tbody></table>
      </>}
      <p className="mut">Credentials shown only after the explicit Show saved login click; they live in this container data volume - LAN only.</p>
    </>
  }
  const visible = servers.filter(s => !query || (s.name + ' ' + s.host + ' ' + (s.group || '')).toLowerCase().includes(query.toLowerCase()))
  if (auth === null) return <p className="skel" style={{ margin: '12vh auto', maxWidth: 360 }}>Checking session...</p>
  if (auth === 'setup') return <AuthScreen mode="setup" />
  if (auth === 'login') return <AuthScreen mode="login" />
  async function logout() { await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {}); window.location.reload() }
  return <>
    <header><h1>iLO 4 Console <span>Redfish - Gen8 / Gen9</span>
      <button className="sp" onClick={logout}>Log out</button>
      <button className="sp" style={{ marginRight: 8 }} onClick={loadFleet}>Refresh</button>
      <button className="sp primary" style={{ marginRight: 8 }} onClick={() => setDlg('add')}>+ Add server</button></h1></header>
    <div className="cards">
      {!fleet && <div className="card"><b>-</b><i>Loading</i></div>}
      {fleet && <>
        {[['total','Servers'],['running','Running'],['off','Off'],['degraded','Degraded'],['unreachable','Unreachable']].map(([k, l]) => <div className="card" key={k}><b>{fleet[k]}</b><i>{l}</i></div>)}
        {fleet.total_watts != null && <div className="card"><b>{fleet.total_watts} W</b><i>Fleet power</i></div>}
      </>}
    </div>
    <div className="chips">Running now: {fleet && fleet.running_now.length ? fleet.running_now.map(s => <span className="chip" key={s.id}><span className="dot" />{s.name}{s.power_watts ? ` - ${s.power_watts} W` : ''}</span>) : <span className="mut">none</span>}</div>
    <main>
      <aside>
        <input type="search" placeholder="Search servers..." value={query} onChange={e => setQuery(e.target.value)} />
        <div>
          {!visible.length && <p className="mut">No servers yet.<br />Add your first iLO by IP.</p>}
          {visible.map(s => {
            const st = statusOf(s.id)
            const cls = !st ? '' : !st.reachable ? 'bad' : st.power === 'on' ? (st.health === 'ok' || st.health === 'unknown' ? 'on' : 'warn') : 'off'
            const lbl = !st ? '...' : !st.reachable ? 'unreachable' : st.power
            return <div key={s.id} className={`srv ${s.id === sel ? 'sel' : ''}`} onClick={() => { setSel(s.id); setCreds(null); setRevealPw(false) }}>
              <span className={`st ${cls}`}>{lbl}</span><b>{s.name || s.host}</b>
              <small>{s.host}{s.group ? ` - ${s.group}` : ''}{s.location ? ` - ${s.location}` : ''}</small></div>
          })}
        </div>
      </aside>
      <section>
        {!server && <p className="mut">Select a server in the side panel, or add one by its iLO IP. Power, health, temperatures, fans and logs load live from that iLO Redfish API through this container - nothing is simulated.</p>}
        {server && <>
          <h2 style={{ margin: 0 }}>{server.name || server.host} <span className="mut" style={{ fontSize: 13 }}>{server.host}</span>{det && det.updating && <span className="upd">updating...</span>}{det && det.data && det.data.age_s != null && <span className="upd">data {det.data.age_s}s old - background refresh</span>}</h2>
          <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <a href={`https://${server.host}/`} target="_blank" rel="noopener"><button className="primary">Open original iLO</button></a>
            <button onClick={showCreds}>Show saved login</button>
            <button onClick={() => setDlg(server)}>Edit</button>
            <button className="danger" onClick={removeServer}>Remove</button>
            <button onClick={() => loadDetail(server.id)}>Reload data</button>
          </div>
          <div className="tabs">{TABS.map(t => <button key={t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{t}</button>)}</div>
          <div>{renderTab()}</div>
        </>}
      </section>
    </main>
    <footer className="foot">Developed by <a href="https://siliconbrane.com" target="_blank" rel="noreferrer">SiliconBrane Inc.</a> · v0.02</footer>
    {dlg && <dialog ref={dlgRef}>
      <form onSubmit={saveDlg}>
        <h3 style={{ margin: '4px 0' }}>{dlg === 'add' ? 'Add server' : 'Edit server'}</h3>
        <label>Friendly name</label><input name="name" defaultValue={dlg === 'add' ? '' : dlg.name} placeholder="e.g. Server 1 (DL380 Gen9)" />
        <label>iLO IP or hostname *</label><input name="host" defaultValue={dlg === 'add' ? '' : dlg.host} placeholder="192.168.1.x" />
        <label>iLO username *</label><input name="username" defaultValue={dlg === 'add' ? '' : dlg.username} placeholder="Administrator" />
        <label>iLO password (blank when editing = keep saved)</label><input name="password" type="password" />
        <label>Group</label><input name="group" defaultValue={dlg === 'add' ? '' : dlg.group} placeholder="Core / GPU / Lab" />
        <label>Location</label><input name="location" defaultValue={dlg === 'add' ? '' : dlg.location} placeholder="Basement rack" />
        <label>Model / notes</label><input name="model_note" defaultValue={dlg === 'add' ? '' : dlg.model_note} placeholder="e.g. DL380 Gen9, 256 GB RAM" />
        <div style={{ marginTop: 16, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" onClick={() => { setDlg(null); if (dlgRef.current) dlgRef.current.close() }}>Cancel</button>
          <button className="primary" type="submit">Save</button></div>
      </form>
    </dialog>}
  </>
}
