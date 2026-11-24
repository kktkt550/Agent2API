import * as React from 'react'
import {
  Button,
  Checkbox,
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  SegmentedControl,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
} from '@ui'
import {
  durationText, errorMessage, loadSettings, saveItem, saveSettings, toast, wb,
  type ProxyPoolItem,
} from './proxies-state'
import { t } from '../i18n'
import { openExternal } from './update-shared'
import { ProxySponsorCards } from '../../../ui-shared/proxy-sponsor-cards'
import { ProxyBatchEditor, type ProxyBatchHandle } from '../../../ui-shared/proxy-batch-editor'
import { proxyHost, type ProxyImportDraft, type ProxyImportReport } from '../../../ui-shared/proxy-import'

/* ─── 新增 / 编辑弹窗 ───────────────────────── */

export function ProxyModal({
  item,
  onClose,
}: {
  item: ProxyPoolItem | null
  onClose: () => void
}) {
  const editing = item !== null
  const [name, setName] = React.useState(item?.name || '')
  // relay 条目的 protocol 是 'relay'；表单把它当成第三种协议
  const isRelayItem = (item as { protocol?: string } | null)?.protocol === 'relay'
  const [protocol, setProtocol] = React.useState<'http' | 'socks5' | 'relay'>(isRelayItem ? 'relay' : item?.protocol === 'socks5' ? 'socks5' : 'http')
  const [host, setHost] = React.useState(item?.host || '')
  const [port, setPort] = React.useState(item?.port ? String(item.port) : '')
  const [username, setUsername] = React.useState(item?.username || '')
  const [password, setPassword] = React.useState(item?.password || '')
  // relay 专属字段：URL / 区域 / 部署凭据（明文保存，用户选择不加密）
  const [relayUrl, setRelayUrl] = React.useState((item as { url?: string } | null)?.url || '')
  const [region, setRegion] = React.useState((item as { region?: string } | null)?.region || '')
  const [cfAccountId, setCfAccountId] = React.useState((item as { cfAccountId?: string } | null)?.cfAccountId || '')
  const [cfApiToken, setCfApiToken] = React.useState('')
  const [regions, setRegions] = React.useState<Array<{ value: string; label: string }>>([
    { value: '', label: t('自动') },
  ])
  const [deploying, setDeploying] = React.useState(false)
  const [enabled, setEnabled] = React.useState(item ? item.enabled : true)
  const [nonDirect, setNonDirect] = React.useState(item?.nonDirect === true)
  const [mode, setMode] = React.useState<'single' | 'batch'>('single')
  const body = React.useRef<HTMLDivElement>(null)
  const [batchFooterHost, setBatchFooterHost] = React.useState<HTMLDivElement | null>(null)
  const [batchBusy, setBatchBusy] = React.useState(false)
  const batch = React.useRef<ProxyBatchHandle>(null)
  const [useAuth, setUseAuth] = React.useState(Boolean(item?.username || item?.password))
  const [saving, setSaving] = React.useState(false)
  const [testing, setTesting] = React.useState(false)
  const [status, setStatus] = React.useState<React.ReactNode>(null)
  const busy = saving || testing || batchBusy || deploying

  React.useEffect(() => { setStatus(null) }, [name, protocol, host, port, username, password, useAuth, nonDirect, relayUrl, region, cfAccountId, cfApiToken])
  React.useEffect(() => { if (body.current) body.current.scrollTop = 0 }, [mode])
  // relay 区域下拉元数据（打开弹窗时拉一次；失败保持默认的「自动」）
  React.useEffect(() => {
    if (protocol !== 'relay') return
    let alive = true
    void wb().workbuddyDesktop?.getRelayRegions?.().then(data => {
      if (alive && Array.isArray(data?.regions) && data.regions.length) setRegions(data.regions)
    }).catch(() => {})
    return () => { alive = false }
  }, [protocol])

  async function saveBatch(items: ProxyImportDraft[]): Promise<ProxyImportReport> {
    const data = await saveItem(null, { items })
    if (!data?.imported) throw new Error(t('批量添加响应异常，请刷新代理列表确认后再试'))
    return data.imported
  }

  async function testBatch(draft: ProxyImportDraft) {
    const data = await wb().workbuddyDesktop?.testProxy?.({ proxy: { ...draft, source: 'custom' } })
    if (!data) throw new Error(t('当前环境不支持代理测试（桥接方法缺失）'))
    return data
  }

  /** 表单 → 归一化后的提交对象；形状非法时返回一句面向用户的错误 */
  function draftPayload(): { payload: Record<string, unknown> } | { error: string } {
    const trimmed = name.trim()
    if (!trimmed) return { error: t('请填写代理名称') }
    // relay 分支：URL + 区域 + 凭据，与 host:port 完全不同
    if (protocol === 'relay') {
      const url = relayUrl.trim()
      if (!url) return { error: t('请填写 relay 地址') }
      if (!/^https:\/\//i.test(url)) return { error: t('relay 地址必须是 https:// 开头') }
      return {
        payload: {
          name: trimmed,
          source: 'relay',
          protocol: 'relay',
          url,
          region: region.trim(),
          cfAccountId: cfAccountId.trim(),
          cfApiToken: cfApiToken.trim(),
          enabled,
        },
      }
    }
    if (useAuth && ([...username.trim()].length > 200 || [...password].length > 200)) {
      return { error: t('代理账号和密码不能超过 200 个字符') }
    }
    if (useAuth && protocol === 'socks5' && (new TextEncoder().encode(username.trim()).length > 255 || new TextEncoder().encode(password).length > 255)) {
      return { error: t('SOCKS5 用户名和密码不能超过 255 字节') }
    }
    let hostText: string
    try { hostText = proxyHost(host, t) }
    catch (error) { return { error: errorMessage(error) } }
    const portNumber = Number(port)
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      return { error: t('代理端口必须是 1-65535 的整数') }
    }
    return {
      payload: {
        name: trimmed,
        source: 'manual',
        protocol,
        host: hostText,
        port: portNumber,
        username: useAuth ? username.trim() : '',
        password: useAuth ? password : '',
        enabled,
        nonDirect,
      },
    }
  }

  /** 用当前表单内容测一次（**未保存也能测**：先确认能通，再决定保存） */
  async function testDraft(): Promise<void> {
    if (busy) return
    const draft = draftPayload()
    if ('error' in draft) {
      setStatus(<span className='text-destructive'>❌ {draft.error}</span>)
      return
    }
    const payload = draft.payload
    const proxy = {
      source: 'custom',
      protocol: payload.protocol,
      host: payload.host,
      port: payload.port,
      username: payload.username,
      password: payload.password,
      nonDirect: payload.nonDirect,
    }
    setTesting(true)
    setStatus(t('正在连接上游…'))
    try {
      const data = await wb().workbuddyDesktop?.testProxy?.({ proxy })
      if (data?.success) {
        const suffix = durationText(data.durationMs)
        setStatus(
          <span className='text-success'>
            {t('✅ 出口可用')}
            {data.ip ? t('　出口 IP {ip}', { ip: data.ip }) : ''}
            {suffix ? `　${suffix}` : ''}
          </span>,
        )
      } else {
        setStatus(<span className='text-destructive'>❌ {data?.error || t('连接失败')}</span>)
      }
    } catch (error) {
      setStatus(<span className='text-destructive'>❌ {errorMessage(error)}</span>)
    } finally {
      setTesting(false)
    }
  }

  /** relay 一键部署：调 Cloudflare API 部署 Worker，成功后自动登记条目 */
  async function deployRelay(): Promise<void> {
    if (busy) return
    const trimmed = name.trim()
    if (!trimmed) { setStatus(<span className='text-destructive'>❌ {t('请填写代理名称')}</span>); return }
    const accountId = cfAccountId.trim()
    const apiToken = cfApiToken.trim() || ''
    if (!accountId) { setStatus(<span className='text-destructive'>❌ {t('请填写 Cloudflare Account ID')}</span>); return }
    // 编辑已记住凭据的条目时 Token 可留空（沿用已存）；新建必须填
    if (!apiToken && !(item as { credentialsSaved?: boolean } | null)?.credentialsSaved) {
      setStatus(<span className='text-destructive'>❌ {t('请填写 Cloudflare API Token')}</span>)
      return
    }
    setDeploying(true)
    setStatus(t('正在部署 Relay Worker…（通常需要 10-30 秒）'))
    try {
      // Worker 名称从已填的 relay URL 提取（有 URL 用它），否则由后端从名称生成
      const projectName = /^https:\/\/([a-z0-9][a-z0-9-]*)\./.exec(relayUrl.trim())?.[1] ?? ''
      const data = await wb().workbuddyDesktop?.deployRelayWorker?.({
        cfAccountId: accountId,
        cfApiToken: apiToken,
        projectName,
        region: region.trim(),
        name: trimmed,
      })
      if (!data?.deployUrl) throw new Error(t('部署响应异常'))
      setRelayUrl(String(data.deployUrl))
      setEnabled(true)
      toast(t('✅ Relay Worker 部署完成，已登记进代理池'))
      setStatus(<span className='text-success'>{t('✅ 部署完成')}　{String(data.deployUrl)}</span>)
    } catch (error) {
      setStatus(<span className='text-destructive'>❌ {errorMessage(error)}</span>)
    } finally { setDeploying(false) }
  }

  /** 切换区域（编辑已部署的 relay 条目时）：Worker 名不变，重传脚本换 placements */
  async function switchRegion(): Promise<void> {
    if (busy || !item) return
    setDeploying(true)
    setStatus(t('正在切换部署区域…'))
    try {
      const data = await wb().workbuddyDesktop?.switchRelayRegion?.({
        id: item.id,
        region: region.trim(),
        cfAccountId: cfAccountId.trim(),
        cfApiToken: cfApiToken.trim(),
      })
      if (!data || typeof data !== 'object' || !('region' in data)) throw new Error(t('区域切换响应异常'))
      toast(t('✅ 部署区域已切换'))
      setStatus(<span className='text-success'>{t('✅ 区域已切换')}</span>)
    } catch (error) {
      setStatus(<span className='text-destructive'>❌ {errorMessage(error)}</span>)
    } finally { setDeploying(false) }
  }

  async function save(): Promise<void> {
    if (busy) return
    const draft = draftPayload()
    if ('error' in draft) {
      setStatus(<span className='text-destructive'>❌ {draft.error}</span>)
      return
    }
    setSaving(true)
    setStatus(null)
    try {
      await saveItem(item, draft.payload)
      toast(editing ? t('已保存「{name}」', { name: name.trim() }) : t('已新增「{name}」', { name: name.trim() }))
      if (editing || !batch.current?.hasDraft()) onClose()
      else { setName(''); setHost(''); setPort(''); setUsername(''); setPassword(''); setStatus(null) }
    } catch (error) {
      setStatus(<span className='text-destructive'>❌ {errorMessage(error)}</span>)
    } finally { setSaving(false) }
  }

  return (
    <Dialog open onOpenChange={(open, details) => {
      if (open) return
      if (busy) { details.cancel(); return }
      onClose()
    }}>
      <DialogContent className={editing ? 'max-w-[560px]' : 'w-[min(760px,calc(100vw-48px))]'}>
        <DialogHeader className='shrink-0'>
          <DialogTitle>{editing ? t('编辑代理') : t('新增代理')}</DialogTitle>
        </DialogHeader>
        {!editing ? <div className='shrink-0 border-b border-hairline px-5 py-3'>
          <SegmentedControl value={mode} onValueChange={setMode} disabled={busy} aria-label={t('新增方式')}
            options={[{ value: 'single', label: t('单个添加') }, { value: 'batch', label: t('批量添加') }]} />
        </div> : null}
        <DialogBody ref={body} className='min-h-0 gap-3.5'>
          <div className={mode === 'single' ? 'flex min-w-0 flex-col gap-3.5' : 'hidden'} inert={busy || mode !== 'single'}>
          <div className='flex flex-col gap-1.5'>
            <Label htmlFor='proxy-name'>{t('名称')}</Label>
            <Input id='proxy-name' maxLength={60} autoComplete='off' spellCheck={false}
              placeholder={t('例如：香港 HTTP 出口')}
              value={name} onChange={event => setName(event.currentTarget.value)} />
          </div>

          <div className='flex flex-row items-end gap-2.5'>
            <div className='flex flex-col gap-1.5'>
              <Label htmlFor='proxy-protocol'>{t('协议')}</Label>
              {/* 协议名 HTTP / SOCKS5 是固定叫法，不进词典 */}
              <Select value={protocol} onValueChange={value => setProtocol(value as 'http' | 'socks5' | 'relay')}>
                <SelectTrigger id='proxy-protocol' className='min-w-[110px]'>
                  <SelectValue>{protocol === 'socks5' ? 'SOCKS5' : protocol === 'relay' ? 'Cloudflare Relay' : 'HTTP'}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value='http'>HTTP</SelectItem>
                  <SelectItem value='socks5'>SOCKS5</SelectItem>
                  <SelectItem value='relay'>Cloudflare Relay</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {protocol === 'relay' ? <div className='flex min-w-0 flex-1 flex-col gap-1.5'>
              <Label htmlFor='relay-url'>{t('Relay 地址')}</Label>
              <Input id='relay-url' placeholder='https://xxx.yyy.workers.dev' autoComplete='off' spellCheck={false}
                className='font-mono text-xs'
                value={relayUrl} onChange={event => setRelayUrl(event.currentTarget.value)} />
            </div> : <>
            <div className='flex min-w-0 flex-1 flex-col gap-1.5'>
              <Label htmlFor='proxy-host'>{t('主机')}</Label>
              <Input id='proxy-host' placeholder='127.0.0.1' autoComplete='off' spellCheck={false}
                value={host} onChange={event => setHost(event.currentTarget.value)} />
            </div>
            <div className='flex flex-col gap-1.5'>
              <Label htmlFor='proxy-port'>{t('端口')}</Label>
              <Input id='proxy-port' type='number' min={1} max={65535} className='max-w-[110px]'
                placeholder='7890' value={port} onChange={event => setPort(event.currentTarget.value)} />
            </div>
            </>}
          </div>
          {protocol === 'relay' ? <>
            <div className='flex flex-row items-end gap-2.5'>
              <div className='flex flex-col gap-1.5'>
                <Label htmlFor='relay-region'>{t('部署区域')}</Label>
                <Select value={region} onValueChange={value => setRegion(value ?? '')}>
                  <SelectTrigger id='relay-region' className='min-w-[160px]'>
                    <SelectValue>{regions.find(option => option.value === region)?.label ?? t('自动')}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {regions.map(option => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <p className='min-w-0 flex-1 pb-2 text-xs leading-relaxed text-subtle'>
                {item
                  ? t('改变区域会重新上传 Worker（名称不变）。Cloudflare 的边缘位置提示属于尽力而为。')
                  : t('relay 把请求经 Cloudflare 边缘转发到上游，出口 IP 变成 Cloudflare 的。区域可指定就近位置。')}
              </p>
            </div>
            <details className='rounded-md border border-hairline px-3 py-2'>
              <summary className='cursor-pointer text-xs font-medium'>{t('Cloudflare 凭据（用于一键部署 / 切区域）')}</summary>
              <div className='mt-2.5 flex flex-col gap-2.5'>
                <div className='flex flex-col gap-1.5'>
                  <Label htmlFor='relay-account'>{t('Account ID')}</Label>
                  <Input id='relay-account' placeholder={t('Cloudflare 账号 ID')} autoComplete='off' spellCheck={false}
                    className='font-mono text-xs' value={cfAccountId} onChange={event => setCfAccountId(event.currentTarget.value)} />
                </div>
                <div className='flex flex-col gap-1.5'>
                  <Label htmlFor='relay-token'>{t('API Token')}</Label>
                  <Input id='relay-token' type='password' autoComplete='new-password'
                    placeholder={(item as { credentialsSaved?: boolean } | null)?.credentialsSaved ? t('已保存，留空则沿用') : 'Workers Scripts: Edit'}
                    className='font-mono text-xs' value={cfApiToken} onChange={event => setCfApiToken(event.currentTarget.value)} />
                </div>
                <p className='text-xs leading-relaxed text-subtle'>
                  {t('凭据以明文保存在本机代理池（用户选择不加密）。Token 需要 Workers Scripts: Edit 权限；部署成功后地址与区域自动回填。')}
                </p>
                <div className='flex flex-wrap gap-2'>
                  <Button variant='outline' size='sm' disabled={busy} onClick={() => void deployRelay()}>
                    {deploying ? t('部署中…') : t('一键部署 Relay Worker')}
                  </Button>
                  {item ? <Button variant='outline' size='sm' disabled={busy} onClick={() => void switchRegion()}>
                    {t('仅切换区域')}
                  </Button> : null}
                </div>
              </div>
            </details>
          </> : <>
          <p className='text-xs leading-[1.8] text-subtle'>{t('地址由网关所在设备访问；本机代理需运行在该设备上。')}</p>
          <Label className='flex cursor-pointer items-center gap-2 text-xs font-normal'>
            <Checkbox checked={useAuth} onCheckedChange={value => setUseAuth(value === true)} />
            {t('需要用户名和密码（可选）')}
          </Label>
          {useAuth ? <div className='flex flex-row items-end gap-2.5'>
            <div className='flex min-w-0 flex-1 flex-col gap-1.5'>
              <Label htmlFor='proxy-user'>{t('用户名')}</Label>
              <Input id='proxy-user' placeholder={t('可选')} autoComplete='off'
                value={username} onChange={event => setUsername(event.currentTarget.value)} />
            </div>
            <div className='flex min-w-0 flex-1 flex-col gap-1.5'>
              <Label htmlFor='proxy-pass'>{t('密码')}</Label>
              <Input id='proxy-pass' type='password' placeholder={t('可选')} autoComplete='new-password'
                value={password} onChange={event => setPassword(event.currentTarget.value)} />
            </div>
          </div> : null}

          <Label className='flex cursor-pointer items-center gap-2 text-xs font-normal'>
            <Checkbox checked={nonDirect} onCheckedChange={setNonDirect} />{t('非直连代理')}
          </Label>
          <p className='text-xs leading-relaxed text-subtle'>{t('非直连会先经过网关所在设备的系统代理，再连接到此代理；系统代理不可用时不会改走直连。')}</p>
          </>}

          <div className='flex flex-row items-center gap-2.5'>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label={t('启用这条代理')} />
            <span className='text-[12.5px]'>
              {t('启用（禁用后，使用此代理的账号请求将失败；仍可测试）')}
            </span>
          </div>

          {status ? <div className='text-xs text-subtle' role='status'>{status}</div> : null}
          </div>
          {!editing ? <div className={mode === 'batch' ? 'min-w-0' : 'hidden'} inert={mode !== 'batch'}>
            <ProxyBatchEditor ref={batch} t={t} locked={saving || testing} onBusyChange={setBatchBusy}
              footerHost={batchFooterHost} active={mode === 'batch'}
              save={saveBatch} test={testBatch} onNotice={(message, failed) => toast(message, failed ? 'err' : 'ok')} />
          </div> : null}
          {!editing ? <ProxySponsorCards compact t={t} openExternal={openExternal} className='border-t border-hairline pt-3' /> : null}
        </DialogBody>
        <DialogFooter className='shrink-0 flex-wrap'>
          <Button variant='outline' className='mr-auto' disabled={busy} onClick={onClose}>{editing ? t('取消') : t('关闭')}</Button>
          {mode === 'single' ? <>
            <Button variant='outline' disabled={busy} onClick={() => void testDraft()}>
              {testing ? t('测试中…') : t('测试出口')}
            </Button>
            <Button disabled={busy} onClick={() => void save()}>
              {saving ? t('保存中…') : editing ? t('保存') : t('添加单个')}
            </Button>
          </> : null}
          {!editing ? <div ref={setBatchFooterHost} className={mode === 'batch' ? 'min-w-0' : 'hidden'} /> : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/* ─── 连通性测试设置 ───────────────────────── */

export function ProxySettingsModal({ onClose }: { onClose: () => void }) {
  const [loading, setLoading] = React.useState(true)
  const [saving, setSaving] = React.useState(false)
  const [testUrl, setTestUrl] = React.useState('')
  const [defaultUrl, setDefaultUrl] = React.useState('')
  const [error, setError] = React.useState('')

  React.useEffect(() => {
    let alive = true
    void loadSettings().then(data => {
      if (!alive) return
      if (!data) throw new Error(t('代理设置响应异常'))
      setTestUrl(data.testUrl || '')
      setDefaultUrl(data.defaults?.testUrl || '')
    }).catch(cause => { if (alive) setError(errorMessage(cause)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])

  async function save(): Promise<void> {
    if (saving || loading) return
    const url = testUrl.trim()
    if (url && !/^https?:\/\//i.test(url)) {
      setError(t('测试网址要以 http:// 或 https:// 开头'))
      return
    }
    setSaving(true)
    setError('')
    try {
      await saveSettings({ testUrl: url })
      toast(t('✅ 连通性测试设置已保存'))
      onClose()
    } catch (cause) {
      setError(errorMessage(cause))
    } finally { setSaving(false) }
  }

  return <Dialog open onOpenChange={open => { if (!open && !saving) onClose() }}>
    <DialogContent className='max-w-[500px]'>
      <DialogHeader><DialogTitle>{t('连通性测试设置')}</DialogTitle></DialogHeader>
      <DialogBody>
        <div className='flex flex-col gap-1.5'>
          <Label htmlFor='proxy-settings-url'>{t('测试目标网址')}</Label>
          <Input id='proxy-settings-url' value={testUrl} placeholder={defaultUrl} autoComplete='off' spellCheck={false}
            disabled={loading || saving} className='font-mono text-xs'
            onChange={event => setTestUrl(event.currentTarget.value)} />
        </div>
        <p className='text-xs leading-[1.8] text-subtle'>
          {t('通过代理访问该网址，检查是否能收到 HTTP 响应。留空沿用网关默认值。')}
        </p>
        {loading ? <p className='text-xs text-subtle'>{t('加载中…')}</p> : null}
        {error ? <p className='text-xs text-destructive'>❌ {error}</p> : null}
      </DialogBody>
      <DialogFooter>
        <Button variant='ghost' className='mr-auto' disabled={loading || saving} onClick={() => { setTestUrl(''); setError('') }}>{t('恢复默认')}</Button>
        <Button variant='outline' disabled={saving} onClick={onClose}>{t('取消')}</Button>
        <Button disabled={loading || saving} onClick={() => void save()}>{saving ? t('保存中…') : t('保存设置')}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
}
