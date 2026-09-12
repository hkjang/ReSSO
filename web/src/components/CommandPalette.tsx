import { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import type { SvgIconComponent } from '@mui/icons-material'
import { CircularProgress, Dialog, DialogContent, DialogTitle, Divider, InputAdornment, List, ListItemButton, ListItemIcon, ListItemText, ListSubheader, Stack, TextField, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { visuallyHidden } from '@mui/utils'
import { api } from '../lib/api'
import { recentDestinations } from '../lib/recent'

export interface PaletteDestination {
  label: string
  path: string
  icon: SvgIconComponent
  keywords?: string
}

/** Something the palette can do that is not a destination. */
export interface PaletteCommand {
  label: string
  description?: string
  icon: SvgIconComponent
  run: () => void
}

interface Option {
  key: string
  group: string
  label: string
  description?: string
  icon: SvgIconComponent
  run: () => void
}

interface SearchHit { kind: string; id: string; label: string; description: string; path: string }

const kindLabels: Record<string, string> = {
  realm: 'Realm', user: '사용자', client: 'Client', federation: 'User Federation',
}

/**
 * Ctrl/Cmd-K: go anywhere, or do something, without reaching for the mouse.
 *
 * The palette used to open on the shortcut and then require a click, which is
 * the one thing a palette exists to avoid — the whole point of the pattern is
 * that the hands never leave the keyboard. It now carries a highlighted option
 * that the arrow keys move and Enter runs, and focus deliberately stays in the
 * text field the entire time so that typing keeps narrowing the list: the
 * active option is announced through `aria-activedescendant` instead, which is
 * the combobox pattern a screen reader expects here.
 *
 * It also answers when it has nothing. A search that matched nothing used to
 * render an empty box, indistinguishable from one still waiting on the server.
 */
export function CommandPalette({ open, onClose, destinations, commands, admin, onNavigate }: {
  open: boolean
  onClose: () => void
  destinations: PaletteDestination[]
  commands: PaletteCommand[]
  admin: boolean
  onNavigate: (path: string) => void
}) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listboxID = useId()
  const listRef = useRef<HTMLUListElement>(null)
  // Clear the query as the palette closes, adjusting during render so the next
  // open never shows the previous search for a frame.
  const [wasOpen, setWasOpen] = useState(open)
  if (wasOpen !== open) {
    setWasOpen(open)
    if (!open) setQuery('')
  }
  const term = query.trim()
  const remote = useQuery({
    queryKey: ['quick-search', term],
    queryFn: () => api<{ items: SearchHit[] }>(`/api/admin/v1/quick-search?q=${encodeURIComponent(term)}`),
    enabled: open && admin && term.length >= 2,
    staleTime: 10_000,
  })
  const searching = remote.isFetching

  const go = useMemo(() => (path: string) => { onClose(); onNavigate(path) }, [onClose, onNavigate])
  const options = useMemo<Option[]>(() => {
    const lowered = query.toLowerCase()
    const matches = (text: string) => text.toLowerCase().includes(lowered)
    const byPath = new Map(destinations.map((item) => [item.path, item]))
    const result: Option[] = []
    // With nothing typed, where they were last beats the menu in its fixed
    // order. Once they type, the match is what matters and history only
    // duplicates rows.
    if (!query) {
      for (const path of recentDestinations(byPath.keys())) {
        const item = byPath.get(path)
        if (!item) continue
        result.push({ key: `recent-${path}`, group: '최근 방문', label: item.label, icon: HistoryRoundedIcon, run: () => go(path) })
      }
    }
    for (const item of destinations) {
      if (!matches(`${item.label} ${item.keywords ?? ''}`)) continue
      result.push({ key: `nav-${item.path}`, group: '빠른 이동', label: item.label, description: item.keywords, icon: item.icon, run: () => go(item.path) })
    }
    for (const command of commands) {
      if (!matches(`${command.label} ${command.description ?? ''}`)) continue
      result.push({ key: `command-${command.label}`, group: '명령', label: command.label, description: command.description, icon: command.icon, run: () => { onClose(); command.run() } })
    }
    for (const hit of remote.data?.items ?? []) {
      result.push({
        key: `hit-${hit.kind}-${hit.id}`, group: '검색 결과', label: hit.label,
        description: `${kindLabels[hit.kind] ?? hit.kind}${hit.description ? ` · ${hit.description}` : ''}`,
        icon: SearchRoundedIcon, run: () => go(hit.path),
      })
    }
    return result
  }, [query, destinations, commands, remote.data, go, onClose])

  // The highlight belongs to the list as it stands now. Narrowing the query
  // shortens the list, and an index left pointing past the end would run
  // nothing on Enter. Both corrections are made during render rather than in
  // an effect, so no frame is ever painted with the highlight in the wrong
  // place — and so that arriving search results, which only lengthen the list,
  // do not drag the highlight back to the top under the operator's fingers.
  const [lastQuery, setLastQuery] = useState(query)
  if (lastQuery !== query) { setLastQuery(query); setActive(0) }
  if (active !== 0 && active >= options.length) setActive(0)
  // Keep the highlight on screen: with a long list the arrow keys otherwise
  // move a selection the operator cannot see.
  useEffect(() => {
    const highlighted = listRef.current?.querySelector('[data-active="true"]')
    // Guarded rather than called: scrollIntoView is absent under jsdom, and a
    // palette that throws while being tested is a palette nobody can test.
    highlighted?.scrollIntoView?.({ block: 'nearest' })
  }, [active, options.length])

  const keydown = (event: KeyboardEvent) => {
    if (!options.length) return
    const move = (next: number) => {
      event.preventDefault()
      setActive(((next % options.length) + options.length) % options.length)
    }
    switch (event.key) {
      // Wrapping at both ends: the last entry is one press up from the first,
      // which is how every palette this pattern comes from behaves.
      case 'ArrowDown': return move(active + 1)
      case 'ArrowUp': return move(active - 1)
      case 'Home': return move(0)
      case 'End': return move(options.length - 1)
      case 'Enter':
        event.preventDefault()
        options[active]?.run()
        return
      default:
    }
  }

  let renderedGroup = ''
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth PaperProps={{ sx: { position: 'fixed', top: { xs: 8, sm: 72 }, m: 1, maxHeight: 'min(680px, calc(100vh - 32px))' } }}>
      {/* MUI는 DialogTitle이 없어도 aria-labelledby를 붙이므로, 제목을 렌더하지 않으면
          없는 id를 가리켜 이름 없는 대화 상자가 된다. 디자인상 제목을 보이지 않으므로
          시각적으로만 감춘다. */}
      <DialogTitle sx={visuallyHidden}>빠른 이동 및 검색</DialogTitle>
      {/* placeholder는 접근 가능한 이름이 아니고, 입력을 시작하면 사라진다. */}
      <TextField autoFocus placeholder="메뉴, 명령, 사용자, Client 검색…" value={query}
        onChange={(event) => setQuery(event.target.value)} onKeyDown={keydown}
        inputProps={{
          'aria-label': '메뉴, 명령, 사용자, Client 검색',
          role: 'combobox', 'aria-expanded': true, 'aria-controls': listboxID,
          'aria-autocomplete': 'list',
          'aria-activedescendant': options.length ? `${listboxID}-${active}` : undefined,
        }}
        InputProps={{
          startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment>,
          endAdornment: searching ? <InputAdornment position="end"><CircularProgress size={18} /></InputAdornment> : undefined,
        }}
        sx={{ '& fieldset': { border: 0 }, px: 1, pt: 1 }} />
      <Divider />
      <DialogContent sx={{ p: 1, overflowY: 'auto' }}>
        <List dense ref={listRef} id={listboxID} role="listbox" aria-label="결과" sx={{ '& .MuiListSubheader-root': { lineHeight: 2.2 } }}>
          {options.map((option, index) => {
            const Icon = option.icon
            const header = option.group === renderedGroup ? null : (renderedGroup = option.group)
            return (
              <div key={option.key}>
                {header && <ListSubheader disableSticky sx={{ bgcolor: 'transparent', color: 'text.secondary', fontSize: 11, letterSpacing: .6, textTransform: 'uppercase' }}>{header}</ListSubheader>}
                <ListItemButton
                  id={`${listboxID}-${index}`} role="option" aria-selected={index === active}
                  data-active={index === active}
                  selected={index === active}
                  // The highlight follows the pointer too, so a mouse and the
                  // arrow keys never disagree about what Enter would run.
                  onMouseMove={() => setActive(index)}
                  onClick={option.run}
                  sx={{ borderRadius: 1 }}
                >
                  <ListItemIcon><Icon /></ListItemIcon>
                  <ListItemText primary={option.label} secondary={option.description} />
                </ListItemButton>
              </div>
            )
          })}
        </List>
        {!options.length && (
          <Stack alignItems="center" spacing={1} sx={{ py: 5, color: 'text.secondary' }} role="status">
            {searching
              ? <><CircularProgress size={22} /><Typography variant="body2">검색 중…</Typography></>
              : <>
                <Typography variant="body2">{term ? `'${term}'에 해당하는 항목이 없습니다` : '검색어를 입력하세요'}</Typography>
                {term.length === 1 && admin && <Typography variant="caption">사용자와 Client 검색은 두 글자부터 시작합니다.</Typography>}
              </>}
          </Stack>
        )}
      </DialogContent>
      {/* 키보드로 쓸 수 있다는 사실 자체가 보이지 않으면 아무도 쓰지 않는다. */}
      <Divider />
      <Stack direction="row" spacing={2} sx={{ px: 2, py: 1, color: 'text.secondary' }}>
        <Typography variant="caption">↑↓ 이동</Typography>
        <Typography variant="caption">Enter 실행</Typography>
        <Typography variant="caption">Esc 닫기</Typography>
      </Stack>
    </Dialog>
  )
}
