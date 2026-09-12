import { Autocomplete, Box, TextField, Typography } from '@mui/material'
import type { Realm } from '../types'

/**
 * Choose the Realm every administration screen is scoped to.
 *
 * This was a plain dropdown, which is fine for the three Realms a trial
 * deployment has and useless for the fifty a service provider runs: finding
 * one meant scrolling a list with no way to narrow it, and the one thing an
 * operator knows about the Realm they want — its display name — was the part
 * they could not search on. Typing now narrows by either name, and the
 * technical name stays visible because that is what appears in issuer URLs,
 * tokens and the audit trail.
 */
export function RealmPicker({ realms, value, onChange }: { realms: Realm[]; value: string; onChange: (value: string) => void }) {
  const selected = realms.find((realm) => realm.id === value) ?? null
  return (
    <Autocomplete
      options={realms}
      value={selected}
      // Clearing it would leave every screen behind this with no Realm to
      // show. The clear control is hidden and a null selection ignored, so the
      // field always comes back to the Realm that is actually in view.
      clearIcon={null}
      openOnFocus
      sx={{ minWidth: 240, maxWidth: 360, flex: { xs: 'unset', sm: '0 0 auto' } }}
      getOptionLabel={(realm) => realm.display_name || realm.name}
      isOptionEqualToValue={(option, current) => option.id === current.id}
      // Both names, because either is what the operator remembers.
      filterOptions={(options, state) => {
        const term = state.inputValue.trim().toLowerCase()
        if (!term) return options
        return options.filter((realm) => `${realm.display_name} ${realm.name}`.toLowerCase().includes(term))
      }}
      onChange={(_, next) => { if (next) onChange(next.id) }}
      renderOption={(props, realm) => {
        const { key, ...rest } = props as { key?: string } & Record<string, unknown>
        return (
          <Box component="li" key={key ?? realm.id} {...rest}>
            <Box sx={{ minWidth: 0 }}>
              <Typography noWrap>{realm.display_name || realm.name}</Typography>
              <Typography variant="caption" color="text.secondary" className="mono" noWrap display="block">{realm.name}</Typography>
            </Box>
          </Box>
        )
      }}
      renderInput={(params) => <TextField {...params} label="Realm" />}
    />
  )
}
