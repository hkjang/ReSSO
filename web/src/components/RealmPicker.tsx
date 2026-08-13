import { FormControl, InputLabel, MenuItem, Select } from '@mui/material'
import type { Realm } from '../types'

export function RealmPicker({ realms, value, onChange }: { realms: Realm[]; value: string; onChange: (value: string) => void }) {
  return (
    <FormControl sx={{ minWidth: 240, maxWidth: 360 }}>
      <InputLabel id="realm-picker-label">Realm</InputLabel>
      <Select labelId="realm-picker-label" value={value} label="Realm" onChange={(event) => onChange(event.target.value)}>
        {realms.map((realm) => <MenuItem key={realm.id} value={realm.id}>{realm.display_name} <span style={{ opacity: .6, marginLeft: 6 }}>({realm.name})</span></MenuItem>)}
      </Select>
    </FormControl>
  )
}
