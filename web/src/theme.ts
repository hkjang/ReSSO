import { createTheme } from '@mui/material/styles'

export const theme = createTheme({
  palette: {
    mode: 'light',
    primary: { main: '#2f6fed', dark: '#1f4db8', light: '#d9e4ff' },
    secondary: { main: '#12a594', dark: '#0b7569' },
    background: { default: '#f6f7fb', paper: '#ffffff' },
    text: { primary: '#101828', secondary: '#475467' },
    error: { main: '#d92d20' },
    warning: { main: '#dc6803' },
    success: { main: '#079455' },
    divider: '#e4e7ec',
  },
  shape: { borderRadius: 10 },
  typography: {
    fontFamily: 'Inter, Pretendard, "Noto Sans KR", system-ui, sans-serif',
    h1: { fontSize: '1.75rem', fontWeight: 760, letterSpacing: '-0.025em' },
    h2: { fontSize: '1.35rem', fontWeight: 720, letterSpacing: '-0.015em' },
    h3: { fontSize: '1.08rem', fontWeight: 700 },
    button: { fontWeight: 650, textTransform: 'none' },
    body2: { lineHeight: 1.55 },
  },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { minHeight: 40, borderRadius: 8 } },
    },
    MuiTextField: { defaultProps: { size: 'small', fullWidth: true } },
    MuiFormControl: { defaultProps: { size: 'small', fullWidth: true } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none' } } },
    MuiDialog: { defaultProps: { fullWidth: true } },
    MuiTableCell: { styleOverrides: { head: { fontWeight: 700, color: '#344054', background: '#f9fafb' } } },
    MuiTooltip: { defaultProps: { arrow: true } },
  },
})
