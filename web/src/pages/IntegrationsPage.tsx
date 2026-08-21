import OpenInNewRoundedIcon from '@mui/icons-material/OpenInNewRounded'
import { Alert, Box, Button, Chip, Grid, Stack, Typography } from '@mui/material'
import { useAuth } from '../lib/auth-context'
import { ContentCard, PageHeader } from '../components/Page'
import { CopyButton } from '../components/CopyField'

// Build the example against the address the administrator is actually on, so
// it can be copied without hand-editing a placeholder host.
function mcpExample(origin: string): string {
  return `{
  "mcpServers": {
    "resso": {
      "url": "${origin}/mcp",
      "headers": {
        "Authorization": "Bearer rk_xxxxx.yyyyy"
      }
    }
  }
}`
}

export function IntegrationsPage() {
  const { meta } = useAuth()
  const example = mcpExample(window.location.origin)
  return <><PageHeader title="API · MCP" description="자동화와 AI Agent가 ReSSO 상태를 안전하게 읽도록 표준 인터페이스를 제공합니다." /><Grid container spacing={2.25}><Grid size={{ xs: 12, lg: 6 }}><ContentCard><Stack direction="row" justifyContent="space-between" alignItems="flex-start"><Box><Typography variant="h2">REST API</Typography><Typography color="text.secondary" sx={{ mt: .7 }}>OpenAPI 3.1 계약과 일관된 JSON 오류 형식을 사용합니다.</Typography></Box><Chip label="OpenAPI 3.1" color="primary" variant="outlined" /></Stack><Stack spacing={1.4} sx={{ mt: 3 }}><Endpoint method="GET" path="/api/openapi.json" /><Endpoint method="GET" path="/api/admin/v1/realms" /><Endpoint method="GET" path="/api/v1/me" /></Stack><Button component="a" href="/api/openapi.json" target="_blank" endIcon={<OpenInNewRoundedIcon />} sx={{ mt: 2 }}>OpenAPI JSON 열기</Button></ContentCard></Grid><Grid size={{ xs: 12, lg: 6 }}><ContentCard><Stack direction="row" justifyContent="space-between" alignItems="flex-start"><Box><Typography variant="h2">Model Context Protocol</Typography><Typography color="text.secondary" sx={{ mt: .7 }}>Streamable HTTP JSON-RPC와 tools/list, tools/call을 지원합니다.</Typography></Box><Chip label="2025-06-18" color="secondary" variant="outlined" /></Stack><Stack spacing={1.4} sx={{ mt: 3 }}><Endpoint method="POST" path="/mcp" /><Endpoint method="GET" path="/.well-known/oauth-protected-resource" /></Stack><Alert severity="info" sx={{ mt: 2 }}>개인 설정에서 <strong>mcp:read</strong> 범위의 API 키를 만든 뒤 Bearer 인증에 사용하세요.</Alert></ContentCard></Grid><Grid size={12}><ContentCard><Stack direction="row" justifyContent="space-between" alignItems="center"><Box><Typography variant="h2">MCP 연결 예시</Typography><Typography color="text.secondary" variant="body2" sx={{ mt: .5 }}>Secret은 생성 직후 한 번만 표시됩니다.</Typography></Box><CopyButton value={example} label="설정 예시 복사" size="medium" /></Stack><Box component="pre" className="mono" sx={{ p: 2.5, mt: 2, mb: 0, bgcolor: '#101828', color: '#d0d5dd', borderRadius: 1.5, overflowX: 'auto', fontSize: 13 }}>{example}</Box></ContentCard></Grid><Grid size={12}><Alert severity="success">현재 서비스 버전: <strong>{meta?.version}</strong> · 모든 UI와 API 자산은 ReSSO 이미지에 포함되어 오프라인 런타임에서 외부 CDN을 사용하지 않습니다.</Alert></Grid></Grid></>
}

function Endpoint({ method, path }: { method: string; path: string }) {
  return <Stack direction="row" alignItems="center" spacing={1.2}><Chip label={method} size="small" color={method === 'POST' ? 'secondary' : 'primary'} sx={{ width: 62, fontWeight: 700 }} /><Typography className="mono" variant="body2" sx={{ overflowWrap: 'anywhere' }}>{path}</Typography></Stack>
}
