import {afterEach,describe,expect,it,vi} from 'vitest'
import {cleanup,render,screen} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {QueryClient,QueryClientProvider} from '@tanstack/react-query'
import {MemoryRouter} from 'react-router-dom'
import {ConnectorsPage,IdentitiesPage,ReportsPage} from './DomainPages'

afterEach(()=>{cleanup();vi.restoreAllMocks()})
function renderPage(page:React.ReactNode){return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter>{page}</MemoryRouter></QueryClientProvider>)}
function response(body:unknown){return Promise.resolve({ok:true,status:200,headers:new Headers(),json:async()=>body})}

describe('completed product workspaces',()=>{
 it('shows observed identities and keeps ambiguous candidates reviewable',async()=>{vi.stubGlobal('fetch',vi.fn((input:RequestInfo|URL)=>String(input).includes('correlation-candidates')?response({items:[{id:'c1',personName:'Taylor Silva',username:'t.silva.legacy',connectorName:'SCIM A',confidence:'LOW'}]}):response({items:[{id:'a1',username:'alex.morgan',primaryEmail:'alex@example.test',accountType:'HUMAN',connectorName:'SCIM A',personName:'Alex Morgan',activeStatus:'ACTIVE',lastSeenAt:'2026-01-01T00:00:00Z'}]})));renderPage(<IdentitiesPage/>);expect(await screen.findByText('alex.morgan')).toBeInTheDocument();expect(await screen.findByText('t.silva.legacy')).toBeInTheDocument();expect(screen.getByRole('button',{name:'Accept'})).toBeInTheDocument()})
 it('allows LDAP connectors to synchronize while keeping them read-only',async()=>{vi.stubGlobal('fetch',vi.fn(()=>response({items:[{id:'ldap-1',name:'Corporate LDAP',type:'LDAP_DIRECTORY',environment:'TEST',enabled:true,readEnabled:true,writeEnabled:false,capabilities:['DISCOVER_USERS'],lastSyncStatus:'SUCCEEDED',lastSyncAt:null}]})));renderPage(<ConnectorsPage/>);expect(await screen.findByText('Corporate LDAP')).toBeInTheDocument();expect(screen.getByText('Read-only')).toBeInTheDocument();expect(screen.getByRole('button',{name:'Synchronize'})).toBeInTheDocument()})
 it('requires an audited mutation before exposing a new PDF download',async()=>{const fetchMock=vi.fn((input:RequestInfo|URL,init?:RequestInit)=>{const url=String(input);if(url.includes('lifecycle-cases'))return response({items:[{id:'case-1',personName:'Alex Morgan',completedAt:'2026-01-01T00:00:00Z'}]});if(init?.method==='POST')return response({downloadURL:'/api/v1/reports/offboarding/case-1.pdf',contentHash:'abc'});return response({items:[]})});vi.stubGlobal('fetch',fetchMock);renderPage(<ReportsPage/>);await userEvent.click(await screen.findByRole('button',{name:'Generate PDF'}));const link=await screen.findByRole('link',{name:'Download PDF'});expect(link).toHaveAttribute('href','/api/v1/reports/offboarding/case-1.pdf');expect(fetchMock).toHaveBeenCalledWith('/api/v1/reports/offboarding/case-1',expect.objectContaining({method:'POST'}))})
})
