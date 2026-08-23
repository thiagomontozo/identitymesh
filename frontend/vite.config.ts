import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
export default defineConfig({plugins:[react()],server:{proxy:{'/api':'http://localhost:8080','/health':'http://localhost:8080','/ready':'http://localhost:8080'}},test:{environment:'jsdom',setupFiles:['./src/test/setup.ts'],css:true,exclude:['e2e/**','node_modules/**','dist/**']}})
