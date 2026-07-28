import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { AppProviders } from './app/providers'
import './styles/globals.css'
document.documentElement.classList.add('dark')
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><AppProviders><App /></AppProviders></React.StrictMode>)
