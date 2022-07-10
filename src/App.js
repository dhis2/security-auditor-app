import React from 'react'
import i18n from '@dhis2/d2-i18n'
import { CssVariables } from '@dhis2/ui'
import { HashRouter } from 'react-router-dom'
import styles from './App.module.css'
import MyRoutes from './components/Routes/Routes.js'
import Sidebar from './components/Sidebar/Sidebar.js'

const App = () => (
    <HashRouter>
        <CssVariables spacers colors />

        <div className={styles.container}>

            <div className={styles.sidebar}>
                <Sidebar />
            </div>

            <main className={styles.content}>
                <div className={styles.contentWrapper}>
                    <MyRoutes />
                </div>
            </main>

        </div>
    </HashRouter>
)

export default App
